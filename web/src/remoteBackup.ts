import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { b64, hex, utf8, concat, random, buffer } from "./bytes";
import type { Identity } from "./identity";
import type { Service } from "./services";
import { documentAt, verifyDocument } from "./services";
import { canonical } from "./naming";
export function backupHeaders(
  method: string,
  path: string,
  body: Uint8Array,
  seed: Uint8Array,
) {
  const holder = "onym:seat-key:" + hex(ed25519.getPublicKey(seed)),
    stamp = new Date().toISOString(),
    nonce = hex(random(16));
  const fields = [
    utf8("onym-backup-v1"),
    utf8(method),
    utf8(path),
    utf8(holder),
    utf8(stamp),
    utf8(nonce),
    sha256(body),
  ];
  const data = concat(
    ...fields.map((f) => {
      const n = new Uint8Array(4);
      new DataView(n.buffer).setUint32(0, f.length);
      return concat(n, f);
    }),
  );
  return {
    "X-Onym-Holder": holder,
    "X-Onym-Timestamp": stamp,
    "X-Onym-Nonce": nonce,
    "X-Onym-Signature": b64(ed25519.sign(data, seed)),
  };
}
export function backupConnection(service: Service, identity: Identity) {
  const m = service.manifest,
    base = m.endpoints
      ?.find((e: any) => e.role === "read-write")
      ?.uri?.replace(/\/$/, "");
  if (
    m.implementationProfileId !== "onym:backup-implementation:object-http-v1" ||
    !base ||
    new URL(base).protocol !== "https:"
  )
    throw Error("Профиль бэкапа не поддерживается");
  // Separate web archive seat: it must not replace mobile snapshots or imply native archive compatibility.
  const seed = hkdf(
    sha256,
    identity.signingSecret,
    utf8("onym-web-backup-v1"),
    utf8(m.componentId),
    32,
  );
  async function call(
    path: string,
    method = "GET",
    body = new Uint8Array(),
    binary = false,
  ) {
    const url = new URL(base + path),
      r = await fetch(url, {
        method,
        headers: {
          ...backupHeaders(method, url.pathname + url.search, body, seed),
          ...(method !== "GET"
            ? {
                "Content-Type": binary
                  ? "application/octet-stream"
                  : "application/json",
              }
            : {}),
        },
        body: method === "GET" ? undefined : buffer(body),
        credentials: "omit",
        redirect: "error",
        signal: AbortSignal.timeout(30000),
      });
    if (!r.ok)
      throw Error(
        "Сервис бэкапа отклонил запрос (" +
          r.status +
          "). Проверьте условия и доступность.",
      );
    const reader = r.body!.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const c = await reader.read();
        if (c.done) break;
        total += c.value.length;
        if (total > 32_000_000) throw Error("Слишком большой архив");
        chunks.push(c.value);
      }
    } finally {
      await reader.cancel();
    }
    const bytes = concat(...chunks);
    return binary && method === "GET"
      ? bytes
      : JSON.parse(new TextDecoder().decode(bytes));
  }
  return {
    async terms() {
      const { data: t } = await documentAt(
        base + "/terms/" + m.declaredTerms.slice(7) + ".json",
      );
      const { termsId, signature, ...body } = t;
      if (
        termsId !== m.declaredTerms ||
        "sha256:" + hex(sha256(utf8(canonical(body)))) !== termsId ||
        t.operator !== m.operator
      )
        throw Error("Условия сервиса изменились");
      verifyDocument({ ...body, signature }, m.operator.slice(9));
      return t;
    },
    list: () => call("/v1/snapshots"),
    async download(digest: string) {
      if (!/^[a-f0-9]{64}$/.test(digest)) throw Error("Неверный архив");
      const bytes = (await call(
        "/v1/snapshots/" + digest,
        "GET",
        new Uint8Array(),
        true,
      )) as Uint8Array;
      if (hex(sha256(bytes)) !== digest) throw Error("Повреждённый архив");
      return JSON.parse(new TextDecoder().decode(bytes));
    },
    async upload(envelope: unknown) {
      const { data: fresh } = await documentAt(service.url);
      verifyDocument(fresh, m.operator.slice(9));
      if (canonical(fresh) !== canonical(m))
        throw Error(
          "Манифест бэкапа изменился. Обновите каталог и выберите сервис снова.",
        );
      const data = utf8(JSON.stringify(envelope)),
        digest = hex(sha256(data));
      if (
        data.length >
        Math.min(m.limits?.maximumSealedSnapshotBytes || 0, 32_000_000)
      )
        throw Error("Архив превышает лимит");
      const grant = await call(
        "/v1/preflight",
        "POST",
        utf8(
          JSON.stringify({
            operationId: crypto.randomUUID(),
            snapshotReference: {
              algorithm: "sha-256/lowercase-hex",
              digest,
              sealedByteSize: data.length,
            },
            acceptedTermsId: m.declaredTerms,
          }),
        ),
      );
      if (!grant.uploadId) {
        if (
          grant.status === "already_retained" ||
          grant.outcome?.status === "already_retained"
        )
          return;
        throw Error("Сервис не выдал разрешение загрузки");
      }
      if (
        !/^[\w-]{1,150}$/.test(grant.uploadId) ||
        !Number.isSafeInteger(grant.chunkBytes) ||
        grant.chunkBytes < 1 ||
        grant.chunkBytes > 64 * 1024 * 1024 ||
        grant.chunkCount !== Math.ceil(data.length / grant.chunkBytes)
      )
        throw Error("Неверные параметры загрузки");
      for (let n = 0; n < grant.chunkCount; n++)
        await call(
          `/v1/uploads/${grant.uploadId}/chunks/${n}`,
          "PUT",
          data.slice(n * grant.chunkBytes, (n + 1) * grant.chunkBytes),
          true,
        );
      const done = await call(`/v1/uploads/${grant.uploadId}/commit`, "POST");
      if (
        !["retained", "already_retained"].includes(done.outcome?.status) ||
        done.outcome?.snapshotReference?.digest !== digest
      )
        throw Error("Сервис не подтвердил сохранение архива");
    },
  };
}
