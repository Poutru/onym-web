import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { canonical } from "./naming";
import { hex, unhex, unb64, utf8 } from "./bytes";
export const ATLAS = "https://atlas.predhit.com/manifest.json";
export const ATLAS_KEY =
  "2dd364cd4025036957330c49d5f6d0f4a0b1969b3e8d9a85ee77a377892e59a1";
export type Service = { url: string; manifest: any };
export type Source = { url: string; key: string; sequence?: number };
export async function documentAt(url: string) {
  const u = new URL(url);
  if (u.protocol !== "https:" || u.username || u.password || u.hash)
    throw Error("Нужен HTTPS-адрес");
  const proxied =
    /^(https:\/\/atlas\.predhit\.com\/(?:manifest\.json|catalogs\/public-services\.json|bsn-np\/manifest\.json|simple-backup\/(?:manifest\.json|terms\/[a-f0-9]{64}\.json))|https:\/\/(?:authority|relayer|backup)\.onym\.app\/manifest\.json|https:\/\/discovery\.onym\.app\/manifests\/(?:onym-courier|onym-blossom)\.json)$/.test(
      u.href,
    );
  const endpoint = proxied
    ? import.meta.env.BASE_URL +
      "api/service-document?url=" +
      encodeURIComponent(u.href)
    : u.href;
  const r = await fetch(endpoint, {
    credentials: "omit",
    redirect: "error",
    referrerPolicy: "no-referrer",
    signal: AbortSignal.timeout(12000),
  });
  if (!r.ok) throw Error("Сервис недоступен: " + r.status);
  const reader = r.body!.getReader();
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const c = await reader.read();
      if (c.done) break;
      size += c.value.length;
      if (size > 2_000_000) throw Error("Слишком большой документ");
      chunks.push(c.value);
    }
  } finally {
    await reader.cancel();
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.length;
  }
  const raw = new TextDecoder("utf-8", { fatal: true }).decode(all);
  return { data: JSON.parse(raw), digest: "sha256:" + hex(sha256(all)) };
}
export function verifyDocument(v: any, key: string, domain = "") {
  const { signature, ...body } = v;
  if (
    !ed25519.verify(
      unb64(signature, 64),
      utf8(domain + canonical(body)),
      unhex(key, 32),
    )
  )
    throw Error("Подпись документа не прошла проверку");
  if (v.validUntil && (!Number.isFinite(Date.parse(v.validUntil)) || Date.parse(v.validUntil) <= Date.now()))
    throw Error("Манифест просрочен");
}
export async function inspectSource(url: string, key?: string) {
  const { data: m } = await documentAt(url);
  const actual = String(m.operator).replace(/^onym:key:/, "");
  if (
    m.seat !== "discovery" ||
    m.implementationProfileId !==
      "onym:discovery-implementation:static-ed25519-v1" ||
    (key && actual !== key)
  )
    throw Error("Неизвестный каталог или изменён ключ");
  verifyDocument(m, actual);
  if (
    !Number.isFinite(Date.parse(m.validUntil)) ||
    Date.parse(m.validUntil) <= Date.now()
  )
    throw Error("Каталог просрочен");
  return { manifest: m, key: actual };
}
export async function loadCatalog(source: Source) {
  const { manifest: m } = await inspectSource(source.url, source.key);
  const cat = m.catalogs.find((x: any) => x.audience === "public");
  if (!cat) throw Error("Нет публичного каталога");
  const { data: c } = await documentAt(cat.snapshot);
  verifyDocument(c, source.key);
  if (
    c.providerId !== m.providerId ||
    c.catalogId !== cat.catalogId ||
    c.policyDigest !== cat.policy ||
    !Number.isSafeInteger(c.sequence) ||
    c.sequence < (source.sequence || 0) ||
    !Number.isFinite(Date.parse(c.expiresAt)) ||
    Date.parse(c.expiresAt) <= Date.now() ||
    Date.parse(c.generatedAt) > Date.now() + 30000 ||
    !Array.isArray(c.entries) ||
    c.entries.length > 200
  )
    throw Error("Недействительный снимок каталога");
  const services: Service[] = [],
    failures: string[] = [];
  for (const e of c.entries) {
    try {
      const { data: v, digest } = await documentAt(e.manifest.uri);
      if (
        digest !== e.manifest.digest ||
        v.componentId !== e.componentId ||
        v.operator !== e.operator ||
        v.seat !== e.seatType
      )
        throw Error("Манифест изменился, обновите каталог позже");
      const domain =
        v.implementationProfileId ===
        "onym:naming-implementation:bsn-stellar-http-v1"
          ? "onym-bsn-np-v1:manifest\n"
          : "";
      verifyDocument(v, e.operator.slice(9), domain);
      services.push({ url: e.manifest.uri, manifest: v });
    } catch (err) {
      failures.push(
        e.componentId + ": " + (err instanceof Error ? err.message : "ошибка"),
      );
    }
  }
  return { services, failures, sequence: c.sequence };
}
