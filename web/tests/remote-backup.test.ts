import { it, expect, vi } from "vitest";
import { backupConnection } from "../src/remoteBackup";
import { identityFromPhrase } from "../src/identity";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8, concat, unhex, unb64, hex, b64 } from "../src/bytes";
import { canonical } from "../src/naming";
it("uploads, lists and downloads opaque encrypted web archives using request-bound backup signatures", async () => {
  const identity = identityFromPhrase(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  );
  const op = new Uint8Array(32).fill(8),
    pub = hex(ed25519.getPublicKey(op));
  const sign = (v: any) => ({
    ...v,
    signature: b64(ed25519.sign(utf8(canonical(v)), op)),
  });
  const body = { operator: "onym:key:" + pub, termsVersion: 1 };
  const termsId = "sha256:" + hex(sha256(utf8(canonical(body))));
  const terms = { ...sign(body), termsId };
  const manifest = sign({
    componentId: "onym:component:test-backup",
    operator: "onym:key:" + pub,
    implementationProfileId: "onym:backup-implementation:object-http-v1",
    endpoints: [{ role: "read-write", uri: "https://backup.example" }],
    declaredTerms: termsId,
    limits: { maximumSealedSnapshotBytes: 100000 },
  });
  let archive = new Uint8Array(),
    ref: any,
    seen = 0;
  const original = globalThis.fetch;
  globalThis.fetch = vi.fn(async (input: any, init: any = {}) => {
    const u = new URL(String(input), "https://web.example");
    if (u.pathname === "/manifest.json") return Response.json(manifest);
    if (u.pathname.startsWith("/terms/")) return Response.json(terms);
    const data = new Uint8Array(init.body || new ArrayBuffer(0)),
      h = init.headers,
      method = init.method;
    const parts = [
      utf8("onym-backup-v1"),
      utf8(method),
      utf8(u.pathname),
      utf8(h["X-Onym-Holder"]),
      utf8(h["X-Onym-Timestamp"]),
      utf8(h["X-Onym-Nonce"]),
      sha256(data),
    ];
    const signed = concat(
      ...parts.map((v) => {
        const n = new Uint8Array(4);
        new DataView(n.buffer).setUint32(0, v.length);
        return concat(n, v);
      }),
    );
    expect(
      ed25519.verify(
        unb64(h["X-Onym-Signature"]),
        signed,
        unhex(h["X-Onym-Holder"].slice(14)),
      ),
    ).toBe(true);
    seen++;
    if (u.pathname === "/v1/preflight") {
      ref = JSON.parse(new TextDecoder().decode(data)).snapshotReference;
      expect(ref.algorithm).toBe("sha-256/lowercase-hex");
      return Response.json({
        uploadId: "test-upload",
        chunkBytes: 10000,
        chunkCount: 1,
      });
    }
    if (method === "PUT") {
      archive = data;
      return Response.json({ status: "ok" });
    }
    if (u.pathname.endsWith("/commit"))
      return Response.json({
        outcome: { status: "retained", snapshotReference: ref },
      });
    if (u.pathname === "/v1/snapshots")
      return Response.json([{ snapshotReference: ref, status: "retained" }]);
    return new Response(archive);
  }) as any;
  try {
    const connection = backupConnection(
      { url: "https://backup.example/manifest.json", manifest },
      identity,
    );
    const encrypted = { version: 1, ciphertext: "opaque-encrypted-data" };
    await connection.terms();
    await connection.upload(encrypted);
    expect((await connection.list()).length).toBe(1);
    expect(await connection.download(ref.digest)).toEqual(encrypted);
    expect(seen).toBe(5);
  } finally {
    globalThis.fetch = original;
  }
});
