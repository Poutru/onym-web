import { it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignJWT, importJWK, decodeJwt } from "jose";
import { ed25519 } from "@noble/curves/ed25519.js";
import { createHash } from "node:crypto";
// @ts-ignore Node service module
import { createAuthSite, ISSUER } from "../naming-provider/auth.mjs";
let server: http.Server, dir: string, base: string;
const original = globalThis.fetch;
const seed = new Uint8Array(32).fill(31),
  pub = ed25519.getPublicKey(seed),
  subject = "onym:key:" + Buffer.from(pub).toString("hex");
let activeName: any = null;
const cookieJar = new Map<string, string>();
async function request(path: string, options: any = {}, jar = true) {
  const headers = new Headers(options.headers);
  if (jar)
    headers.set(
      "cookie",
      [...cookieJar].map(([k, v]) => k + "=" + v).join("; "),
    );
  const r = await fetch(new URL(path, "https://atlas.predhit.com"), {
    ...options,
    headers,
    redirect: "manual",
  });
  if (jar)
    for (const raw of r.headers.getSetCookie()) {
      const pair = raw.split(";")[0],
        at = pair.indexOf("=");
      cookieJar.set(pair.slice(0, at), pair.slice(at + 1));
    }
  return r;
}
async function redirects(response: Response) {
  let r = response;
  for (let i = 0; r.status >= 300 && r.status < 400 && i < 12; i++)
    r = await request(r.headers.get("location")!);
  return r;
}
beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "onym-auth-test-"));
  const handler = await createAuthSite({ getSetup: async () => null, getAcceptedName: async () => activeName }, dir);
  server = http.createServer((q, r) => {
    if (!handler(q, r)) {
      r.statusCode = 404;
      r.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = "http://127.0.0.1:" + (server.address() as any).port;
  globalThis.fetch = async (input: any, init: any = {}) => {
    const url = new URL(String(input));
    if (url.origin !== "https://atlas.predhit.com")
      throw Error("Unexpected network request " + url);
    const h = new Headers(init.headers);
    h.set("host", "atlas.predhit.com");
    h.set("x-forwarded-host", "atlas.predhit.com");
    h.set("x-forwarded-proto", "https");
    return original(base + url.pathname + url.search, { ...init, headers: h });
  };
});
afterAll(async () => {
  globalThis.fetch = original;
  await new Promise<void>((r) => server?.close(() => r()));
  await rm(dir, { recursive: true, force: true });
});
it("runs PAR, PKCE, signed identity consent, authorization code and RP session; rejects replay", async () => {
  const r = await redirects(await request("/bsn-np/login"));
  expect(r.status).toBe(200);
  const html = await r.text();
  const id = html.match(/#auth=([\w-]+)/)?.[1];
  expect(id, html).toBeTruthy();
  const cr = await request("/auth/onym-auth/requests/" + id, {}, false),
    { request: compact } = await cr.json();
  const p = decodeJwt(compact),
    now = Math.floor(Date.now() / 1000),
    jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: Buffer.from(pub).toString("base64url"),
    };
  const proof = await new SignJWT({
    iss: subject,
    sub: subject,
    aud: ISSUER,
    client_id: "atlas-bsn",
    request_id: id,
    request_hash: createHash("sha256").update(compact).digest("base64url"),
    challenge: p.challenge,
    decision: "approve",
    iat: now,
    exp: Math.min(now + 90, p.exp!),
    jti: "x".repeat(32),
  })
    .setProtectedHeader({ typ: "onym-auth-proof+jwt", alg: "EdDSA", jwk })
    .sign(
      await importJWK(
        { ...jwk, d: Buffer.from(seed).toString("base64url") },
        "EdDSA",
      ),
    );
  const opts = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: "https://onym.predhit.com",
    },
    body: JSON.stringify({ proof }),
  };
  expect((await request("/auth/onym-auth/responses", opts, false)).status).toBe(
    204,
  );
  expect((await request("/auth/onym-auth/responses", opts, false)).status).toBe(
    400,
  );
  const action = html.match(/action="([^"]+\/finish)"/)![1];
  expect(
    (await request(action.replace("/finish", ""), {}, false)).status,
  ).toBeGreaterThanOrEqual(400);
  const finish = await request(action.replace("/finish", ""));
  const end = await redirects(finish);
  const text = await end.text();
  expect(end.status, text).toBe(200);
  expect(text).toContain("Настройка имени BSN");
  expect(text).toContain(subject);
  activeName = { displayName: "Test connected name", stellarAccount: "GTEST", nameTag: "Name", bindingTag: "OwnershipFull3", expiresAt: new Date(Date.now() + 60000).toISOString() };
  const connected = await (await request("/bsn-np/account")).text();
  expect(connected).toContain("Test connected name");
  expect(connected).toContain("GTEST");
  expect(connected).toContain("OwnershipFull3");
  expect(connected).not.toContain('name="account"');
  activeName = null;
  const foreign = await request("/bsn-np/account/save", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://atlas.predhit.com",
    },
    body: "csrf=wrong&account=bad",
  });
  expect(foreign.status).toBe(400);
}, 30000);
it("never exposes a private signing key through discovery JWKS", async () => {
  const d = await (
    await request("/auth/.well-known/openid-configuration")
  ).json();
  expect(d.issuer).toBe(ISSUER);
  const jwks = await (await request(d.jwks_uri)).json();
  expect(jwks.keys[0].d).toBeUndefined();
  expect(d.require_pushed_authorization_requests).toBe(true);
});

it("rejects an unregistered issuer or return target before beginning login", async () => {
  expect(
    (await request("/bsn-np/login?iss=https%3A%2F%2Fevil.example")).status,
  ).toBe(400);
  expect(
    (await request("/bsn-np/login?target_link_uri=https%3A%2F%2Fevil.example"))
      .status,
  ).toBe(400);
});
