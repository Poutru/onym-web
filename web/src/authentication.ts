import { createLocalJWKSet, jwtVerify, decodeProtectedHeader } from "jose";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { b64, utf8, hex, random } from "./bytes";
import type { Identity } from "./identity";
import { documentAt } from "./services";
import { namingManifest } from "./naming";
export const AUTH_ISSUER = "https://atlas.predhit.com/auth";
const b64url = (b: Uint8Array) =>
  b64(b).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
export async function loginRequest(id: string) {
  if (!/^[\w-]{43}$/.test(id)) throw Error("Неверный запрос входа");
  const m = await namingManifest();
  if (
    m.authentication?.issuer !== AUTH_ISSUER ||
    m.authentication?.client_id !== "atlas-bsn"
  )
    throw Error("Сервер входа не совпадает с манифестом");
  const { data: metadata } = await documentAt(
    AUTH_ISSUER + "/.well-known/openid-configuration",
  );
  if (
    metadata.issuer !== AUTH_ISSUER ||
    new URL(metadata.jwks_uri).origin !== new URL(AUTH_ISSUER).origin
  )
    throw Error("Неверный сервер входа");
  const { data: keys } = await documentAt(metadata.jwks_uri);
  const {
    data: { request: compact },
  } = await documentAt(AUTH_ISSUER + "/onym-auth/requests/" + id);
  const { payload: p } = await jwtVerify(compact, createLocalJWKSet(keys), {
    issuer: AUTH_ISSUER,
    audience: "urn:onym:authenticator",
    algorithms: ["ES256"],
    typ: "onym-auth-request+jwt",
  });
  if (
    p.request_id !== id ||
    p.client_id !== m.authentication.client_id ||
    typeof p.resume_uri !== "string" ||
    !p.resume_uri.startsWith(AUTH_ISSUER + "/interaction/") ||
    !/^[-\w]+$/.test(
      p.resume_uri.slice((AUTH_ISSUER + "/interaction/").length),
    ) ||
    p.rp_origin !== "https://atlas.predhit.com" ||
    p.redirect_uri !== "https://atlas.predhit.com/bsn-np/account/callback" ||
    p.code_challenge_method !== "S256" ||
    typeof p.code_challenge !== "string" ||
    typeof p.challenge !== "string" ||
    typeof p.oidc_nonce !== "string" ||
    typeof p.exp !== "number" ||
    typeof p.iat !== "number" ||
    p.iat > Date.now() / 1000 + 30 ||
    p.exp! > p.iat + 120 ||
    !/^\d{6}$/.test(String(p.display_code))
  )
    throw Error("Некорректный запрос входа");
  const allowed = [
    "openid",
    ...m.authentication.permissions.map((x: any) => x.scope),
  ];
  if (
    typeof p.scope !== "string" ||
    p.scope.split(" ").some((s) => !allowed.includes(s))
  )
    throw Error("Сайт запросил не объявленные в манифесте данные");
  return { payload: p, compact };
}
export async function answerLogin(
  request: Awaited<ReturnType<typeof loginRequest>>,
  identity: Identity,
  approve: boolean,
) {
  const p = request.payload,
    now = Math.floor(Date.now() / 1000),
    subject = "onym:key:" + hex(identity.signingPublic);
  if (p.exp! <= now) throw Error("Запрос входа истёк");
  const header = {
    alg: "EdDSA",
    typ: "onym-auth-proof+jwt",
    jwk: { kty: "OKP", crv: "Ed25519", x: b64url(identity.signingPublic) },
  };
  const payload = {
    iss: subject,
    sub: subject,
    aud: AUTH_ISSUER,
    client_id: p.client_id,
    request_id: p.request_id,
    request_hash: b64url(sha256(utf8(request.compact))),
    challenge: p.challenge,
    decision: approve ? "approve" : "deny",
    iat: now,
    exp: Math.min(now + 90, p.exp!),
    jti: b64url(random(24)),
  };
  const data =
    b64url(utf8(JSON.stringify(header))) +
    "." +
    b64url(utf8(JSON.stringify(payload)));
  const proof =
    data + "." + b64url(ed25519.sign(utf8(data), identity.signingSecret));
  const r = await fetch(AUTH_ISSUER + "/onym-auth/responses", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ proof }),
    credentials: "omit",
    redirect: "error",
    signal: AbortSignal.timeout(10000),
  });
  if (r.status !== 204)
    throw Error("Вход не подтверждён. Вернитесь на сайт и начните заново.");
}
