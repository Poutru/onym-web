import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { z } from "zod";
import { b64, unb64, unhex, hex, utf8, random } from "./bytes";
import type { Identity } from "./identity";
export const NAMING_URL = "https://atlas.predhit.com/bsn-np/";
export const NAMING_KEY =
  "82693a8632f81e2e26b777a34b9d82adb5a60138530cc840fc9eae9d2344806e";
export const NAMING_NS = "bsn.atlas.predhit.com";
const registry = "onym:registry:atlas-bsn";
const timestamp = z.string().datetime();
const signature = z.string().max(100);
export const recordSchema = z
  .object({
    recordVersion: z.literal(1),
    registry: z.literal(registry),
    name: z.string().regex(/^G[A-Z2-7]{55}$/),
    displayName: z
      .string()
      .min(1)
      .max(64)
      .refine((s) => !!s.trim() && !/[\p{Cc}\p{Cf}]/u.test(s)),
    namespace: z.literal(NAMING_NS),
    subject: z.string().regex(/^onym:key:[a-f0-9]{64}$/),
    scope: z.tuple([z.literal("display-name")]),
    issuedAt: timestamp,
    expiresAt: timestamp,
    sequence: z.number().int().positive(),
    policy: z.string().regex(/^sha256:[a-f0-9]{64}$/),
    membershipCondition: z.null(),
    stellarAccount: z.string(),
    nameTag: z.enum(["Name", "name"]),
    bindingTag: z.string(),
    network: z.literal("public"),
    signature,
  })
  .strict();
export type NameRecord = z.infer<typeof recordSchema>;
const acceptanceSchema = z
  .object({
    acceptanceVersion: z.literal(1),
    record: z.string(),
    subject: z.string(),
    publish: z.boolean(),
    acceptedAt: timestamp,
    expiresAt: timestamp,
    signature,
  })
  .strict();
const rowSchema = z
  .object({
    record: recordSchema,
    acceptance: acceptanceSchema.nullable(),
    status: z.enum([
      "active",
      "unaccepted",
      "expired",
      "superseded",
      "revoked",
      "disavowed",
    ]),
    disavowal: z.unknown().nullable(),
    supersededBy: z.string().nullable(),
  })
  .strict();
const resolutionSchema = z
  .object({
    version: z.literal(1),
    registry: z.literal(registry),
    query: z.string(),
    records: z.array(rowSchema).max(20),
    checkedAt: timestamp,
    expiresAt: timestamp,
    signature,
  })
  .strict();
export function canonical(value: unknown): string {
  const sort = (v: any): any =>
    Array.isArray(v)
      ? v.map(sort)
      : v && typeof v === "object"
        ? Object.fromEntries(
            Object.keys(v)
              .sort()
              .map((k) => [k, sort(v[k])]),
          )
        : v;
  return JSON.stringify(sort(value));
}
export const recordDigest = (v: unknown) =>
  "sha256:" + hex(sha256(utf8(canonical(v))));
function signBytes(kind: string, value: Record<string, unknown>) {
  const { signature: _, ...v } = value;
  return utf8(`onym-bsn-np-v1:${kind}\n${canonical(v)}`);
}
export function verifySigned(kind: string, value: any, key = NAMING_KEY) {
  try {
    return ed25519.verify(
      unb64(value.signature, 64),
      signBytes(kind, value),
      unhex(key),
    );
  } catch {
    return false;
  }
}
function sign(
  kind: string,
  value: Record<string, unknown>,
  identity: Identity,
) {
  return {
    ...value,
    signature: b64(
      ed25519.sign(signBytes(kind, value), identity.signingSecret),
    ),
  };
}
export function requestProof(
  operation: string,
  fields: Record<string, unknown>,
  identity: Identity,
) {
  const now = Date.now();
  return sign(
    "request",
    {
      ...fields,
      requestVersion: 1,
      operation,
      audience: NAMING_URL,
      subject: "onym:key:" + hex(identity.signingPublic),
      issuedAt: now,
      expiresAt: now + 120000,
      nonce: hex(random(16)),
    },
    identity,
  );
}
const errors: Record<string, string> = {
  binding_missing: "В Stellar ещё нет тега связи с этой идентичностью Onym.",
  name_missing_or_unsafe: "В Stellar не найден допустимый тег Name.",
  invalid_stellar_account: "Проверьте Stellar-адрес и его контрольную сумму.",
  account_not_found: "Этот аккаунт не найден в основной сети Stellar.",
  stellar_unavailable: "Stellar временно недоступен. Имя не подтверждено.",
  service_unavailable: "Провайдер имён временно недоступен.",
  revoked: "Имя или связь в BSN изменились. Запросите имя заново.",
  expired: "Срок записи истёк. Запросите имя заново.",
  superseded: "Уже существует более новая запись имени.",
  rate_limited: "Слишком много запросов. Повторите через минуту.",
};
async function api(path: string, body?: unknown) {
  const r = await fetch(NAMING_URL + path, {
    method: body ? "POST" : "GET",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: "omit",
    referrerPolicy: "no-referrer",
    redirect: "error",
    signal: AbortSignal.timeout(12000),
  });
  let size = 0;
  const reader = r.body!.getReader();
  const chunks: Uint8Array[] = [];
  try {
    while (true) {
      const v = await reader.read();
      if (v.done) break;
      size += v.value.length;
      if (size > 131072) throw Error("Слишком большой ответ провайдера");
      chunks.push(v.value);
    }
  } finally {
    await reader.cancel();
  }
  const data = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    data.set(c, at);
    at += c.length;
  }
  const json = JSON.parse(new TextDecoder().decode(data));
  if (!r.ok)
    throw Error(
      errors[json.error] || "Провайдер отклонил запрос: " + String(json.error),
    );
  return json;
}
export async function namingManifest() {
  const m = await api("manifest.json");
  if (
    m.registry !== registry ||
    m.namespace !== NAMING_NS ||
    m.trustRoot?.publicKey !== NAMING_KEY ||
    !verifySigned("manifest", m)
  )
    throw Error(
      "Ключ или подпись провайдера BSN изменились. Подключение остановлено.",
    );
  return m;
}
export function verifyResolution(
  raw: unknown,
  query: string,
  policy: string,
  now = Date.now(),
  trustKey = NAMING_KEY,
) {
  const r = resolutionSchema.parse(raw),
    checked = Date.parse(r.checkedAt),
    until = Date.parse(r.expiresAt);
  if (
    r.query !== query ||
    !verifySigned("resolution", r, trustKey) ||
    checked > now + 5000 ||
    now - checked > 60000 ||
    until <= now ||
    until - checked > 60000
  )
    throw Error("Подпись или актуальность ответа BSN не подтверждена.");
  for (const row of r.records) {
    const rec = row.record;
    if (
      !verifySigned("record", rec, trustKey) ||
      rec.policy !== policy ||
      rec.name !== rec.stellarAccount ||
      rec.subject !== query ||
      Date.parse(rec.issuedAt) > now + 5000
    )
      throw Error("Неверная запись имени BSN.");
    if (row.status === "active") {
      const a = row.acceptance;
      if (
        !a ||
        !a.publish ||
        a.subject !== rec.subject ||
        a.record !== recordDigest(rec) ||
        !verifySigned("acceptance", a, rec.subject.slice(9)) ||
        Date.parse(rec.expiresAt) <= now ||
        Date.parse(a.expiresAt) <= now ||
        Date.parse(a.expiresAt) > Date.parse(rec.expiresAt) ||
        Date.parse(a.acceptedAt) > now + 5000 ||
        row.disavowal ||
        row.supersededBy
      )
        throw Error("Владелец не подтвердил действующее имя BSN.");
    }
  }
  return r;
}
export async function nameOffer(account: string, identity: Identity) {
  const subject = "onym:key:" + hex(identity.signingPublic),
    m = await namingManifest();
  const preview = await api("v1/preview", { stellarAccount: account, subject });
  if (!preview.eligible)
    return {
      missing: true as const,
      name: String(preview.name || ""),
      tag: String(preview.tag),
      value: identity.stellarAccount,
    };
  const raw = await api(
    "v1/request-issuance",
    requestProof("request-issuance", { stellarAccount: account }, identity),
  );
  const r = verifyResolution(raw, subject, m.policy);
  const record = r.records[0]?.record;
  if (
    !record ||
    record.stellarAccount !== account ||
    r.records[0].status !== "unaccepted" ||
    Date.parse(record.expiresAt) <= Date.now()
  )
    throw Error("Неверное предложение имени");
  return { missing: false as const, record };
}
export async function acceptName(record: NameRecord, identity: Identity) {
  if (
    record.subject !== "onym:key:" + hex(identity.signingPublic) ||
    !verifySigned("record", record)
  )
    throw Error("Имя предназначено другой идентичности");
  const acceptance = sign(
    "acceptance",
    {
      acceptanceVersion: 1,
      record: recordDigest(record),
      subject: record.subject,
      publish: true,
      acceptedAt: new Date().toISOString(),
      expiresAt: record.expiresAt,
    },
    identity,
  );
  const m = await namingManifest();
  const raw = await api(
    "v1/accept-record",
    requestProof(
      "accept-record",
      { record: recordDigest(record), acceptance },
      identity,
    ),
  );
  const r = verifyResolution(raw, record.subject, m.policy);
  if (
    !r.records.some(
      (x) =>
        x.status === "active" &&
        recordDigest(x.record) === recordDigest(record),
    )
  )
    throw Error("Имя не активировано");
  return r;
}
export async function disavowName(record: string, identity: Identity) {
  const subject = "onym:key:" + hex(identity.signingPublic);
  const disavowal = sign(
    "disavowal",
    {
      disavowalVersion: 1,
      record,
      subject,
      effectiveFrom: new Date().toISOString(),
    },
    identity,
  );
  await api(
    "v1/disavow-record",
    requestProof("disavow-record", { record, disavowal }, identity),
  );
}
export async function resolveName(subject: string, policy: string) {
  return verifyResolution(
    await api("v1/resolve-subject", { subject }),
    subject,
    policy,
  );
}
