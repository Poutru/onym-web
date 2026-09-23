import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { z } from "zod";
import { derive, type Identity } from "./identity";
import {
  utf8,
  text,
  b64,
  unb64,
  random,
  buffer,
  concat,
  hex,
  unhex,
} from "./bytes";
const bytes = (n: number) =>
  z.string().refine((s) => {
    try {
      return unb64(s, n).length === n;
    } catch {
      return false;
    }
  });
export const profileSchema = z.object({
  alias: z.string().max(200),
  inbox_public_key: bytes(32),
  sending_pubkey: bytes(32),
});
export const inviteSchema = z.object({
  version: z.literal(1),
  group_id: bytes(32),
  group_secret: bytes(32),
  name: z.string().max(200),
  members: z
    .array(z.object({ public_key_compressed: bytes(48), leaf_hash: bytes(32) }))
    .min(1)
    .max(2048),
  epoch: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  salt: bytes(32),
  commitment: bytes(32),
  tier_raw: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  group_type_raw: z.literal("tyranny"),
  admin_pubkey_hex: z.string().regex(/^[a-f0-9]{96}$/),
  member_profiles: z.record(z.string().regex(/^[a-f0-9]{96}$/), profileSchema),
  invitation_message: z.string().max(2000).nullish(),
});
export type Invitation = z.infer<typeof inviteSchema>;
export const messageSchema = z.object({
  version: z.literal(1),
  message_id: z.string().uuid(),
  group_id: bytes(32),
  sender_bls_pubkey_hex: z.string().regex(/^[a-f0-9]{96}$/),
  sent_at_millis: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  variant: z.object({
    kind: z.literal("tyranny"),
    body: z.string().max(32000),
  }),
});
export type Message = z.infer<typeof messageSchema>;
export const capabilitySchema = z.object({
  intro_pub: bytes(32),
  group_id: bytes(32),
  group_name: z.string().max(200).nullish(),
  rules: z
    .string()
    .refine((s) => s === s.trim() && utf8(s).length <= 1500)
    .nullish(),
});
export const offerSchema = capabilitySchema.extend({
  offer_version: z.literal(1),
  inviter_alias: z.string().max(200),
  invitation_message: z.string().max(16000).nullish(),
});
export function offerLink(offer: z.infer<typeof capabilitySchema>) {
  return (
    "https://onym.app/join?c=" +
    encodeURIComponent(b64(utf8(JSON.stringify(capabilitySchema.parse(offer)))))
  );
}
export function parseInviteLink(input: string) {
  if (input.length > 12000) throw Error("Слишком длинная ссылка");
  const links = input
    .trim()
    .match(/(?:https:\/\/onym\.app\/join|onym:\/\/join)\/?\?[^\s<>"«»]+/g);
  if (!links || links.length !== 1)
    throw Error(
      "Вставьте одну ссылку приглашения https://onym.app/join?c=… или onym://join?c=…",
    );
  const url = new URL(links[0].replace(/[).,;]+$/, ""));
  if (!(
    (url.protocol === "https:" &&
      url.hostname === "onym.app" &&
      ["/join", "/join/"].includes(url.pathname)) ||
    (url.protocol === "onym:" && url.hostname === "join")
  ))
    throw Error("Нужна ссылка приглашения onym.app/join?c=…");
  return capabilitySchema.parse(
    JSON.parse(text(unb64(url.searchParams.get("c") ?? ""))),
  );
}
const envelopeSchema = z.object({
  version: z.literal(1),
  scheme: z.literal("x25519-aes-256-gcm-v1"),
  ephemeral_public_key: bytes(32),
  ephemeral_key_signature: bytes(64),
  sender_ed25519_public_key: bytes(32),
  nonce: bytes(12),
  ciphertext: z.string().max(3_000_000),
  authentication_tag: bytes(16),
});
export async function seal(
  payload: unknown,
  recipient: Uint8Array,
  identity: Identity,
) {
  const ephemeral = random(32),
    pub = x25519.getPublicKey(ephemeral);
  const shared = x25519.getSharedSecret(ephemeral, recipient);
  const raw = derive(shared, "sep-invitation-v1", "aes-256-gcm");
  const key = await crypto.subtle.importKey(
    "raw",
    buffer(raw),
    "AES-GCM",
    false,
    ["encrypt"],
  );
  ephemeral.fill(0);
  shared.fill(0);
  raw.fill(0);
  const nonce = random(12);
  const plain = utf8(JSON.stringify(payload));
  try {
    const cipher = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: buffer(nonce) },
        key,
        buffer(plain),
      ),
    );
    return utf8(
      JSON.stringify({
        version: 1,
        scheme: "x25519-aes-256-gcm-v1",
        ephemeral_public_key: b64(pub),
        ephemeral_key_signature: b64(ed25519.sign(pub, identity.signingSecret)),
        sender_ed25519_public_key: b64(identity.signingPublic),
        nonce: b64(nonce),
        ciphertext: b64(cipher.slice(0, -16)),
        authentication_tag: b64(cipher.slice(-16)),
      }),
    );
  } finally {
    plain.fill(0);
  }
}
export async function openEnvelope(bytes: Uint8Array, identity: Identity) {
  if (bytes.length > 2_000_000) throw Error("Слишком большой конверт");
  const e = envelopeSchema.parse(JSON.parse(text(bytes))),
    pub = unb64(e.ephemeral_public_key),
    sender = unb64(e.sender_ed25519_public_key);
  if (!ed25519.verify(unb64(e.ephemeral_key_signature), pub, sender))
    throw Error("Неверная подпись конверта");
  const shared = x25519.getSharedSecret(identity.inboxSecret, pub),
    raw = derive(shared, "sep-invitation-v1", "aes-256-gcm");
  const key = await crypto.subtle.importKey(
    "raw",
    buffer(raw),
    "AES-GCM",
    false,
    ["decrypt"],
  );
  raw.fill(0);
  shared.fill(0);
  const plain = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(unb64(e.nonce)) },
      key,
      buffer(concat(unb64(e.ciphertext), unb64(e.authentication_tag))),
    ),
  );
  try {
    return { sender: hex(sender), payload: JSON.parse(text(plain)) as unknown };
  } finally {
    plain.fill(0);
  }
}
export type NostrEvent = {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
};
export function eventHash(e: Omit<NostrEvent, "id" | "sig">) {
  return sha256(
    utf8(
      JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content]),
    ),
  );
}
export function makeEvent(payload: Uint8Array, inbox: string): NostrEvent {
  const secret = random(32),
    pub = hex(schnorr.getPublicKey(secret));
  const event = {
    pubkey: pub,
    created_at: Math.floor(Date.now() / 1000),
    kind: 34113,
    tags: [
      ["d", "sep-inbox:" + inbox],
      ["t", inbox],
      ["sep_inbox", inbox],
      ["sep_version", "1"],
    ],
    content: b64(payload),
  };
  const digest = eventHash(event);
  const sig = hex(schnorr.sign(digest, secret));
  secret.fill(0);
  return { ...event, id: hex(digest), sig };
}
export function validEvent(e: NostrEvent, inbox: string) {
  try {
    if (
      ![34113, 24113].includes(e.kind) ||
      e.content.length > 3_000_000 ||
      !Number.isSafeInteger(e.created_at) ||
      e.created_at > Date.now() / 1000 + 600 ||
      e.tags.length > 20
    )
      return false;
    const addressed = e.tags.some(
      (t) =>
        (t[0] === "d" && t[1] === "sep-inbox:" + inbox) ||
        (t[0] === "t" && t[1] === inbox),
    );
    return (
      addressed &&
      hex(eventHash(e)) === e.id &&
      schnorr.verify(unhex(e.sig, 64), unhex(e.id, 32), unhex(e.pubkey, 32))
    );
  } catch {
    return false;
  }
}
