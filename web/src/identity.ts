import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeedSync,
  mnemonicToEntropy,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { schnorr } from "@noble/curves/secp256k1.js";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { utf8, hex, concat, bigint, intBytes } from "./bytes";
export const FR = BigInt(
  "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
);
export const derive = (key: Uint8Array, salt: string, info: string, n = 32) =>
  hkdf(sha256, key, utf8(salt), utf8(info), n);
export function arkPublic(secret: Uint8Array) {
  const scalar = bigint(secret) % FR;
  if (scalar === 0n) throw Error("Нулевой ключ");
  return bls12_381.G1.Point.BASE.multiply(scalar).toBytes(true);
}
export function stellarAddress(pub: Uint8Array) {
  const raw = concat(new Uint8Array([48]), pub);
  let crc = 0;
  for (const b of raw) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++)
      crc = ((crc << 1) ^ (crc & 0x8000 ? 0x1021 : 0)) & 65535;
  }
  const bytes = concat(raw, new Uint8Array([crc & 255, crc >> 8]));
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0,
    value = 0,
    result = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet[(value >>> bits) & 31];
    }
  }
  if (bits) result += alphabet[(value << (5 - bits)) & 31];
  return result;
}
export const newPhrase = () => generateMnemonic(wordlist, 128);
export function identityFromPhrase(input: string) {
  const phrase = input.trim().toLowerCase().split(/\s+/).join(" ");
  if (
    ![12, 24].includes(phrase.split(" ").length) ||
    !validateMnemonic(phrase, wordlist)
  )
    throw Error(
      "Проверьте фразу: нужны 12 или 24 английских слова с правильной контрольной суммой.",
    );
  const seed = mnemonicToSeedSync(phrase);
  const nostrSecret = derive(seed, "app.onym.bip39", "nostr-secp256k1-v1");
  const blsSecret = derive(seed, "app.onym.bip39", "bls12-381-v1");
  const signingSecret = derive(
    nostrSecret,
    "app.onym.ios",
    "stellar-ed25519-v1",
  );
  const inboxSecret = derive(
    nostrSecret,
    "app.onym.ios",
    "x25519-key-agreement-v1",
  );
  const id = derive(
    mnemonicToEntropy(phrase, wordlist),
    "app.onym.bip39",
    "identity-id-v1",
    16,
  );
  id[6] = (id[6] & 15) | 64;
  id[8] = (id[8] & 63) | 128;
  const h = hex(id).toUpperCase();
  seed.fill(0);
  const signingPublic = ed25519.getPublicKey(signingSecret),
    inboxPublic = x25519.getPublicKey(inboxSecret);
  return {
    id: `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`,
    phrase,
    nostrSecret,
    blsSecret,
    signingSecret,
    inboxSecret,
    nostrPublic: schnorr.getPublicKey(nostrSecret),
    blsPublic: arkPublic(blsSecret),
    signingPublic,
    inboxPublic,
    stellarAccount: stellarAddress(signingPublic),
    inboxTag: inboxTag(inboxPublic),
  };
}
export type Identity = ReturnType<typeof identityFromPhrase>;
export const inboxTag = (pub: Uint8Array) =>
  hex(sha256(concat(utf8("sep-inbox-v1"), pub))).slice(0, 16);
export function wipeIdentity(i: Identity) {
  i.nostrSecret.fill(0);
  i.blsSecret.fill(0);
  i.signingSecret.fill(0);
  i.inboxSecret.fill(0);
  i.phrase = "";
}
