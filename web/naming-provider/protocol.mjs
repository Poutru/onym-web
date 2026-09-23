import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
export const BASE = "https://atlas.predhit.com/bsn-np/";
export const NS = "bsn.atlas.predhit.com";
export const REGISTRY = "onym:registry:atlas-bsn";
export const PROFILE = "onym:naming-implementation:bsn-stellar-http-v1";
export const canonical = (value) => JSON.stringify(sort(value));
function sort(v) {
  return Array.isArray(v)
    ? v.map(sort)
    : v && typeof v === "object"
      ? Object.fromEntries(
          Object.keys(v)
            .sort()
            .map((k) => [k, sort(v[k])]),
        )
      : v;
}
export const digest = (value) =>
  "sha256:" + createHash("sha256").update(canonical(value)).digest("hex");
export const unsigned = ({ signature, ...value }) => value;
export const bytes = (kind, value) =>
  Buffer.from(`onym-bsn-np-v1:${kind}\n${canonical(unsigned(value))}`);
export const publicHex = (key) =>
  createPublicKey(key)
    .export({ type: "spki", format: "der" })
    .subarray(-32)
    .toString("hex");
export const privateKey = (seed) =>
  createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      seed,
    ]),
    type: "pkcs8",
    format: "der",
  });
export function signed(kind, value, key) {
  return {
    ...value,
    signature: sign(null, bytes(kind, value), key).toString("base64"),
  };
}
export function valid(kind, value, pub) {
  try {
    return (
      /^[a-f0-9]{64}$/.test(pub) &&
      typeof value.signature === "string" &&
      verify(
        null,
        bytes(kind, value),
        createPublicKey({
          key: Buffer.concat([
            Buffer.from("302a300506032b6570032100", "hex"),
            Buffer.from(pub, "hex"),
          ]),
          type: "spki",
          format: "der",
        }),
        Buffer.from(value.signature, "base64"),
      )
    );
  } catch {
    return false;
  }
}
export function stellarAddress(pub) {
  const raw = Buffer.concat([Buffer.from([48]), Buffer.from(pub, "hex")]);
  let crc = 0;
  for (const b of raw) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++)
      crc = ((crc << 1) ^ (crc & 32768 ? 0x1021 : 0)) & 65535;
  }
  const data = Buffer.concat([raw, Buffer.from([crc & 255, crc >> 8])]);
  let bits = 0,
    value = 0,
    out = "";
  for (const b of data) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(value >>> bits) & 31];
    }
  }
  return (
    out +
    (bits ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(value << (5 - bits)) & 31] : "")
  );
}
export function validAccount(account) {
  if (typeof account !== "string" || !/^G[A-Z2-7]{55}$/.test(account))
    return false;
  let bits = 0,
    value = 0,
    out = [];
  for (const c of account) {
    value = (value << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 255);
    }
  }
  return (
    stellarAddress(Buffer.from(out.slice(1, 33)).toString("hex")) === account
  );
}
export class Fault extends Error {
  constructor(code, status = 400, detail = {}) {
    super(code);
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}
export function readEvidence(data, account, subjectKey) {
  const decode = (k) => {
    try {
      const s = data[k];
      if (typeof s !== "string") return "";
      return new TextDecoder("utf-8", { fatal: true }).decode(
        Buffer.from(s, "base64"),
      );
    } catch {
      return "";
    }
  };
  const tag = Object.hasOwn(data, "Name") ? "Name" : "name";
  const name = decode(tag);
  if (
    !name.trim() ||
    Buffer.byteLength(name) > 64 ||
    /[\p{Cc}\p{Cf}]/u.test(name)
  )
    throw new Fault("name_missing_or_unsafe", 422);
  const target = stellarAddress(subjectKey);
  const bindingTag =
    account === target
      ? "self"
      : Object.keys(data).find(
          (k) => /^OwnershipFull\d*$/.test(k) && decode(k) === target,
        );
  if (!bindingTag)
    throw new Fault("binding_missing", 409, {
      tag: "OwnershipFull",
      value: target,
      name,
    });
  return { displayName: name, nameTag: tag, bindingTag, onymAccount: target };
}
