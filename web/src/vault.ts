import { argon2id } from "hash-wasm";
import { z } from "zod";
import { random, b64, unb64, utf8, text, buffer } from "./bytes";
const AAD = utf8("onym-web-vault-v1");
const schema = z
  .object({
    version: z.literal(1),
    kdf: z.literal("argon2id"),
    memory: z.literal(65536),
    iterations: z.literal(3),
    parallelism: z.literal(1),
    salt: z.string().max(32),
    iv: z.string().max(24),
    ciphertext: z.string().max(32_000_000),
  })
  .strict();
export type VaultEnvelope = z.infer<typeof schema>;
export async function passwordKey(password: string, salt: Uint8Array) {
  const raw = await argon2id({
    password,
    salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 65536,
    hashLength: 32,
    outputType: "binary",
  });
  try {
    return await crypto.subtle.importKey("raw", buffer(raw), "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]);
  } finally {
    raw.fill(0);
  }
}
export function checkPassword(p: string) {
  if (p.length < 12 || p.length > 1024)
    throw Error("Пароль должен содержать от 12 до 1024 символов.");
}
export async function encryptVault(
  data: unknown,
  key: CryptoKey,
  salt: Uint8Array,
): Promise<VaultEnvelope> {
  const iv = random(12);
  const plain = utf8(JSON.stringify(data));
  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: buffer(iv), additionalData: buffer(AAD) },
      key,
      buffer(plain),
    );
    return {
      version: 1,
      kdf: "argon2id",
      memory: 65536,
      iterations: 3,
      parallelism: 1,
      salt: b64(salt),
      iv: b64(iv),
      ciphertext: b64(new Uint8Array(ciphertext)),
    };
  } finally {
    plain.fill(0);
  }
}
export async function createVault(data: unknown, password: string) {
  checkPassword(password);
  const salt = random(16),
    key = await passwordKey(password, salt);
  return { key, salt, envelope: await encryptVault(data, key, salt) };
}
export async function unlockVault(raw: unknown, password: string) {
  const e = schema.parse(raw),
    salt = unb64(e.salt, 16),
    iv = unb64(e.iv, 12);
  const key = await passwordKey(password, salt);
  let plain;
  try {
    plain = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: buffer(iv), additionalData: buffer(AAD) },
        key,
        buffer(unb64(e.ciphertext)),
      ),
    );
    return { key, salt, data: JSON.parse(text(plain)) as unknown };
  } catch {
    throw Error("Неверный пароль или повреждённое хранилище.");
  } finally {
    plain?.fill(0);
  }
}
export function parseVault(raw: unknown) {
  return schema.parse(raw);
}
function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open("onym-web", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("vault");
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
export async function readVault(): Promise<VaultEnvelope | null> {
  const d = await db();
  try {
    return await new Promise((resolve, reject) => {
      const r = d.transaction("vault").objectStore("vault").get("main");
      r.onsuccess = () => resolve(r.result ?? null);
      r.onerror = () => reject(r.error);
    });
  } finally {
    d.close();
  }
}
export async function writeVault(v: VaultEnvelope) {
  const d = await db();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = d.transaction("vault", "readwrite");
      tx.objectStore("vault").put(v, "main");
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error ?? Error("Сохранение отменено"));
    });
  } finally {
    d.close();
  }
}
