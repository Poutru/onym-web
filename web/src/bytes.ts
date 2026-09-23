export const utf8 = (s: string) => new TextEncoder().encode(s);
export const text = (b: Uint8Array) =>
  new TextDecoder("utf-8", { fatal: true }).decode(b);
export const hex = (b: Uint8Array) =>
  Array.from(b, (n) => n.toString(16).padStart(2, "0")).join("");
export function unhex(s: string, length?: number) {
  if (
    !/^(?:[a-fA-F0-9]{2})+$/.test(s) ||
    (length !== undefined && s.length !== length * 2)
  )
    throw Error("Неверный формат ключа");
  return Uint8Array.from(s.match(/../g)!, (x) => parseInt(x, 16));
}
export function b64(b: Uint8Array) {
  let s = "";
  for (let i = 0; i < b.length; i += 8192)
    s += String.fromCharCode(...b.subarray(i, i + 8192));
  return btoa(s);
}
export function unb64(s: string, length?: number) {
  if (typeof s !== "string" || s.length > 4_000_000)
    throw Error("Неверные данные");
  const a = Uint8Array.from(
    atob(s.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0),
  );
  if (length !== undefined && a.length !== length)
    throw Error("Неверная длина ключа");
  return a;
}
export const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
};
export const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));
export const buffer = (b: Uint8Array) => new Uint8Array(b).buffer;
export const equal = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((v, i) => v === b[i]);
export const bigint = (b: Uint8Array) => BigInt("0x" + hex(b));
export const intBytes = (n: bigint, len: number) =>
  unhex(n.toString(16).padStart(len * 2, "0"), len);
