// Port of onym-contracts/plonk/prover/src/circuit/plonk/poseidon.rs (MIT).
import { sha256 } from "@noble/hashes/sha2.js";
import { FR } from "./identity";
import { bigint, concat, intBytes, utf8 } from "./bytes";
const mod = (n: bigint) => ((n % FR) + FR) % FR;
function power(a: bigint, b: bigint) {
  let v = 1n;
  for (; b; b >>= 1n, a = mod(a * a)) if (b & 1n) v = mod(v * a);
  return v;
}
let seed = sha256(
  utf8("SEP-XXXX-Poseidon-BLS12-381-w3-f8-p56-a5-round-constants"),
);
const constants = Array.from({ length: 192 }, () => {
  const first = seed;
  seed = sha256(seed);
  const ext = concat(first, seed);
  seed = sha256(seed);
  return bigint(ext.reverse()) % FR;
});
const mds = Array.from({ length: 3 }, (_, i) =>
  Array.from({ length: 3 }, (_, j) => power(BigInt(i + j + 5), FR - 2n)),
);
export function poseidon(...values: bigint[]) {
  let s = [0n, ...values.map(mod)];
  while (s.length < 3) s.push(0n);
  if (s.length !== 3) throw Error("Poseidon arity");
  for (let r = 0; r < 64; r++) {
    s = s.map((v, i) => mod(v + constants[r * 3 + i]));
    s = s.map((v, i) => (r < 4 || r >= 60 || i === 0 ? power(v, 5n) : v));
    s = mds.map((row) => mod(row.reduce((sum, m, i) => sum + m * s[i], 0n)));
  }
  return s[1];
}
export const leafHash = (secret: Uint8Array) =>
  intBytes(poseidon(bigint(secret)), 32);
export function commitment(
  leaves: Uint8Array[],
  depth: number,
  epoch: number,
  salt: Uint8Array,
) {
  if (
    !Number.isInteger(depth) ||
    depth < 1 ||
    depth > 12 ||
    leaves.length > 2 ** depth ||
    !Number.isSafeInteger(epoch) ||
    epoch < 0
  )
    throw Error("Некорректное дерево группы");
  let layer = leaves.map(bigint);
  while (layer.length < 2 ** depth) layer.push(0n);
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2)
      next.push(poseidon(layer[i], layer[i + 1]));
    layer = next;
  }
  return intBytes(
    poseidon(
      poseidon(layer[0], BigInt(epoch)),
      bigint(new Uint8Array(salt).reverse()),
    ),
    32,
  );
}
