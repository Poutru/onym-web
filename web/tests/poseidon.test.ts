import { it, expect } from "vitest";
import { commitment, leafHash, poseidon } from "../src/poseidon";
import { intBytes, hex, bigint } from "../src/bytes";
// Canonical Rust/Soroban fixture from onym-contracts at 42d20216; baker.rs keys 1..8, salt EE, epoch 0.
it("matches native Rust/Soroban creation commitments at all three tiers", async () => {
  const expected = [
    "549b35e595ae790ae1850be6e35e740c664da9f12120cfde4fed6fa737240795",
    "19c5d1198cee96b15b8ff1c0d6e70313973f09bec4f47830b1e0f82580e834b6",
    "6031e9faad82bcee58ca7252239ebd9a40ac197058b3c8319f5b5d76f5b4f1ef",
  ];
  const leaves = Array.from({ length: 8 }, (_, i) =>
    leafHash(intBytes(BigInt(i + 1), 32)),
  );
  for (const [i, depth] of [5, 8, 11].entries())
    expect(
      hex(commitment(leaves, depth, 0, new Uint8Array(32).fill(0xee))),
    ).toBe(expected[i]);
  expect(hex(intBytes(poseidon(bigint(leaves[0]), 0x7777n), 32))).toBe(
    "6bb54951206bf080e0410ea0bccfb0106c6ae21c131d8bca94143cfcead02df2",
  );
});
