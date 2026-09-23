import { describe, it, expect } from "vitest";
import { identityFromPhrase } from "../src/identity";
import { hex } from "../src/bytes";
const phrase =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
describe("official iOS/Android identity vectors", () => {
  it("derives exactly the same identity and keys", () => {
    const i = identityFromPhrase(phrase);
    expect(i.id).toBe("59B0B267-F746-46B7-AD6C-31863606156F");
    expect(hex(i.nostrPublic)).toBe(
      "d8631b8e96d3d3d6d42cdadd07bc6db04108367dc2ce2d5e9b9a524123dc0821",
    );
    expect(hex(i.blsPublic)).toBe(
      "a5859e962056987df69617fa41318641def18a1f78959951d1cf07bd164a6dcb50962786c8ead48c4e6aab5db6ce8f10",
    );
    expect(hex(i.signingPublic)).toBe(
      "7a33c09cdb7f51fe723a4003d2f28272cddc8fa2cf3d74a374a5f2ee6fb1fcdc",
    );
    expect(hex(i.inboxPublic)).toBe(
      "66ac34309b3b73163b628c2c40174ea76d58d4eb769172611e5c42f9a0cefe5f",
    );
    expect(i.stellarAccount).toBe(
      "GB5DHQE43N7VD7TSHJAAHUXSQJZM3XEPULHT25FDOSS7F3TPWH6NYJ7A",
    );
    expect(i.inboxTag).toBe("f462ae97384bd242");
  });
  it("rejects bad recovery phrases", () =>
    expect(() => identityFromPhrase("abandon ".repeat(12))).toThrow());
});
