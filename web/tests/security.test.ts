import { it, expect } from "vitest";
import "fake-indexeddb/auto";
import { createVault, unlockVault, readVault, writeVault } from "../src/vault";
import { identityFromPhrase, newPhrase } from "../src/identity";
import { seal, openEnvelope, makeEvent, validEvent } from "../src/wire";
import { text, utf8 } from "../src/bytes";
it("encrypts persistent state; rejects wrong password and corruption", async () => {
  const data = { phrase: "secret words", messages: ["private message"] };
  const v = await createVault(data, "correct horse battery staple");
  await writeVault(v.envelope);
  const saved = await readVault();
  expect(JSON.stringify(saved)).not.toContain("secret words");
  expect(JSON.stringify(saved)).not.toContain("private message");
  expect(
    (await unlockVault(saved, "correct horse battery staple")).data,
  ).toEqual(data);
  await expect(unlockVault(saved, "wrong")).rejects.toThrow();
  await expect(
    unlockVault(
      { ...saved, ciphertext: "AAAA" },
      "correct horse battery staple",
    ),
  ).rejects.toThrow();
  await expect(
    unlockVault({ ...saved, memory: 999999999 }, "correct"),
  ).rejects.toThrow();
}, 15000);
it("seals authenticated messages, rejects tampering and wrong recipient", async () => {
  const a = identityFromPhrase(newPhrase()),
    b = identityFromPhrase(newPhrase()),
    c = identityFromPhrase(newPhrase());
  const wire = await seal({ body: "Привет" }, b.inboxPublic, a);
  expect((await openEnvelope(wire, b)).payload).toEqual({ body: "Привет" });
  await expect(openEnvelope(wire, c)).rejects.toThrow();
  const raw = JSON.parse(text(wire));
  raw.sender_ed25519_public_key = raw.ephemeral_public_key;
  await expect(openEnvelope(utf8(JSON.stringify(raw)), b)).rejects.toThrow();
});
it("verifies Nostr signatures and recipient tags", () => {
  const e = makeEvent(utf8("sealed"), "123456789abcdef0");
  expect(validEvent(e, "123456789abcdef0")).toBe(true);
  expect(validEvent({ ...e, content: "AAAA" }, "123456789abcdef0")).toBe(false);
  expect(validEvent(e, "wrong")).toBe(false);
});

it("decrypts a mobile-format envelope produced independently by Apple CryptoKit", async () => {
  const fixture = await import("./fixtures/cryptokit-envelope.json");
  const identity = identityFromPhrase(newPhrase());
  identity.inboxSecret = new Uint8Array(32).fill(9);
  expect(
    (await openEnvelope(utf8(JSON.stringify(fixture.default)), identity))
      .payload,
  ).toEqual({ body: "Привет из CryptoKit" });
});
