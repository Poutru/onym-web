import { it, expect, vi, afterEach } from "vitest";
import "fake-indexeddb/auto";
import { Client } from "../src/client";
import { defaultSettings, stateSchema, type State } from "../src/state";
import { identityFromPhrase } from "../src/identity";
import { b64, hex, utf8 } from "../src/bytes";
import { offerLink, parseInviteLink, seal, openEnvelope } from "../src/wire";
import { createVault, readVault, unlockVault } from "../src/vault";

const phrase =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const identity = identityFromPhrase(phrase);
const offer = {
  offer_version: 1 as const,
  intro_pub: b64(identity.inboxPublic),
  group_id: b64(new Uint8Array(32).fill(42)),
  group_name: "Проверка приглашений",
  inviter_alias: "Отправитель",
  invitation_message: "Приходите в наш чат",
};
async function fixture() {
  const state: State = {
    version: 1,
    phrase,
    name: "Тест",
    settings: defaultSettings,
    groups: [],
    pending: [],
  };
  const vault = await createVault(state, "test password for invitations");
  const c = new Client(
    state,
    vault.key,
    vault.salt,
    () => {},
    () => {},
    () => {},
  );
  const send = vi.fn(async () => 1);
  c.transport = { send, close: () => {} } as never;
  const receive = (sender: string, payload: unknown) =>
    (c as unknown as { receive(s: string, p: unknown): Promise<void> }).receive(
      sender,
      payload,
    );
  return { c, send, receive };
}
afterEach(() => vi.unstubAllGlobals());
it("recognizes native URL-safe links and links copied with surrounding message text", () => {
  const encoded = b64(utf8(JSON.stringify(offer)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  for (const input of [
    `https://onym.app/join?c=${encoded}`,
    `onym://join?c=${encoded}`,
    `Приглашаю в чат:\nhttps://onym.app/join?c=${encoded}`,
  ]) {
    expect(parseInviteLink(input).group_id).toBe(offer.group_id);
  }
  expect(parseInviteLink(offerLink(offer)).intro_pub).toBe(offer.intro_pub);
  expect(() =>
    parseInviteLink("https://example.com/join?c=anything"),
  ).toThrow();
  expect(() =>
    parseInviteLink(`${offerLink(offer)}\n${offerLink(offer)}`),
  ).toThrow();
});
it("stores authenticated native push offers without sending or joining, and persists dismissal across replay", async () => {
  const { c, send, receive } = await fixture();
  const decoded = await openEnvelope(
    await seal(offer, identity.inboxPublic, identity),
    identity,
  );
  await receive(decoded.sender, decoded.payload);
  expect(c.state.offers?.[0].group_name).toBe(offer.group_name);
  expect(c.state.groups).toHaveLength(0);
  expect(c.state.pending).toHaveLength(0);
  expect(send).not.toHaveBeenCalled();
  await c.dismissOffer(offer.group_id, decoded.sender);
  const saved = stateSchema.parse(
    (await unlockVault(await readVault(), "test password for invitations"))
      .data,
  );
  expect(saved.offers?.[0].status).toBe("dismissed");
  await receive(decoded.sender, decoded.payload);
  expect(c.state.offers).toHaveLength(1);
  expect(c.state.offers?.[0].status).toBe("dismissed");
  await c.close();
  expect(c.state.offers).toHaveLength(0);
});
it("sends a join request only after explicit acceptance; relay failure keeps the offer actionable", async () => {
  const { c, send, receive } = await fixture();
  await receive(hex(identity.signingPublic), offer);
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({ epoch: 1, commitment: b64(new Uint8Array(32)) }),
        ),
    ),
  );
  send.mockRejectedValueOnce(Error("offline"));
  await expect(c.join(offerLink(offer))).rejects.toThrow("offline");
  expect(c.state.offers?.[0].status).toBe("new");
  await c.join(offerLink(offer));
  expect(c.state.offers?.[0].status).toBe("requested");
  expect(c.state.groups).toHaveLength(0);
  expect(c.state.pending).toHaveLength(1);
  await receive(hex(identity.signingPublic), offer);
  expect(c.state.offers).toHaveLength(1);
  await c.close();
});
