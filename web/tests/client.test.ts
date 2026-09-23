import { it, expect, vi, afterEach } from "vitest";
import "fake-indexeddb/auto";
import { identityFromPhrase, newPhrase } from "../src/identity";
import { b64, hex, unhex } from "../src/bytes";
import { leafHash, commitment } from "../src/poseidon";
import { verifyInvitation, verifyChain, Client } from "../src/client";
import { defaultSettings, type State } from "../src/state";
import { createVault } from "../src/vault";
import type { Invitation } from "../src/wire";
function fixture() {
  const admin = identityFromPhrase(newPhrase()),
    member = identityFromPhrase(newPhrase());
  const members = [admin, member]
    .map((i) => ({
      public_key_compressed: b64(i.blsPublic),
      leaf_hash: b64(leafHash(i.blsSecret)),
    }))
    .sort((a, b) =>
      hex(
        Uint8Array.from(atob(a.public_key_compressed), (c) => c.charCodeAt(0)),
      ).localeCompare(
        hex(
          Uint8Array.from(atob(b.public_key_compressed), (c) =>
            c.charCodeAt(0),
          ),
        ),
      ),
    );
  const salt = new Uint8Array(32).fill(2);
  const inv: Invitation = {
    version: 1,
    group_id: b64(new Uint8Array(32).fill(1)),
    group_secret: b64(new Uint8Array(32).fill(3)),
    name: "Test group",
    members,
    epoch: 1,
    salt: b64(salt),
    commitment: b64(
      commitment(
        members.map((m) =>
          Uint8Array.from(atob(m.leaf_hash), (c) => c.charCodeAt(0)),
        ),
        5,
        1,
        salt,
      ),
    ),
    tier_raw: 0,
    group_type_raw: "tyranny",
    admin_pubkey_hex: hex(admin.blsPublic),
    member_profiles: Object.fromEntries(
      [admin, member].map((i) => [
        hex(i.blsPublic),
        {
          alias: "Test",
          inbox_public_key: b64(i.inboxPublic),
          sending_pubkey: b64(i.signingPublic),
        },
      ]),
    ),
  };
  return { admin, member, inv };
}
afterEach(() => vi.unstubAllGlobals());
it("checks own membership, admin signer, and native commitment", () => {
  const { admin, member, inv } = fixture();
  expect(() =>
    verifyInvitation(inv, member, hex(admin.signingPublic)),
  ).not.toThrow();
  expect(() =>
    verifyInvitation(inv, member, hex(member.signingPublic)),
  ).toThrow();
  expect(() =>
    verifyInvitation(
      { ...inv, commitment: b64(new Uint8Array(32)) },
      member,
      hex(admin.signingPublic),
    ),
  ).toThrow();
  const changed = structuredClone(inv);
  changed.member_profiles[hex(member.blsPublic)].sending_pubkey = b64(
    admin.signingPublic,
  );
  expect(() =>
    verifyInvitation(changed, member, hex(admin.signingPublic)),
  ).toThrow();
});
it("rejects a valid-looking invitation absent from the selected chain", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({ epoch: 1, commitment: b64(new Uint8Array(32)) }),
        ),
    ),
  );
  await expect(
    verifyChain(defaultSettings, "id", b64(new Uint8Array(32).fill(1)), 1),
  ).rejects.toThrow();
});
it("pins a historical commitment to its exact epoch", async () => {
  const wanted = b64(new Uint8Array(32).fill(1));
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ epoch: 3, commitment: b64(new Uint8Array(32)) }),
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify([{ epoch: 2, commitment: wanted }])),
      ),
  );
  await expect(verifyChain(defaultSettings, "id", wanted, 1)).rejects.toThrow();
});
it("does not mark messages sent if the relay has not acknowledged", async () => {
  const { admin, member, inv } = fixture();
  const state: State = {
    version: 1,
    phrase: member.phrase,
    name: "Test",
    settings: defaultSettings,
    pending: [],
    groups: [
      {
        ...inv,
        adminSigner: hex(admin.signingPublic),
        verifiedAt: Date.now(),
        messages: [],
      },
    ],
  };
  const vault = await createVault(state, "public test password");
  const c = new Client(
    state,
    vault.key,
    vault.salt,
    () => {},
    () => {},
    () => {},
  );
  c.transport = {
    send: async () => {
      throw Error("offline");
    },
    close: () => {},
  } as never;
  await expect(c.send(inv.group_id, "hello")).rejects.toThrow("offline");
  expect(c.state.groups[0].messages[0].delivery).toBe("failed");
  await c.close();
  expect(c.identity.signingSecret.every((n) => n === 0)).toBe(true);
  expect(c.state.phrase).toBe("");
});
