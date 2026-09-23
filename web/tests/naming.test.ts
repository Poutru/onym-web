import { it, expect, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { identityFromPhrase } from "../src/identity";
import { hex } from "../src/bytes";
import {
  recordDigest,
  requestProof,
  verifyResolution,
  verifySigned,
} from "../src/naming";
// Provider uses only Node built-ins; wire interoperability is tested against the browser verifier.
// @ts-ignore untyped Node service module
import { createService } from "../naming-provider/service.mjs";
// @ts-ignore untyped Node protocol module
import {
  privateKey,
  publicHex,
  signed,
  digest,
  stellarAddress,
  validAccount,
  readEvidence,
  // @ts-ignore untyped Node protocol module
} from "../naming-provider/protocol.mjs";
const alice = identityFromPhrase(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const aliceKey = hex(alice.signingPublic),
  subject = "onym:key:" + aliceKey;
const account = "GCPJUXPETZEIJNEAAEO2LGZIA6IQNNWGOHPNP4ZQECDS6IKKIGJO5LFV";
const enc = (v: string) => Buffer.from(v).toString("base64");
const issuer = privateKey(Buffer.alloc(32, 41));
const issuerPublic = publicHex(issuer);
const directories: string[] = [];
afterEach(async () => {
  for (const d of directories.splice(0))
    await rm(d, { recursive: true, force: true });
});
async function setup() {
  let data: Record<string, string> = {
    Name: enc("Valerij Utrosin"),
    OwnershipFull3: enc(alice.stellarAccount),
  };
  const dir = await mkdtemp(join(tmpdir(), "onym-naming-"));
  directories.push(dir);
  const options = {
    key: issuer,
    file: join(dir, "db.json"),
    fetchAccount: async () => data,
  };
  const service = await createService(options);
  const request = (op: string, fields: Record<string, unknown> = {}) =>
    service.call(op, requestProof(op, fields, alice));
  const offer = async () =>
    (await request("request-issuance", { stellarAccount: account })).records[0]
      .record;
  const accept = async (record: any, publish = true) =>
    request("accept-record", {
      record: digest(record),
      acceptance: signed(
        "acceptance",
        {
          acceptanceVersion: 1,
          record: digest(record),
          subject,
          publish,
          acceptedAt: new Date().toISOString(),
          expiresAt: record.expiresAt,
        },
        privateKey(Buffer.from(alice.signingSecret)),
      ),
    });
  return {
    service,
    options,
    request,
    offer,
    accept,
    setData: (v: Record<string, string>) => {
      data = v;
    },
  };
}
it("validates Stellar checksum and exact BSN binding, not an unrelated ownership tag", () => {
  expect(validAccount(account)).toBe(true);
  expect(validAccount(account.slice(0, -1) + "A")).toBe(false);
  expect(stellarAddress(aliceKey)).toBe(alice.stellarAccount);
  expect(() =>
    readEvidence(
      { Name: enc("Alice"), OwnershipFull: enc(account) },
      account,
      aliceKey,
    ),
  ).toThrow("binding_missing");
  expect(
    readEvidence(
      { name: enc("Алиса"), OwnershipFull27: enc(alice.stellarAccount) },
      account,
      aliceKey,
    ).displayName,
  ).toBe("Алиса");
  expect(() =>
    readEvidence(
      { Name: enc("Alice\u202E"), OwnershipFull: enc(alice.stellarAccount) },
      account,
      aliceKey,
    ),
  ).toThrow("name_missing_or_unsafe");
});
it("requires explicit acceptance and publication before reverse or forward resolution", async () => {
  const s = await setup(),
    record = await s.offer();
  expect(
    (await s.service.call("resolve-subject", { subject })).records,
  ).toEqual([]);
  await s.accept(record, false);
  expect(
    (
      await s.service.call("resolve-name", {
        name: account + "@bsn.atlas.predhit.com",
      })
    ).records,
  ).toEqual([]);
  await s.accept(record, true);
  const resolution = await s.service.call("resolve-subject", { subject });
  expect(resolution.records[0].status).toBe("active");
  expect(verifySigned("resolution", resolution, issuerPublic)).toBe(true);
  expect(recordDigest(record)).toBe(digest(record));
  expect(
    verifySigned("acceptance", resolution.records[0].acceptance, aliceKey),
  ).toBe(true);
  const restarted = await createService(s.options);
  expect(
    (await restarted.call("resolve-subject", { subject })).records[0].status,
  ).toBe("active");
});
it("rejects tampered proof, replay, wrong subject and malformed acceptance timestamps", async () => {
  const s = await setup();
  const req = requestProof(
    "request-issuance",
    { stellarAccount: account },
    alice,
  );
  await s.service.call("request-issuance", req);
  await expect(s.service.call("request-issuance", req)).rejects.toThrow(
    "replayed_request",
  );
  await expect(
    s.service.call("request-issuance", {
      ...req,
      stellarAccount: alice.stellarAccount,
    }),
  ).rejects.toThrow("invalid_subject_proof");
  const record = await s.offer();
  const invalid = signed(
    "acceptance",
    {
      acceptanceVersion: 1,
      record: digest(record),
      subject,
      publish: true,
      acceptedAt: "bad",
      expiresAt: record.expiresAt,
    },
    privateKey(Buffer.from(alice.signingSecret)),
  );
  await expect(
    s.request("accept-record", { record: digest(record), acceptance: invalid }),
  ).rejects.toThrow("invalid_acceptance");
  await expect(
    s.request("revoke-record", { record: digest(record) }),
  ).rejects.toThrow("forbidden");
});
it("withdraws names when Stellar data changes and requires fresh acceptance for renewal", async () => {
  const s = await setup(),
    record = await s.offer();
  await s.accept(record);
  s.setData({
    Name: enc("New Name"),
    OwnershipFull: enc(alice.stellarAccount),
  });
  expect(
    (await s.service.call("resolve-subject", { subject })).records[0].status,
  ).toBe("revoked");
  const next = await s.offer();
  expect(next.displayName).toBe("New Name");
  await s.accept(next);
  const rows = (await s.service.call("resolve-subject", { subject })).records;
  expect(rows.map((r: any) => r.status)).toEqual(["superseded", "active"]);
  s.setData({ Name: enc("New Name") });
  expect(
    (await s.service.call("resolve-subject", { subject })).records.at(-1)
      .status,
  ).toBe("revoked");
});
it("publishes holder disavowal and prevents reactivation", async () => {
  const s = await setup(),
    record = await s.offer();
  await s.accept(record);
  const disavowal = signed(
    "disavowal",
    {
      disavowalVersion: 1,
      record: digest(record),
      subject,
      effectiveFrom: new Date().toISOString(),
    },
    privateKey(Buffer.from(alice.signingSecret)),
  );
  await s.request("disavow-record", { record: digest(record), disavowal });
  expect(
    (await s.service.call("resolve-subject", { subject })).records[0].status,
  ).toBe("disavowed");
  await expect(s.accept(record)).rejects.toThrow("disavowed");
});
it("browser rejects responses from an unpinned registry even when otherwise valid", async () => {
  const s = await setup(),
    record = await s.offer();
  const r = await s.accept(record);
  expect(() => verifyResolution(r, subject, record.policy)).toThrow("Подпись");
  const tampered = { ...r, query: "onym:key:" + "a".repeat(64) };
  expect(verifySigned("resolution", tampered, issuerPublic)).toBe(false);
});

it("browser verifies both signatures and fails closed on stale, expired or unaccepted active names", async () => {
  const s = await setup(),
    record = await s.offer(),
    r = await s.accept(record);
  expect(
    verifyResolution(r, subject, record.policy, Date.now(), issuerPublic)
      .records[0].record.displayName,
  ).toBe("Valerij Utrosin");
  expect(() =>
    verifyResolution(
      r,
      subject,
      record.policy,
      Date.now() + 61000,
      issuerPublic,
    ),
  ).toThrow();
  const changed = structuredClone(r);
  changed.records[0].record.displayName = "Fake Name";
  const fake = signed("resolution", changed, issuer);
  expect(() =>
    verifyResolution(fake, subject, record.policy, Date.now(), issuerPublic),
  ).toThrow("Неверная запись");
  const noConsent = structuredClone(r);
  noConsent.records[0].acceptance = null;
  expect(() =>
    verifyResolution(
      signed("resolution", noConsent, issuer),
      subject,
      record.policy,
      Date.now(),
      issuerPublic,
    ),
  ).toThrow("Владелец");
  const changedSubject = structuredClone(r);
  changedSubject.records[0].acceptance.signature =
    Buffer.alloc(64).toString("base64");
  expect(() =>
    verifyResolution(
      signed("resolution", changedSubject, issuer),
      subject,
      record.policy,
      Date.now(),
      issuerPublic,
    ),
  ).toThrow("Владелец");
});
