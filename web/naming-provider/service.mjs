import { readFile, writeFile, rename, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import {
  BASE,
  NS,
  REGISTRY,
  PROFILE,
  canonical,
  digest,
  unsigned,
  signed,
  valid,
  publicHex,
  validAccount,
  readEvidence,
  Fault,
} from "./protocol.mjs";
const iso = (n) => new Date(n).toISOString();
const keyOf = (s) =>
  typeof s === "string" && /^onym:key:[a-f0-9]{64}$/.test(s)
    ? s.slice(9)
    : null;
export async function createService({
  key,
  file,
  fetchAccount,
  clock = Date.now,
}) {
  let db = { records: {}, current: {}, sequence: {}, nonces: {} };
  if (file)
    try {
      db = JSON.parse(await readFile(file, "utf8"));
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
    }
  db.setups ||= {};
  const pub = publicHex(key);
  let queue = Promise.resolve();
  const sign = (kind, value) => signed(kind, value, key);
  const persist = async () => {
    if (!file) return;
    await mkdir(dirname(file), { recursive: true, mode: 0o700 });
    await writeFile(file + ".tmp", JSON.stringify(db), { mode: 0o600 });
    await rename(file + ".tmp", file);
  };
  const policy = {
    version: 1,
    registry: REGISTRY,
    network: "public",
    nameTags: ["Name", "name"],
    binding:
      "OwnershipFull or OwnershipFullN equals the Stellar StrKey of the Onym Ed25519 signing public key; same-account proof is also accepted.",
    nameUniqueness:
      "name is the full Stellar account; displayName is the exact BSN tag and is not unique.",
    recordLifetimeSeconds: 604800,
    maxStatusAgeSeconds: 60,
    publication:
      "Only records explicitly accepted with publish:true are returned in public resolution. Requests, offers and private acceptances are not enumerable.",
    privacy:
      "Public resolution exposes accepted Onym signing keys and Stellar accounts. The provider sees lookup keys and IP addresses; access logging is disabled. No conversation contents or private keys are requested.",
    revocation:
      "Every resolution rechecks Stellar. Name or binding changes revoke the old record. A new record requires a new acceptance.",
    profile: PROFILE,
  };
  const policyHash = digest(policy);
  const profile = sign("profile", {
    profileVersion: 1,
    profileId: "onym:naming-profile:qualified-association-v1",
    interface: "onym-naming-v1",
    implementationProfileId: PROFILE,
    operations: [
      "resolve-name",
      "resolve-subject",
      "request-issuance",
      "accept-record",
      "renew-record",
      "revoke-record",
      "disavow-record",
    ],
    signatureSuite:
      "Ed25519; sorted-key UTF-8 JSON; domain onym-bsn-np-v1:<kind>\\n",
    maxStatusAgeSeconds: 60,
    specification: BASE + "protocol.md",
  });
  const manifest = sign("manifest", {
    version: 1,
    componentId: "onym:component:atlas-bsn-np",
    seat: "naming.association",
    operator: "onym:key:" + pub,
    namespace: NS,
    registry: REGISTRY,
    trustRoot: { algorithm: "Ed25519", publicKey: pub },
    implementationProfileId: PROFILE,
    namingProfileId: profile.profileId,
    policy: policyHash,
    authentication: {
      protocol: "onym-oidc-v1",
      issuer: "https://atlas.predhit.com/auth",
      client_id: "atlas-bsn",
      permissions: [
        {
          scope: "urn:onym:scope:signing-key",
          required: true,
          reason:
            "Связать идентичность Onym со Stellar-аккаунтом и получить имя из BSN.",
        },
      ],
    },
    configuration: {
      mode: "website",
      required_before_use: true,
      initiate_login_uri: BASE + "login",
      description: "Укажите Stellar-адрес и подтвердите его связь с Onym.",
      status_endpoint: BASE + "v1/configuration-status",
    },
    endpoints: [
      { uri: BASE + "v1/", role: "resolve" },
      { uri: BASE + "v1/", role: "issue" },
    ],
  });
  function auth(b, operation) {
    const pub = keyOf(b?.subject),
      now = clock();
    if (
      !pub ||
      b.requestVersion !== 1 ||
      b.operation !== operation ||
      b.audience !== BASE ||
      !Number.isSafeInteger(b.issuedAt) ||
      Math.abs(now - b.issuedAt) > 300000 ||
      !Number.isSafeInteger(b.expiresAt) ||
      b.expiresAt < now ||
      b.expiresAt > b.issuedAt + 300000 ||
      !/^[a-f0-9]{32}$/.test(b.nonce) ||
      !valid("request", b, pub)
    )
      throw new Fault("invalid_subject_proof", 401);
    for (const [n, t] of Object.entries(db.nonces))
      if (t < now) delete db.nonces[n];
    const id = b.subject + ":" + b.nonce;
    if (db.nonces[id]) throw new Fault("replayed_request", 409);
    db.nonces[id] = b.expiresAt;
    return pub;
  }
  async function evidence(account, pub) {
    if (!validAccount(account)) throw new Fault("invalid_stellar_account");
    return readEvidence(await fetchAccount(account), account, pub);
  }
  function entry(hash) {
    const e = db.records[hash];
    if (!e) throw new Fault("not_found", 404);
    return e;
  }
  async function status(e) {
    if (e.disavowal) return "disavowed";
    if (e.revoked) return "revoked";
    if (
      Date.parse(e.record.expiresAt) <= clock() ||
      (e.acceptance && Date.parse(e.acceptance.expiresAt) <= clock())
    )
      return "expired";
    if (e.acceptance && db.current[e.record.name] !== digest(e.record))
      return "superseded";
    try {
      const ev = await evidence(
        e.record.stellarAccount,
        keyOf(e.record.subject),
      );
      if (
        ev.displayName !== e.record.displayName ||
        ev.nameTag !== e.record.nameTag
      )
        return "revoked";
    } catch (err) {
      if (err instanceof Fault && [404, 409, 422].includes(err.status))
        return "revoked";
      throw err;
    }
    return e.acceptance ? "active" : "unaccepted";
  }
  async function resolution(e) {
    return {
      record: e.record,
      acceptance: e.acceptance || null,
      status: await status(e),
      disavowal: e.disavowal || null,
      supersededBy:
        db.current[e.record.name] !== digest(e.record)
          ? db.current[e.record.name] || null
          : null,
    };
  }
  const envelope = (query, records) =>
    sign("resolution", {
      version: 1,
      registry: REGISTRY,
      query,
      records,
      checkedAt: iso(clock()),
      expiresAt: iso(clock() + 60000),
    });
  async function mutate(operation, b) {
    const subjectPub = auth(b, operation);
    if (operation === "configuration-status") {
      const setup = db.setups[b.subject];
      let state = "setup_required",
        displayName;
      if (setup) {
        try {
          const ev = await evidence(setup.account, subjectPub);
          state = "ready";
          displayName = ev.displayName;
        } catch (e) {
          if (e instanceof Fault && [404, 409, 422].includes(e.status))
            state = "pending";
          else throw e;
        }
      }
      await persist();
      return sign("configuration", {
        version: 1,
        subject: b.subject,
        requestNonce: b.nonce,
        state,
        ...(setup ? { stellarAccount: setup.account } : {}),
        ...(displayName ? { displayName } : {}),
        checkedAt: iso(clock()),
        expiresAt: iso(clock() + 60000),
      });
    }
    if (operation === "request-issuance" || operation === "renew-record") {
      if (b.useSavedConfiguration === true) {
        const setup = db.setups[b.subject];
        if (!setup) throw new Fault("setup_required", 409);
        b = { ...b, stellarAccount: setup.account };
      }
      const ev = await evidence(b.stellarAccount, subjectPub);
      if (Object.keys(db.records).length >= 100000)
        throw new Fault("capacity_reached", 503);
      const sequence = (db.sequence[b.stellarAccount] || 0) + 1;
      db.sequence[b.stellarAccount] = sequence;
      const record = sign("record", {
        recordVersion: 1,
        registry: REGISTRY,
        name: b.stellarAccount,
        displayName: ev.displayName,
        namespace: NS,
        subject: b.subject,
        scope: ["display-name"],
        issuedAt: iso(clock()),
        expiresAt: iso(clock() + 7 * 86400000),
        sequence,
        policy: policyHash,
        membershipCondition: null,
        stellarAccount: b.stellarAccount,
        nameTag: ev.nameTag,
        bindingTag: ev.bindingTag,
        network: "public",
      });
      db.records[digest(record)] = { record };
      await persist();
      return envelope(b.subject, [
        await resolution(db.records[digest(record)]),
      ]);
    }
    const e = entry(b.record);
    if (operation === "revoke-record") {
      if (subjectPub !== pub) throw new Fault("forbidden", 403);
      e.revoked = true;
    } else {
      if (e.record.subject !== b.subject) throw new Fault("wrong_subject", 403);
      if (operation === "accept-record") {
        const a = b.acceptance;
        if (
          !a ||
          a.acceptanceVersion !== 1 ||
          a.subject !== b.subject ||
          a.record !== b.record ||
          typeof a.publish !== "boolean" ||
          !Number.isFinite(Date.parse(a.acceptedAt)) ||
          Math.abs(Date.parse(a.acceptedAt) - clock()) > 300000 ||
          !Number.isFinite(Date.parse(a.expiresAt)) ||
          Date.parse(a.expiresAt) > Date.parse(e.record.expiresAt) ||
          Date.parse(a.expiresAt) <= clock() ||
          !valid("acceptance", a, subjectPub)
        )
          throw new Fault("invalid_acceptance", 400);
        const s = await status(e);
        if (!["unaccepted", "active"].includes(s)) throw new Fault(s, 409);
        const current = db.records[db.current[e.record.name]];
        if (current && current.record.sequence > e.record.sequence)
          throw new Fault("superseded", 409);
        e.acceptance = a;
        db.current[e.record.name] = b.record;
      } else if (operation === "disavow-record") {
        const d = b.disavowal;
        if (
          !d ||
          d.disavowalVersion !== 1 ||
          d.subject !== b.subject ||
          d.record !== b.record ||
          !Number.isFinite(Date.parse(d.effectiveFrom)) ||
          Math.abs(Date.parse(d.effectiveFrom) - clock()) > 300000 ||
          !valid("disavowal", d, subjectPub)
        )
          throw new Fault("invalid_disavowal");
        e.disavowal = d;
      } else throw new Fault("unknown_operation", 404);
    }
    await persist();
    return envelope(b.subject, [await resolution(e)]);
  }
  async function acceptedName(subject) {
    const entries = Object.values(db.records)
      .filter((e) => e.record.subject === subject && e.acceptance?.publish === true)
      .sort((a, b) => b.record.sequence - a.record.sequence);
    for (const e of entries) {
      if (await status(e) === "active") return { ...e.record };
    }
    return null;
  }
  return {
    getAcceptedName: acceptedName,
    async getSetup(subject) {
      return db.setups[subject] ? { ...db.setups[subject] } : null;
    },
    async saveSetup(subject, account) {
      if (!keyOf(subject) || !validAccount(account))
        throw new Fault("invalid_setup");
      const result = queue.then(async () => {
        const active = await acceptedName(subject);
        if (active && active.stellarAccount !== account)
          throw new Fault("active_name_account_locked", 409);
        db.setups[subject] = { account };
        await persist();
      });
      queue = result.catch(() => {});
      return result;
    },
    manifest,
    profile,
    policy,
    async call(operation, b = {}) {
      if (operation === "preview") {
        if (!validAccount(b.stellarAccount) || !keyOf(b.subject))
          throw new Fault("invalid_request");
        const data = await fetchAccount(b.stellarAccount);
        try {
          return {
            eligible: true,
            ...readEvidence(data, b.stellarAccount, keyOf(b.subject)),
          };
        } catch (e) {
          if (e.code === "binding_missing")
            return { eligible: false, ...e.detail };
          throw e;
        }
      }
      if (operation === "resolve-subject" || operation === "resolve-name") {
        const query = operation === "resolve-subject" ? b.subject : b.name;
        if (
          operation === "resolve-subject"
            ? !keyOf(query)
            : !validAccount(query?.split("@")[0]) || !query.endsWith("@" + NS)
        )
          throw new Fault("invalid_query");
        const es = Object.values(db.records).filter(
          (e) =>
            e.acceptance?.publish === true &&
            (operation === "resolve-subject"
              ? e.record.subject === query
              : e.record.name + "@" + NS === query),
        );
        const rows = [];
        for (const e of es.slice(-20)) rows.push(await resolution(e));
        return envelope(query, rows);
      }
      const result = queue.then(() => mutate(operation, b));
      queue = result.catch(() => {});
      return result;
    },
  };
}
