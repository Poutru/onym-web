# Onym Web

Independent browser client derived from [onymchat/onym-android](https://github.com/onymchat/onym-android). The original Android source remains in this fork; the web application is in **[`web/`](web/)**.

**Early implementation, not an official Onym release and not a complete mobile-client replacement. Use a test identity until a security review and a real-device interoperability session are complete.**

## Run

Requires Node.js 22.12+ (or a newer supported LTS).

```sh
cd web
npm ci
npm run build
npm test
npm start
```

Open **http://127.0.0.1:4173**. For a hosted installation, put the Node server behind HTTPS. `HOST` defaults to `127.0.0.1`; set `HOST=0.0.0.0` only inside a properly configured container/reverse-proxy deployment. `PORT` defaults to `4173`.

The small server serves the built app and forwards **only** `get_commitment` / `get_history` calls to `https://relayer.onym.app`. The official endpoint does not currently handle browser CORS preflight. No identity secrets, recovery phrases, plaintext messages or encrypted archives are uploaded to this server. Encrypted message envelopes travel directly from the browser to the chosen Nostr relay.

## Implemented

- Create a 12-word identity or import a valid 12/24-word Onym recovery phrase.
- Byte-identical mobile identity derivation: BLS, Nostr, Ed25519, X25519, UUID, Stellar address and inbox tag.
- Password-encrypted **IndexedDB** vault: Argon2id (64 MiB, 3 iterations, parallelism 1), AES-256-GCM, random salt and per-write nonce. Includes keys, settings and conversation history.
- Explicit lock, five-minute idle lock, one-minute background lock, and exclusive-tab Web Lock.
- Export/import the encrypted web vault, without sending the password to a server.
- View/copy public keys and edit the local alias.
- Join existing **Tyranny** groups through `https://onym.app/join?c=…` links, including explicit acceptance of group rules.
- Verify invitation membership commitments with the native Onym Poseidon parameters, then check the selected relayer's exact epoch/current or historical commitment.
- Receive authenticated mobile-format envelopes and member announcements; send/receive text chat messages. Outgoing messages become “accepted by relay” only after a Nostr `OK`; this is **not** a recipient read receipt.
- Configure relay, Stellar network and Tyranny contract.
- Receive native group invitation offers, preview and explicitly accept them.
- Optional BSN names: signed requests, Stellar OwnershipFull binding, explicit record acceptance, pinned registry verification, live freshness checks and disavowal. Provider deployed at https://atlas.predhit.com/bsn-np/; source and HTTP specification in [web/naming-provider/](web/naming-provider/protocol.md). This is an experimental implementation profile of the Onym naming draft.

## Not implemented yet

- Browser generation of TurboPlonk group-create/update proofs; creating/administering groups and establishing new 1:1 groups.
- Media, calls, moderation, payments, push notifications, multi-identity UI, group rename/avatar/removal events.
- Onym Object HTTP backup interoperability: the downloadable file is a **web-vault archive**, not an Onym mobile backup.
- Guaranteed historical recovery solely from a phrase. Group state needs the encrypted web archive or a new invitation; relays may not retain old events.

## Validation

`npm test` checks official mobile key vectors, native Rust/Soroban commitment fixtures for depths 5/8/11, an independently generated Apple CryptoKit envelope, tampering/wrong-password rejection, membership/signer validation and relay failure handling. See [`docs/WEB-IMPLEMENTATION.md`](docs/WEB-IMPLEMENTATION.md) for provenance and trust boundaries.

An actual mobile-to-browser end-to-end conversation has **not** yet been run. Source-format compatibility and the tests above are narrower evidence; do not present them as a completed device interoperability test.

## Security model

The password protects stored data from offline access. It does not protect an unlocked session from malicious JavaScript, a compromised deployment or a hostile browser extension. No analytics or third-party runtime scripts/fonts are included. JavaScript garbage collection does not offer guaranteed memory erasure; typed secret arrays are cleared on lock, and references are dropped where possible.

Clearing site data destroys the local vault. A forgotten password cannot be reset by the server. The recovery phrase recovers keys, **not message history**. Export an encrypted copy before changing devices or clearing site data.

MIT. Original copyright notices are retained. Android reference documentation: [`docs/ANDROID-UPSTREAM.md`](docs/ANDROID-UPSTREAM.md).
