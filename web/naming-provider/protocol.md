# BSN Naming Provider — Stellar HTTP profile v1

Base URL: https://atlas.predhit.com/bsn-np/

This is an experimental concrete implementation of the Onym **draft** Association Naming boundary, not an upstream-certified naming standard. Reference: https://github.com/onymchat/onym-system/blob/4712694da80a9d2f82fff0fa73725af30260eb6b/association/Association-Naming.md .

## Identity and source of authority

A subject is `onym:key:<64 lowercase hex characters>`: its Onym **Ed25519 sending/signing public key** (not its BLS key, inbox key, UUID or Nostr key). Native group rosters already bind that signing key to each BLS member. The browser resolves the key from that authenticated roster; names never determine routing, membership, payments or identity recovery.

The source is **Stellar public/mainnet**, irrespective of which network a chat uses. Horizon account data is decoded from Base64 as strict UTF-8. Use the exact `Name` value, with lowercase `name` as a fallback only if `Name` does not exist. Empty names, control/format characters and values longer than 64 UTF-8 bytes are refused. Tags are never modified by this provider.

The source account must contain `OwnershipFull` or `OwnershipFullN` (N is decimal digits) equal to the Stellar StrKey derived from the subject's Ed25519 key. The subject then proves possession of that key and accepts the precise issued record. If the source account equals this StrKey, the same-key proof suffices. A wallet password, seed, secret key or Stellar transaction is never sent to this provider.

`OwnershipFull` by itself is not treated as sufficient BSN reciprocal ownership evidence: the Onym signature supplies the other side for this particular naming assertion. No claim of reciprocal ownership in other BSN tools is made.

Names are not unique. `record.name` is the full source Stellar account; `record.displayName` is the exact BSN tag. The canonical qualified name is `<G-address>@bsn.atlas.predhit.com`. UI shows displayName, registry namespace and shortened account, with the full qualified name available. Homonyms are never merged.

## Discovery and trust

GET `manifest.json`: signed Registry Manifest, Ed25519 trust root and policy hash.
GET `profile.json`: signed Naming Profile.
GET `policy.json`: versioned policy, authenticated by the manifest's policy digest.
GET `health`: service liveness.

The web client pins public key `82693a8632f81e2e26b777a34b9d82adb5a60138530cc840fc9eae9d2344806e`. A key change fails closed until an explicitly reviewed client update. Display is optional; the viewer can disable this registry. The current client supports this one selected provider, not arbitrary registry URLs.

## Encoding and signatures

JSON UTF-8; recursively lexicographically sorted object keys; compact separators; array order retained; no Unicode normalization or float values in signed objects. `signature` is excluded from bytes to sign. All field values and any extension fields are covered. Unknown fields are rejected by the browser for records/resolution objects.

Signature input: UTF-8 `onym-bsn-np-v1:<kind>\n` followed by canonical unsigned JSON. The newline is one LF byte. Kinds: `profile`, `manifest`, `request`, `record`, `acceptance`, `disavowal`, `resolution`.

Signatures: Ed25519, standard Base64. Digests: `sha256:` plus lowercase SHA-256 hex of canonical **complete signed** object (signature included). No floating-point timestamps: requests use integer milliseconds, record dates use ISO-8601 UTC.

## HTTP operations

All operations below use POST JSON to `v1/<operation>`. No cookies or API keys. Bodies are limited to 16 KiB; HTTPS is required. CORS is limited to the Atlas and Onym Web origins. Native/CLI callers may omit Origin. Public information endpoints need no holder signature.

- `preview`: `{stellarAccount, subject}` returns the tag and binding eligibility, or the required binding tag/value. This is informational, never an accepted name.
- `resolve-subject`: `{subject}` returns registry-signed `records`, `query`, `checkedAt`, `expiresAt`. Only records with acceptance `publish:true` are exposed.
- `resolve-name`: `{name:"<G-address>@bsn.atlas.predhit.com"}` returns the same resolution envelope. Bare display names are not lookup keys.
- `request-issuance` and `renew-record`: signed request with `stellarAccount`. Returns an unaccepted registry-signed AssociationRecord. Record lifetime is seven days. Name changes and renewal always need new acceptance.
- `accept-record`: signed request with `record` digest and signed `acceptance`. Acceptance fields: `acceptanceVersion:1`, `record`, `subject`, `publish:boolean`, `acceptedAt`, `expiresAt`, `signature`. Expiry must not exceed record expiry. Only successful acceptance supersedes the previous current name for that Stellar account. Browser acceptance publishes the link explicitly; API also supports private acceptance.
- `disavow-record`: signed request with record digest and signed `disavowal`: `{disavowalVersion:1,record,subject,effectiveFrom,signature}`. Immediate and irreversible for that record; renewal is separate.
- `revoke-record`: signed request with record digest, authenticated by the registry key (not the holder). Normal operation automatically withdraws a record when Stellar evidence ceases to match.

Signed request common fields:

```json
{"requestVersion":1,"operation":"request-issuance","audience":"https://atlas.predhit.com/bsn-np/","subject":"onym:key:<hex>","stellarAccount":"G...","issuedAt":1790000000000,"expiresAt":1790000120000,"nonce":"<32 random lowercase hex characters>","signature":"<Base64>"}
```

A request must be within five minutes of server time, expires within five minutes, and its nonce may be consumed once per subject. Successful state changes persist nonce and record state atomically to a mode-0600 file; operations are serialized. Clients generate a new nonce when retrying. Server time and key files must persist across deployments.

## Records and freshness

AssociationRecord fields follow the draft: recordVersion, registry, name, subject, scope `["display-name"]`, issuedAt, expiresAt, sequence, policy, membershipCondition null, signature. This profile adds displayName, namespace, stellarAccount, nameTag, bindingTag and network.

Responses contain rows `{record,acceptance,status,disavowal,supersededBy}`. Status: active, unaccepted, expired, superseded, revoked, disavowed. Signatures alone are insufficient: acceptance subject/digest, both expirations, manifest policy, subject lookup and response freshness must match. The browser checks all of them.

Every potentially active resolution rereads Horizon; no name cache is used by the provider. Upstream failure fails closed. A signed resolution is fresh for at most 60 seconds. The browser refreshes every 30 seconds while unlocked and drops expired evidence. Horizon remains a trusted public ledger gateway in this profile; the provider does not run a Stellar validator or prove ledger inclusion to the client.

Stellar tag removal, ownership change or name change makes the previous record inactive. Status derived from live Stellar evidence may become active again if the original evidence is restored before expiry; an explicit disavowal or registry revocation cannot. A newer **accepted** sequence permanently supersedes the old record. Losing the registry never loses Onym keys or chats.

## Privacy and practical limits

Publication is separate from requesting an offer. Before accepting, the UI explains that the Stellar account, Onym signing key and selected name become publicly resolvable. The provider never receives chats, BLS secrets, inbox secrets, recovery phrases or vault passwords. Public records, including published disavowals, remain available as historical assertions; unaccepted/private offers are not public. The public resolver returns the most recent 20 published records for a query.

Viewer lookups reveal queried signing keys and request IPs to the service. This is explicitly opt-in. The web client resolves its own key plus up to 19 other members of the currently open group; it does not upload all contacts. Access logs are disabled. Reverse resolution is not private-information retrieval. Records are retained on the operator's disk; there is no admin analytics interface or arbitrary URL proxy.

Limits: 120 requests/minute/IP, 100,000 stored records, 256 KiB upstream response, eight-second Horizon timeout. This alpha uses a single-process file store; multi-instance deployment, automatic trust-root rotation, anonymous queries and exhaustive upstream conformance fixtures are not implemented. Existing native clients receive the annotated alias on new joins but cannot independently verify this BSN profile until they implement it.

## Operations

Run `server.mjs` with Node 24. `BSN_KEY_FILE` is an existing raw 32-byte seed, `BSN_DB_FILE` is the private database path, `PORT` defaults to 4181 on loopback. The service never auto-generates or rotates a key. Keep the key and database outside release directories and back them up together. `bsn-np.service` and `nginx.conf` show the isolated systemd service and Atlas path proxy. Test with `npm test` from `web/`; no production key is used in tests.

## Ready-to-sign Stellar binding transaction

Onym Web constructs an **unsigned** XDR locally using the official Stellar SDK. It reloads the source account and sequence from Horizon, finds the first unused `OwnershipFull`/`OwnershipFullN` key, and creates exactly one ManageData operation containing the Onym signing key's Stellar address. Existing tags are never overwritten; the current account sequence prevents reuse after another transaction from the same source.

The transaction uses Stellar PUBLIC, a 15-minute validity window, and the maximum of the current base fee and the observed p90 charged fee, capped at 0.01 XLM. The UI shows that exact fee and the current base reserve required for one new data entry. It offers XDR copy/download and a `web+stellar:tx` SEP-7 URI. No callback URL, secret, payment, signer change, or auto-submit is included. The holder signs and submits in their own Stellar wallet, then clicks “Я отправил — проверить связь”. Generating XDR alone neither modifies Stellar nor publishes a naming acceptance.
