# Web port: scope and provenance

## Baselines

- Android fork: `onymchat/onym-android@b5d21e7b820cf43a922ece1b3bb334d7868c798c`.
- iOS derivation fixture: `onymchat/onym-ios@4e7f60bc28c7ae4b87281117eeac5f5ee1c4f8cf`, `Tests/OnymIOSTests/IdentityRepositoryTests.swift`.
- Poseidon and Soroban fixture: `onymchat/onym-contracts@42d20216d964a4ea842bf36ee67614860f38909e`, `plonk/prover/src/circuit/plonk/poseidon.rs`, `baker.rs`, `plonk/verifier/tests/fixtures/tyranny-create-pi-d{5,8,11}.bin`.
- Independent envelope fixture: `web/scripts/mobile-envelope.swift`, generated with Apple CryptoKit using public deterministic test keys. Regenerate with `swift web/scripts/mobile-envelope.swift`.

## Module mapping

| Web | Mobile reference |
| --- | --- |
| `identity.ts` | `Bip39`, `IdentityRepository`, `IdentityId`, `StellarStrKey` |
| `poseidon.ts` | Rust `sep-common-ffi`, native Poseidon parameters |
| `wire.ts` | `SealedEnvelope`, `GroupInvitationPayload`, `ChatMessagePayload`, `IntroCapability` |
| `transport.ts` | `NostrInboxTransport` kind 34113 and legacy 24113 |
| `client.ts` | `JoinRequestSender`, `IncomingMessageDispatcher` subset |
| `vault.ts` | Web-specific encrypted persistence boundary |

No mobile binary has been embedded. Standard curves/hash algorithms use pinned Noble/Scure dependencies. Poseidon parameter generation and sponge behavior are ported from the native reference; the resulting commitments match the reference binary fixtures. This covers hashing, not zero-knowledge proof generation.

## Boundaries

- One identity/vault per origin in this version. A Web Lock prevents two tabs from simultaneously writing it.
- IndexedDB stores one authenticated encrypted envelope. The name, phrase, group secrets, profiles and messages are all inside it.
- The password derives a non-extractable Web Crypto AES key. Salt, nonce and fixed KDF parameters are public. Imports reject attacker-selected KDF parameters and oversized input.
- A separate password does not change the Onym key derivation. BIP39 uses the empty passphrase like the inspected mobile path; an extra BIP39 passphrase is not supported by this UI.
- Lock tears down relay connections and clears identity secret arrays. Native immutable strings and GC copies cannot be reliably wiped; this is documented, not presented as secure-memory hardware.
- An invitation must match a requested group, contain this identity's keys/leaf, have an internally valid commitment, and agree with the configured chain reader. The admin signing key is pinned on first accepted invitation, consistent with the inspected mobile trust boundary. The chain reader itself is trusted, not independently verified by a browser light client.
- Messages must have a valid Nostr signature and signed sealed envelope, and the envelope signer must match the claimed member's stored Ed25519 key. Sender aliases remain self-asserted.
- Seen event IDs and message IDs are deduplicated with bounded buffers. Relay `OK` is acceptance, not delivery to a recipient.
- Fixed `/api/chain` proxy allows only two read calls, reconstructs fields, imposes request/response/time/rate bounds, and cannot forward user-chosen URLs or credentials. Logs should not record POST bodies. Custom HTTPS relayers require CORS.
- First-version group membership removals/rekeys are not implemented. Use test groups without membership churn. This remains a blocker for a production chat deployment.

## Local validation record (2026-09-23)

- Production build and TypeScript checks passed. All 13 tests passed, including actual production-server HTML/assets and proxy rejection checks.
- Native identity vectors and commitment fixtures passed.
- Wrong password, malformed KDF, corrupt ciphertext and invalid signatures rejected.
- Browser import of the public `abandon × 11 + about` test phrase produced the expected keys.
- Browser Nostr connection reached `Подключено`.
- Browser lock and wrong-password rejection checked manually.
- Mobile-device conversation and production deployment are not claimed.
