# Onym authentication and BSN website (preview)

Issuer: https://atlas.predhit.com/auth (OIDC discovery at `/auth/.well-known/openid-configuration`). Website: `/bsn-np/account`. Preview authenticator: https://onym.predhit.com/preview/ . The existing main web client is not replaced.

Uses pinned oidc-provider and openid-client, Authorization Code, mandatory PAR and PKCE S256, private_key_jwt, ES256 OP keys, pairwise subjects, explicit signing-key claim consent and Ed25519 JWS key proofs. Only the registered `atlas-bsn` RP is enabled in this release. Onboarding other websites requires server-side registration and an authenticator trust/permission integration; there is no open dynamic registration.

BSN and OP currently run in the same process on localhost:4181 under the bsn-np system account. Existing BSN signing key remains unchanged. OP/RP keys and cookie/pairwise secrets are generated once in `/var/lib/bsn-np/auth-keys.json` with mode 0600; the persistent SQLite OIDC/session store is in the same protected directory. Do not publish these files. Back up them and the existing records database together. Restarting the process retains login sessions; signing proofs expire after 120 seconds and are consumed once. RP login state is bound to an HttpOnly Secure SameSite=Lax cookie and callback verification uses state, nonce, PKCE and issuer validation. Access logs are disabled.

Both entry points currently require an explicit fresh login confirmation. Automatic repeat consent reuse and the opaque login_hint extension remain unimplemented; the UI does not promise one-click access. No user secrets leave Onym. Approved public signing keys are correlated with Stellar accounts by explicit design.

`configuration-status` uses the existing signed request envelope; its signed `configuration` reply echoes `requestNonce`, subject, state (`setup_required`, `pending`, `ready`) and timestamps. `request-issuance` accepts `useSavedConfiguration:true`, resolves only the signed subject's saved account and independently rechecks Stellar. Acceptance remains an explicit client signature. Manual Stellar account issuance remains supported for the old built-in BSN panel.

The RP website uses CSRF-protected forms. It prepares a single manageData transaction in Stellar public, uses a free OwnershipFull tag, and never signs or submits a Stellar transaction. Users sign with their own wallet. Onym preview verifies the response and explicitly accepts the name.

The browser preview stores encrypted data in `onym-web-preview`, separate from `onym-web`; both share an origin, so this is storage separation, not an origin security boundary. Import an existing encrypted backup explicitly to transfer data. The preview has its own process/release on localhost:4182. Roll back preview by switching its symlink, without restarting the main 4180 service.

Backup uses the object-http wire API with a separate derived web archive seat. Archives remain password-encrypted web vaults, not mobile sealed-device archives. Downloaded copies are restored with the existing import UI. Native archive interoperability is not claimed. Generic catalogue entries with unsupported profiles remain visible and are not activated.
