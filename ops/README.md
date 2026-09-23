# Onym Web deployment

Target: `https://onym.predhit.com`, on the existing Predhit Ubuntu server.
The web client is an alpha; creating/administering groups and membership removal/rekey support remain incomplete. Use test identities and test groups.

Build `web/` locally with `npm ci`, `npm test`, `npm run build`. Deploy only `web/dist/` and `web/server/` into `/opt/onym-web/releases/<release>/`, with `dist` and `server` as sibling directories. Retain the previous release for rollback. Point `/opt/onym-web/current` at the verified release.

The Node runtime is isolated in `/opt/onym-web/runtime`, with the official Node.js 24 LTS binary. Verify the archive against the SHA-256 checksum from `nodejs.org` before unpacking. Runtime security updates are an operator responsibility.

Install `onym-web.service` after creating a system user `onym-web` with no login shell. The service has read-only access to its files and listens only on `127.0.0.1:4180`. It stores no identity or conversation database and requires no application secrets. Enable it with `systemctl enable --now onym-web`.

Install the nginx template as `/etc/nginx/sites-available/onym.predhit.com`, link it in `sites-enabled`, run `nginx -t`, then reload nginx. Add an A record for `onym.predhit.com` pointing at this server. Once authoritative DNS resolves correctly, run `certbot --nginx -d onym.predhit.com --non-interactive --redirect` using the server's existing ACME account. Do not overwrite the resulting TLS configuration during updates.

Checks: HTTPS certificate and redirect, HTML/CSS/JS byte equality with the release, wrong-method and invalid-body rejection for `/api/chain`, browser key creation/unlock/lock, and relay connectivity. A real mobile-device conversation is a separate interoperability check.

Access logging is off to avoid retaining invitation URLs. The chain proxy supports only `get_commitment` and `get_history` and never forwards client-selected URLs, credentials or message payloads. Nginx and the Node service must continue preserving these limits.

Updates: upload a new release, test locally, switch `current`, restart `onym-web`, then check HTTPS. Rollback switches `current` back and restarts only `onym-web`. Do not remove users' browser vaults or change the site's origin; local encrypted storage belongs to that origin. Atlas and Simple backup are separate services.
