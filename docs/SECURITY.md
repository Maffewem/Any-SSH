# Any-SSH design and security notes

Any-SSH is a self-hosted, multi-user SSH client. People sign in from any browser (desktop, Mac, iPhone, Android) and get a
real terminal; the server holds the SSH keys and makes the SSH connections on their behalf. That makes the Any-SSH server
the most sensitive box in the setup: whoever controls it can reach every saved server. This document says how it is
protected, and what is deliberately left for later.

## Architecture

```
 Browser / PWA (React + xterm.js)
        │  HTTPS: JSON API, HttpOnly session cookie
        │  WSS:   /api/terminal  (single-use ticket + cookie + Origin check)
        ▼
 Any-SSH server (Node 22, Fastify, TypeScript)
   ├─ SQLite (better-sqlite3): users, sessions, keys, servers, shares, audit log
   ├─ Secrets sealed with AES-256-GCM under ANYSSH_MASTER_KEY
   └─ ssh2 client ──SSH──▶ your servers
```

**Why this stack.** Node + TypeScript on both sides keeps one language and one type system across the API and UI.
Fastify is a mainstream, fast framework with first-party plugins for exactly what we need (cookies, Helmet headers, rate
limiting, WebSockets). `ssh2` is the de facto pure-JS SSH implementation. xterm.js is the terminal used by VS Code and most
web terminals. SQLite keeps a self-hosted install to one process and one file; the data layer is plain SQL so moving to
Postgres later is mechanical. A responsive PWA is the quickest route to "works on Mac and iPhone" with one codebase; native
wrappers can come later.

## Accounts and sign-in

| Control | Implementation |
| --- | --- |
| Password hashing | Argon2id, 64 MiB / 3 passes / 4 lanes (OWASP baseline). Hashes are upgraded on login if parameters change. |
| Password policy | Minimum 12 characters, max 256, not a common password, must not contain the username. |
| Username enumeration | Unknown usernames still run a full Argon2 verification and return the same error as a wrong password. |
| Brute force | Per-IP rate limits on login and MFA (10/min) and first-run setup (5/min); account locked 15 min after every 5 consecutive failures (password or MFA). Admins can unlock. |
| MFA | TOTP (RFC 6238, works with any authenticator app). ±30 s drift, replay of a used code is rejected. Ten single-use recovery codes, stored as SHA-256 hashes. TOTP seed is encrypted at rest. |
| Sessions | 256-bit random token in an `HttpOnly`, `SameSite=Strict` cookie (`__Host-` prefixed and `Secure` in production). Only the token's SHA-256 is stored, so a database leak cannot be replayed as cookies. Locks after 15 min idle, signs out after 120 min idle, 12 h absolute expiry (all configurable). |
| Idle lock | Decided server-side from the last real activity (API calls, terminal keystrokes, and a throttled heartbeat when the browser sees keyboard or pointer use; the lock screen's own state check does not count). A locked session gets `401 session_locked` from every API call except `me`, `state`, `unlock` and `logout`, cannot get terminal tickets, and its open terminals are paused: keystrokes are dropped and the SSH channel stops reading, so output waits on the remote side instead of reaching an unattended screen. Unlocking needs the account password only (the session already passed 2FA); 5 wrong passwords end the session, a locked-out account cannot unlock, and the idle sign-out and absolute lifetime still apply while locked. Users can also lock on demand. |
| Session fixation | A new token is issued after the password step, after MFA, and after a password change. |
| Revocation | Users can see and sign out their devices. Password change signs out all other sessions. Disabling, demoting, resetting or deleting a user ends their sessions and closes their live terminals immediately. |
| First run | No default credentials. On an empty database the server prints a one-time setup token to its console; it is required to create the first administrator and is discarded afterwards. |
| Admin-created accounts | With an email address: an invite link (72 h, single use) lets them choose their own password; until then the account has an unusable random password. Without one: a random 20-character temporary password shown once to the admin, which must be changed at first sign-in. |
| Password reset | "Forgot password" takes a username or email and always gives the same answer, so it cannot be used to discover accounts. If the account has an email, it gets a single-use link valid for 30 minutes; a new link revokes the previous one, and repeat requests within 2 minutes are ignored (5 requests/min/IP). Completing a reset signs out every session and closes open terminals. **It does not bypass 2FA**: the next sign-in still asks for a code. Admins can email a reset link (or re-send an invite) from the user's page. |
| Link tokens | 256-bit random, stored only as SHA-256, carried in the URL fragment (`#/reset?token=…`) so they never reach server logs, proxies or `Referer` headers, and removed from the address bar once used. |
| Security notices | Users get an email when their password is changed or reset, 2FA is turned on or off, recovery codes are regenerated, or their email address changes (sent to the *old* address). |
| Email address changes | Need the current password, and cancel any pending reset links, so a hijacked session cannot quietly redirect resets to an attacker's mailbox. |

## Authorisation model

- **Roles:** `admin` and `user`. Admins manage accounts and read the audit log. There is always at least one active admin,
  and admins cannot demote, disable or delete themselves.
- **Admins do not get implicit access to other people's servers or keys.** Administration and data access are separate,
  so a compromised admin session cannot silently open a shell on every server.
- **Servers** belong to an owner. The owner can share a server with any number of users:
  - `use`: can connect. Cannot see or change host, username or credentials.
  - `manage`: can also rename it, edit notes and forget the pinned host key.
  - Only the owner can change connection details or credentials, grant `manage`, or delete. This stops a manager from
    re-pointing a server that stores a password at a machine they control and harvesting it.
- **Re-sharing is off by default.** A `manage` grant carries a separate "can re-share" flag that only the owner can set.
  Without it, the share dialog is hidden and the API refuses the grant, so access cannot spread without the owner's say-so.
  With it, a manager may still only grant `use`, never `manage`, and never more than they hold themselves.
- **Whose credentials.** Each share records whether the person connects with the server's saved credentials or must
  supply their own. Switching an existing share to "their own" closes their open terminals on that server at once, and
  the choice is re-checked when the terminal socket opens, not just when the ticket is issued. A manager who must bring
  their own credentials cannot hand the owner's to anyone else.
- **Credential use without disclosure.** People sharing the owner's credentials connect using the owner's key or stored
  password, but the secret never leaves the Any-SSH server. They only ever see the server's name and address.
- **Own credentials** are a saved key belonging to the connecting user, a password typed at connect time, or a one-off
  key (below). A user can only ever select one of their own stored keys.
- **SSH keys** are private to their owner and can only be attached to the owner's own servers.
- Anything you cannot access returns **404, not 403**, so IDs cannot be probed.
- Revoking a share closes that person's open terminals on that server immediately.

## Secrets at rest

Private keys, stored SSH passwords and TOTP seeds are sealed with **AES-256-GCM** using `ANYSSH_MASTER_KEY` (32 random
bytes supplied by environment variable or file; the server refuses to start without one). Every ciphertext is bound
(as GCM additional data) to the row and column it belongs to, e.g. `ssh_key:<id>:private`, so a ciphertext copied to
another row fails to decrypt instead of handing one user's key to another. Ciphertexts carry a key ID to support
rotation.

- The database file is created `0600`, the data directory `0700`, and SQLite `secure_delete` is on.
- Private keys are returned by the API only through **`POST /api/keys/:id/export`**, to the key's owner, after
  re-entering the account password (rate-limited to 5/min, audited, and an email notice is sent). Nothing else ever
  returns key material: a key attached to a server is invisible to the people it is shared with.
- **One-off keys.** A user may paste a private key at connect time instead of saving one. It is parsed and checked for
  weak types, held in the connect ticket in memory, used for that SSH handshake and then dropped. It is never written to
  the database and never appears in the audit log; only the fingerprint is recorded.
- Imported keys protected by a passphrase are stored with that passphrase (both sealed), so they can be used without
  prompting.
- Decrypted secrets exist only in memory for the duration of an SSH handshake.

- **Key rotation.** Generate a new key, start the server with `ANYSSH_MASTER_KEY=<new>` and
  `ANYSSH_PREVIOUS_MASTER_KEYS=<old>`, then run `npm run rotate-keys`. Every sealed value is re-encrypted under the new key
  (safe while the server is running), the run is audited, and the server warns at startup while anything still uses a
  retired key. Then drop the old key.
- **Settings changed in the web UI** are stored in the `settings` table. The SMTP password is sealed under
  `setting:mail`, re-sealed by key rotation, and never returned by the API (the admin page only learns whether one is
  saved). Changing the SMTP server or username drops the saved password unless a new one is entered, so a hijacked admin
  session cannot redirect SMTP to its own server and collect the old password.
- Key material (and the SMTP password) is removed from `process.env` as soon as it is read, so child processes never
  inherit it. `ANYSSH_MASTER_KEY_FILE` (e.g. a Docker/Kubernetes secret) is preferred over the environment variable.
- **Weak keys are refused on import:** DSA, and RSA below 2048 bits. Generated keys are Ed25519 by default.
- **Every use of a stored key is attributable:** the SSH session audit entry records which key (by fingerprint) and
  auth method were used, and each key shows when it was last used, so unexpected use stands out.

**Keep the master key out of the database backup.** A stolen database without the key yields no usable secrets; the two
together yield everything.

## Email

Outgoing mail uses SMTP configured with `ANYSSH_SMTP_*` variables, or by an admin on the **Settings** page, which then
takes precedence (until reset) and applies without a restart. A test email can be sent from there. Changes are audited
(field names only, never the password) and the admin gets a security notice. TLS is mandatory: implicit TLS on port 465, otherwise
STARTTLS is required and the connection fails rather than sending a reset link in clear text (TLS 1.2+). Messages are plain
text only. Without SMTP configured, emails are written to the server log (for development), and admins are shown invite
and reset links directly so they can pass them on.

## Terminal connections

1. The browser asks `POST /api/servers/:id/connect` for a ticket. The server checks access and the per-user terminal limit
   (default 8) and returns a random ticket valid for **30 seconds, single use**, bound to that user, server and session.
2. The browser opens `wss://…/api/terminal?ticket=…`. The server burns the ticket first, then requires that the
   `Origin` header is an allowed origin and that the session cookie is the one the ticket was issued to. This blocks
   cross-site WebSocket hijacking.
3. **Host key verification (no blind trust).** The SHA-256 fingerprint of the server's host key is pinned per saved
   server. On first connection the owner (or a manager) is shown the fingerprint and must explicitly trust it; people with
   `use` access cannot trust on first use and are refused until the owner has. The ticket also carries which credentials
   the connection uses (saved, one of the user's own keys, a one-off key, or a password prompt) and the SSH login name. A changed key is **refused**, shown as a
   possible attack and audited. Changing a server's host or port clears the pin.
4. **SSRF guard.** The hostname is resolved once and the vetted IP is what we dial (no DNS rebinding window). Loopback,
   link-local (including cloud metadata `169.254.169.254`), unspecified and multicast addresses are refused unless
   `ANYSSH_ALLOW_LOOPBACK_TARGETS=true`. Private LAN ranges are allowed, since reaching them is the point.
5. While a terminal is open the server rechecks the web session every 30 s; logout, expiry or revocation closes it.
   Keystrokes count as activity for the idle lock and timeout. A locked session pauses the terminal (see Idle lock).

## Runtime settings

Admins can change email (SMTP), session timing (lock, idle sign-out, maximum length) and the per-user terminal limit on
the Settings page. Each group falls back to its environment variable until saved, and can be reset to it. Startup and
security boundary settings stay environment-only on purpose, so a stolen admin session cannot change them: the master
key, database, allowed origins, public URL (it is the base of emailed links), cookie and proxy flags, and the loopback
SSRF guard. Note that an admin can point SMTP at any host and port the server can reach.

## Web hardening

- **CSRF:** `SameSite=Strict` cookies, plus every state-changing API call must send `X-Any-SSH: 1` (a custom header a
  cross-site page cannot send without a CORS preflight we never approve) and any `Origin` sent must be allowed.
- **Headers (Helmet):** strict CSP (`script-src 'self'`, no inline scripts, `frame-ancestors 'none'`, `object-src 'none'`),
  HSTS when secure cookies are on, `nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP same-origin.
  `style-src` allows `'unsafe-inline'` because xterm.js injects its renderer styles.
- API responses are `Cache-Control: no-store`; the service worker never caches `/api/`.
- Input validation with zod on every route; request bodies capped at 256 KB and WebSocket frames at 256 KB.
- A global rate limit (600/min/IP) on top of the tighter auth limits.

## Audit log

Append-only table recording sign-ins (and failures with reason), MFA changes, password changes, admin actions, key
creation/deletion/export, server changes, share grants/changes/revocations, host-key trust/mismatch, and SSH session start/end
(with duration and byte count), and software updates (`system.update`: result, trigger, from/to version, recorded by the
host's `any-ssh update` through a CLI inside the container; versions and a short note only). Each entry stores the actor's ID **and** username so history survives account deletion.

- SQLite triggers reject `UPDATE`/`DELETE` on the table.
- Each row includes the SHA-256 of the previous row (hash chain). **Admin → Audit → Verify integrity** walks the chain
  and reports the first tampered entry, which catches edits made by someone who bypasses the triggers.
- Secrets are never written to the log. Terminal content is not recorded.

## Deployment checklist

The installer (`deploy/install.sh`) and the provided `compose.yaml` cover most of this; see [DEPLOY.md](DEPLOY.md).

- Run behind a TLS-terminating reverse proxy (Caddy, nginx, Traefik). Set `NODE_ENV=production`,
  `ANYSSH_COOKIE_SECURE=true`, `ANYSSH_TRUST_PROXY=true` and `ANYSSH_ORIGIN=https://your.host`. The proxy must pass
  WebSocket upgrades for `/api/terminal`.
- Bind the app to `127.0.0.1` (the default) so only the proxy can reach it.
- Generate the master key with `npm run gen-key`, store it in a secret manager or a root-only file, and back it up
  separately from the database.
- Turn on 2FA for every admin.
- Restrict outbound SSH from the Any-SSH host with a firewall if it should only reach certain networks.

## Known gaps and next steps

These are intentionally out of scope for this first pass:

- **Enforced MFA policy** (e.g. require 2FA for admins or everyone) and **WebAuthn / passkeys** (Face ID / Touch ID on
  iPhone and Mac would be a natural fit, including as a way to unlock a locked session).
- Settings are cached per process; with several instances (see DEPLOY.md) a change reaches the others on restart.
- **SSO** (OIDC / SAML) for organisations.
- **Groups / teams** for sharing with many people at once.
- Optional KMS/HSM-backed envelope encryption, so the master key never sits on the Any-SSH host at all.
- Per-user key encryption (unlocking keys with the user's own passphrase or passkey), which would protect keys even from
  someone holding the master key, at the cost of sharing without disclosure.
- **SSH certificates** (short-lived user certs signed by an Any-SSH CA) instead of long-lived keys.
- **Jump hosts / bastions**, SFTP file transfer, port forwarding, agent forwarding (deliberately off).
- **Session recording** for compliance (opt-in, per server).
- Audit log export / shipping to a SIEM.
- Native iOS/macOS wrappers if the PWA hits limits (e.g. background sessions, hardware keyboard shortcuts).
- External penetration test before exposing a deployment to the internet.

## Updates

The only outbound call added for update checks is an anonymous, read-only request to the image registry (ghcr.io) for the
image's labels, every ~6 hours; it can be disabled with `ANYSSH_UPDATE_CHECK=false`. The app never receives the Docker
socket and cannot update itself: installing is done by `any-ssh update` or an opt-in systemd timer on the host, which back
up first and roll back if the new image is unhealthy. Images are pulled by tag over TLS from the registry; they are not
signature-verified yet (a possible hardening: cosign signatures and pinning by digest).
