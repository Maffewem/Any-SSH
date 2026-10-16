# Any-SSH design and security notes

Any-SSH is a self-hosted, multi-user SSH client. People sign in from any browser (desktop, Mac, iPhone, Android) and get a
real terminal; the server holds the SSH keys and makes the SSH connections on their behalf. That makes the Any-SSH server
the most sensitive machine in the setup: whoever controls it can reach every saved server. This document says how it is
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
| Brute force | Layered. (1) Per-IP request rate limits on login, MFA, unlock (10/min) and reset/setup (5/min). (2) **Per-account lockout**: failed passwords, 2FA/recovery codes, screen-unlock passwords, trusted-IP challenge codes and wrong passwords re-entered for sensitive actions (change password/email, 2FA, key export, trusted IPs) are counted in a sliding window; at the threshold (default 5 in 15 min) the account is locked (default 15 min), the owner is emailed, and for a re-auth lockout every session of the account is ended. (3) **Per-IP lockout**: the same failures, plus unknown usernames, bad reset links and bad setup tokens, are counted per address across all accounts (default 30 in 15 min); a blocked address gets `429 ip_locked` from login, MFA, unlock, challenge, forgot-password, reset links and setup. Unknown-identifier reset requests count against the address only, never an account, so nobody can lock a victim out through password reset. Thresholds, window, lockout length and the owner email are admin-configurable on Settings → Brute-force protection (minimum threshold 3). Counters restart after each lockout. Admins unlock accounts (Users) and addresses (Settings). Each lockout is one `auth.lockout` audit entry (scope, count, kind, expiry); blocked requests are not logged individually, so an attack cannot flood the log. Trade-off: a determined attacker who knows a username can keep that account locked (a denial of service); the owner is told by email, and admins can unlock. Behind a proxy the address is the one set by `ANYSSH_TRUST_PROXY`, so that setting must be right or all users share one address. |
| MFA | TOTP (RFC 6238, works with any authenticator app). ±30 s drift, replay of a used code is rejected. Ten single-use recovery codes, stored as SHA-256 hashes. TOTP seed is encrypted at rest. |
| Sessions | 256-bit random token in an `HttpOnly`, `SameSite=Strict` cookie (`__Host-` prefixed and `Secure` in production). Only the token's SHA-256 is stored, so a database leak cannot be replayed as cookies. Locks after 15 min idle, signs out after 120 min idle, 12 h absolute expiry (all configurable). |
| Idle lock | Decided server-side from the last real activity (API calls, terminal keystrokes, and a throttled heartbeat when the browser sees keyboard or pointer use; the lock screen's own state check does not count). A locked session gets `401 session_locked` from every API call except `me`, `state`, `unlock` and `logout`, cannot get terminal tickets, and its open terminals are paused: keystrokes are dropped and the SSH channel stops reading, so output waits on the remote side instead of reaching an unattended screen. Unlocking needs the account password only (the session already passed 2FA); 5 wrong passwords end the session, a locked-out account cannot unlock, and the idle sign-out and absolute lifetime still apply while locked. Users can also lock on demand. |
| Session fixation | A new token is issued after the password step, after MFA, and after a password change. |
| Revocation | Users can see and sign out their devices. Password change signs out all other sessions (the current one is re-issued) and closes their terminals; password reset by emailed link or by an administrator signs out every session. Each records the number of sessions ended in the audit entry and the security notice email says devices were signed out. Disabling, demoting, resetting or deleting a user ends their sessions and closes their live terminals immediately. |
| First run | No default credentials. On an empty database the server prints a one-time setup token to its console; it is required to create the first administrator and is discarded afterwards. |
| Admin-created accounts | With an email address: an invite link (72 h, single use) lets them choose their own password; until then the account has an unusable random password. Without one: a random 20-character temporary password shown once to the admin, which must be changed at first sign-in. |
| Password reset | "Forgot password" takes a username or email and always gives the same answer, so it cannot be used to discover accounts. If the account has an email, it gets a single-use link valid for 30 minutes; a new link revokes the previous one, and repeat requests within 2 minutes are ignored (5 requests/min/IP). Completing a reset signs out every session and closes open terminals. **It does not bypass 2FA**: the next sign-in still asks for a code. Admins can email a reset link (or re-send an invite) from the user's page. |
| Link tokens | 256-bit random, stored only as SHA-256, carried in the URL fragment (`#/reset?token=…`) so they never reach server logs, proxies or `Referer` headers, and removed from the address bar once used. |
| Security notices | Users get an email when their password is changed or reset, 2FA is turned on or off, recovery codes are regenerated, or their email address changes (sent to the *old* address). |
| Trusted IP list | Optional, per user, off by default (Account → Trusted IP addresses). The user lists IPv4/IPv6 addresses or CIDR ranges (ranges wider than /8 IPv4 or /32 IPv6 are refused). Once on, every API request of a signed-in session and every terminal WebSocket connect is checked against the list, so a stolen cookie replayed from another network is caught, not only a fresh login. Policy **notify** ("Allow and notify me by email"): the session is allowed, the event is audited (`auth.untrusted_ip`) and the user is emailed once per new address. Policy **challenge** ("Require verification with a code"): the session is held (all routes return 403 `ip_challenge`, live terminals close) until the user enters a TOTP or recovery code, or an emailed 8-digit code (single use, 10 min, 5 tries, then the session ends and failures count towards the account lockout). A fresh TOTP code entered at login counts as the proof. The address is Fastify's `req.ip`: the socket address, or with `ANYSSH_TRUST_PROXY=true` the `X-Forwarded-For` that Caddy sets (Caddy overwrites a client-supplied value; the app is only reachable through it, see the deployment checklist). Turning it on needs the current address on the list, challenge needs an email or 2FA, adding entries and changing the setting need the password, and the entry covering the current address cannot be removed while enforced. An admin can switch it off for a locked-out user (`admin.user_reset_trusted_ips`). It is a tripwire and a second factor for new networks, not a replacement for 2FA: dynamic or shared (CGNAT, mobile) addresses make a narrow list noisy. |
| Email address changes | Need the current password, and cancel any pending reset links, so a hijacked session cannot quietly redirect resets to an attacker's mailbox. |

## Authorisation model

- **Roles:** `admin` and `user`. Admins manage accounts and read the audit log. There is always at least one active admin,
  and admins cannot demote, disable or delete themselves.
- **Admins do not get implicit access to other people's servers or keys.** Administration and data access are separate,
  so a compromised admin session cannot silently open a shell on every server.
- **Servers** belong to an owner. The owner can share a server with any number of users:
  - `use`: can connect. Cannot see or change host, username or credentials.
  - `manage`: can also rename it, edit notes and trust a server's host key on first use (but not replace a pinned one).
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
together yield everything. Backups are therefore protected twice by default: encrypted to a recovery key (see Backups),
and the secrets inside stay sealed under the master key.

## Backups

Admins can have Any-SSH write backups to S3-compatible storage, SFTP or the data volume on a schedule (Settings → Backups;
see docs/DEPLOY.md for use). The admin chooses one of three encryption modes:

| Mode | Who can read a backup | Trade-off |
| --- | --- | --- |
| **Recovery key** (default) | Only the holder of the recovery secret key (plus the master key to use the secrets inside). | Strongest: a compromised server, a stolen bucket, or both together, cannot read old backups. The secret key must be kept safe; lose it and the backups are unreadable. |
| **System-managed** | Anyone with the master key. The backup key pair is derived from the master key (HKDF-SHA256, never stored), so restore needs nothing else. | The storage provider still sees only ciphertext, but a stolen server (or master key) together with a backup can decrypt it. No extra key to lose. After a master key rotation, older system-managed backups need the old key (kept in `ANYSSH_PREVIOUS_MASTER_KEYS` during rotation, and tried automatically on restore). |
| **None** | Anyone who can read the file. | The plain SQLite file: usernames, emails, password hashes (Argon2id), TOTP and session tables, server addresses, host keys and the audit log are readable. SSH keys, server passwords and setting secrets stay sealed under the master key. Choosing it needs an explicit confirmation (`acceptUnencrypted`) and the password, and the UI asks again when the destination is S3 or SFTP. The run history marks each unencrypted backup. |

| Control | Implementation |
| --- | --- |
| Encryption | Recovery-key and system-managed modes share one format: public-key, in the style of age. Each file uses a fresh ephemeral X25519 key; the shared secret goes through HKDF-SHA256 to an AES-256-GCM key. Data is in 1 MiB frames with counter nonces, a "last frame" flag in the nonce and the header as associated data, so frames cannot be reordered, dropped, truncated or moved between files. |
| Who can decrypt | See the modes above. In recovery-key mode the server stores just the public key; the secret key is generated on request (or offline with `any-ssh backup-key`), shown once and never stored or logged. Every backup's header carries its key ID, and the run history records the mode used. |
| Never plaintext off the server (encrypted modes) | The SQLite snapshot is encrypted before it leaves the data volume; the S3/SFTP code only ever sees ciphertext, and the snapshot and temporary files are removed afterwards. Recovery-key mode cannot be saved with a destination but no key. |
| Integrity | Before encryption the snapshot must pass SQLite's integrity check, schema check, the audit log hash chain and a master key check (every stored secret opens). After upload the stored size must match, S3 uploads carry `Content-MD5`, SFTP uploads are written as `.partial` and renamed, and the SHA-256 of each backup is kept in the run history. Restore authenticates every frame of an encrypted backup and refuses wrong keys, tampering, truncation and trailing data before touching anything (an unencrypted backup has only the database checks). |
| Credentials | S3 secret keys and SFTP passwords/private keys are sealed under `setting:backup` with the master key, re-sealed by key rotation, and never returned by the API. They are dropped when the endpoint/bucket/key ID (S3) or host/port/username (SFTP) changes without new ones being entered. |
| Changing the target | Changing the encryption mode, key, destination or schedule needs the admin's password again (rate-limited), is audited by field name only, and sends the admin a security notice, so a hijacked admin session cannot quietly redirect copies of the database. |
| Host trust | SFTP requires the server's host key fingerprint to be entered before any connection; a mismatch is refused and the connection test reports what was presented. S3 uses HTTPS (HTTP is allowed for a LAN MinIO since content is encrypted and requests are signed). Destinations are resolved through the same SSRF guard as SSH targets (loopback, link-local and metadata addresses refused unless `ANYSSH_ALLOW_LOOPBACK_TARGETS`). As with SMTP, an admin can still point backups at any other host the server can reach. |
| Scheduling | An in-process scheduler (hourly, daily or weekly in UTC, checked each minute). Missed slots run when the server is back; failures retry every 30 minutes up to three times. Runs left unfinished by a crash are closed as failed on start. |
| Retention | After a successful upload, only the newest N `any-ssh-*.anybak` / `any-ssh-*.db` files are kept at the destination; other files in the folder are never touched. Retention failures are reported as a warning, not a failure of the backup. Use bucket versioning/object lock if you want protection against deletion by a compromised server. |
| Failure notice | The Settings page shows the last result, next run, history and a stale warning (no success for two periods). Admins with email get a failure email, at most once a day. Every run is audited (`backup.run`), as are tests and key generation. |
| Restore | `any-ssh restore` / `any-ssh verify-backup` on the host. The tool works out the mode from the file: it tries the recovery secret key if one is given, then the system key of the current and previous master keys, and takes an unencrypted file as is; the same verification runs in every case. Never in the web UI: restore replaces the accounts that would authorise it, and the secret key must not be typed into a possibly compromised server. |

Limits: encryption streams in 1 MiB frames, but an S3 upload reads the finished backup into memory and sends it as a single PUT (up to 5 GB). Backups are only as fresh
as the schedule; for a seconds-level recovery point use Litestream. The audit log is part of the database, so restoring
rolls it back to the backup time.

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
   server, with its key type, when it was trusted and by whom.
   - *First connection:* the owner (or a manager) is shown the fingerprint and key type and must explicitly trust it
     (the dialog says how to check it on the server). People with `use` access cannot trust on first use and are refused
     until the owner has.
   - *A changed key is always refused.* The user sees a blocking dialog with the pinned and presented fingerprints side by
     side, the owner is emailed (once per distinct new key, not per retry), and the attempt is audited as
     `ssh.host_key_mismatch` with both fingerprints. The new key is parked on the server record as a pending change.
   - *Accepting it is owner-only* (not managers, not admins), needs the owner's **account password**, and must name the exact
     fingerprint that was shown, so a key that appears later cannot ride on an earlier review. Audited as
     `server.host_key_accept` and the owner is emailed again. The owner can instead dismiss the change (`server.host_key_dismiss`),
     or forget the pin to verify afresh (`server.host_key_forget`, owner-only).
   - Changing a server's host or port clears the pin and any pending change.
   - Admins get a read-only **Host keys** page listing every pinned fingerprint, who trusted it, any pending change, and
     servers pinned to different keys for the same host and port. It exposes no credentials and grants no access.
   The ticket also carries which credentials the connection uses (saved, one of the user's own keys, a one-off key, or a
   password prompt) and the SSH login name.
4. **SSRF guard.** The hostname is resolved once and the vetted IP is what we dial (no DNS rebinding window). Loopback,
   link-local (including cloud metadata `169.254.169.254`), unspecified and multicast addresses are refused unless
   `ANYSSH_ALLOW_LOOPBACK_TARGETS=true`. Private LAN ranges are allowed, since reaching them is the point.
5. While a terminal is open the server rechecks the web session every 30 s; logout, expiry or revocation closes it.
   Keystrokes count as activity for the idle lock and timeout. A locked session pauses the terminal (see Idle lock).

## Jump hosts (bastions)

A server can be reached through a jump host instead of directly from the Any-SSH server, so a single machine does not have to be
exposed or trusted with the route to everything.

- **Admin-only.** Only admins create, change, disable, delete or verify jump hosts (`/api/admin/jump-hosts`, all audited as
  `jump_host.*`). A server's owner may turn jumping off or choose "closest"; naming one **specific** jump host is an admin
  decision (`fixed` mode needs an admin account), and a non-admin owner cannot move a server off a jump host an admin fixed it to.
- **The jump host never sees the user's credentials.** Any-SSH logs in to the jump host with the jump host's own key and asks it for a
  TCP channel to the target (`direct-tcpip`). The user's SSH session to the target (key exchange, authentication, terminal) then runs
  inside that channel, end to end, so the jump host relays ciphertext. The jump host's key is generated by Any-SSH (Ed25519), sealed
  like any other key under `jump_host:<id>:private` (re-sealed by key rotation), and never returned by the API; the admin gets only
  the public half to add to `authorized_keys` (recommended with `restrict,port-forwarding`). Agent and X11 forwarding are not used.
- **Host keys are verified at every hop.** The target's pinned fingerprint is checked exactly as for a direct connection (a changed key is
  refused, audited as `ssh.host_key_mismatch`). The jump host's host key must be pinned by an admin before it can be used: the admin sees
  the fingerprint from a test connection and confirms it, the server probes again and pins only if the key presented is still that
  one. A changed jump host key is refused and audited (`ssh.jump_host_key_mismatch`); changing its address clears the pin.
- **"Closest"** (`auto`) means the enabled, host-key-verified jump hosts ordered by lowest TCP connect time from the Any-SSH server
  (measured at connect time, cached for 60 s); unreachable ones are skipped and a failing one falls over to the next. It is a
  proximity-to-Any-SSH measure, not a measure of the path onward to the target. `fixed` never falls back: if its jump host is disabled,
  deleted or unverified, the connection fails closed instead of going direct or through another jump host.
- Disabling, deleting, re-pointing or forgetting the host key of a jump host closes the live terminals using it, and changing a server's
  route closes that server's open terminals. The session audit entry records which jump host (and mode) was used.
- The target name is resolved by the jump host, so it may be reachable only from there. Literal addresses still get the SSRF guard;
  names are not resolved by Any-SSH in this mode, so the guard cannot vet them (the jump host is admin-chosen and trusted for routing).
- Any number of jump hosts can be defined (for example one per site); "closest" chooses between them and fails over. One hop per
  connection for now; chains of several jump hosts are not supported yet.
- `deploy/jump-host-setup.sh` prepares a jump host: it creates a dedicated key-only account with no shell, agent, X11 or tunnel
  forwarding (optionally limited to listed destinations with `--allow host:port`), validates `sshd` before reloading it, and prints the
  host key fingerprints to verify. It is meant to be downloaded, read, then run as root; Settings → Access shows the exact command.

## Detached sessions and split panes

- **Split panes** are a browser feature: each pane is its own terminal (its own SSH session and ticket) to the same server with the
  same credentials, so every pane is checked, limited (per-user terminal limit), audited and locked individually.
- **Sessions survive a dropped browser connection.** When a terminal's WebSocket drops after the shell is up, the server keeps the SSH
  session for `detachMinutes` (Settings → Limits, default 5, `ANYSSH_DETACH_MINUTES`; 0 closes at once) and buffers the last 512 KB of
  output. The browser re-attaches with a fresh single-use ticket for that session id; the server replays the buffer. The session id is
  a 256-bit random value held only in browser memory, and a resume is accepted only for the **same user**, for a terminal that is
  currently detached, on a server that user still has access to, from a session that is not locked. Re-attaching from another
  device takes the terminal over and closes the earlier connection (audited as `ssh.session_resume`; drops as `ssh.session_detach`).
- **The web session still governs a detached terminal.** Logout, expiry, revocation, removed access, a disabled user, or an expired
  detach window end it; the idle lock pauses it (output is held on the remote side) and a locked session cannot re-attach until it is
  unlocked. A server restart loses detached sessions (they live in memory), and so does reloading the page (the id is not persisted).
- A detached session holds an open SSH connection with no one watching, and its buffered output sits in server memory until the
  window closes; shorten the window (or set it to 0) if that is unwanted.

## Runtime settings

Admins can change email (SMTP), session timing (lock, idle sign-out, maximum length), the open-terminal limits (set separately for standard users and administrators), how long a
dropped terminal is kept, the jump hosts, brute-force thresholds, backups, updates and the maintenance window on the Settings page, which is organised into
Security, Access, Limits, Backups, Updates and Notifications tabs. Each group falls back to its environment variable until saved, and can be reset to it. Startup and
security boundary settings stay environment-only on purpose, so a stolen admin session cannot change them: the master
key, database, allowed origins, public URL (it is the base of emailed links), cookie and proxy flags, and the loopback
SSRF guard. Note that an admin can point SMTP at any host and port the server can reach.

## Signing out everywhere and deleting accounts

- **Sign out of all devices** (Account page, or an admin on a user's dialog) destroys every session of the account, including the current
  one, and closes its live terminals. Audited as `auth.sign_out_everywhere` / `admin.user_sign_out`; the user is emailed when an admin does it.
- **Delete account** needs the account password (and a 2FA code when 2FA is on; failures count towards brute-force protection). It removes
  the account's keys, servers, shares and sessions, and is audited as `user.account_delete` with the names of what was removed.
- **Shared servers.** If other people use servers the account owns, deletion is refused until the person either types "delete" to
  confirm those servers are removed for everyone, or transfers them to another active user. A transfer moves ownership of the shared
  servers and the saved keys they use (so credentials keep working); servers that are not shared are still deleted. The new owner is emailed.
  Administrators can do the same for another user (`/api/admin/users/:id/transfer-servers`, then delete), audited as `admin.servers_transfer`.
- The last active administrator cannot be deleted.

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
creation/deletion/export, server changes, share grants/changes/revocations, host-key trust/mismatch, and SSH session start/end/detach/resume
(with duration and byte count), jump host changes, host key pins and failed hops, and software updates (`system.update`: result, trigger, from/to version, recorded by the
host's `any-ssh update` through a CLI inside the container; versions and a short note only). Each entry stores the actor's ID **and** username so history survives account deletion.

- SQLite triggers reject `UPDATE`/`DELETE` on the table.
- Each row includes the SHA-256 of the previous row (hash chain). **Admin → Audit → Verify integrity** walks the chain
  and reports the first tampered entry, which catches edits made by someone who bypasses the triggers.
- Secrets are never written to the log. Terminal content is not recorded.
- **Failed attempts are recorded** for every credential check: sign-in (`auth.login`, with reason `bad_password`, `unknown_user`, `locked`, `disabled`), 2FA (`auth.mfa`), screen unlock (`auth.unlock`), trusted-IP challenge (`auth.ip_challenge`), reset requests (`auth.password_reset_request`), password/email/2FA/recovery-code/key-export confirmations, plus `auth.lockout` and `admin.ip_unlock`.
- **Setting changes are recorded with old → new values** in `details.changes` (`{field: {from, to}}`): admin Settings (`admin.settings_change`, `admin.settings_reset`; for email only whether the password changed, never its value), admin edits to a user (`admin.user_update`), a user's trusted-IP on/off and policy (`user.trusted_ip_settings`), email changes (`user.email_change`) and display-name changes (`user.profile_update`). Trusted-IP entries added or removed are recorded with the entry.

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
- Chained (multi-hop) jump hosts, a require-a-jump-host policy, SFTP file transfer, port forwarding, agent forwarding (deliberately off).
- **Session recording** for compliance (opt-in, per server).
- Audit log export / shipping to a SIEM.
- Native iOS/macOS wrappers if the PWA hits limits (e.g. background sessions, hardware keyboard shortcuts).
- External penetration test before exposing a deployment to the internet.

## Tags and the status page

Tags are plain labels on a saved server (up to 10, 32 characters each, letters, numbers, spaces and `. _ : / -`). They are
metadata, not access control: everyone a server is shared with sees them, and the owner and managers can change them.
Search runs in the browser over the servers the user can already see.

The admin **Status** page (`/api/admin/health`) lists every saved server's name, host, owner and host key state, which
admins can already see on the Host keys page, and no credentials. "Check now" opens a plain TCP connection to each distinct
host and port from the server, using the same address checks as terminals (no loopback, link-local or metadata addresses),
and sends no data. Servers that go through a jump host are not tested directly. The certificate check connects to the
configured public address from the server itself, so behind NAT without hairpinning it may report that it cannot connect.

## Updates

The only outbound call added for update checks is an anonymous, read-only request to the image registry (ghcr.io) for the
image's labels, every ~6 hours; it can be disabled with `ANYSSH_UPDATE_CHECK=false`. The app never receives the Docker
socket and cannot update itself: installing is done by `any-ssh update` or the opt-in update agent (a systemd timer on the host), which back
up first and roll back if the new image is unhealthy. **Update now** only writes a request row to the database (admin only,
rate-limited, audited as `admin.update_requested` / `admin.update_cancelled`); the agent, which already runs as root on the host,
decides when to act on it. A compromised admin session can therefore trigger an update of the image the operator already follows,
but cannot choose an image, run commands or reach Docker. The maintenance window is an admin setting (audited with old and new
values) and limits only automatic updates. Images are pulled by tag over TLS from the registry; they are not
signature-verified yet (a possible hardening: cosign signatures and pinning by digest).
