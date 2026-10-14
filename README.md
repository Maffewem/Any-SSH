# Any-SSH

A self-hosted, multi-user SSH client you can use from any browser: desktop, Mac, iPhone, iPad or Android.
Install it as an app from Safari ("Add to Home Screen") or Chrome.

- **Accounts:** sign-in with Argon2id-hashed passwords, optional TOTP two-factor with recovery codes, device list and
  remote sign-out.
- **Administration:** admins invite users by email (or hand out a temporary password), set roles, disable, unlock,
  send reset links, reset 2FA, delete, and read a tamper-evident audit log.
- **Email:** invites, "forgot password" reset links and security notices over SMTP (logged to the console in
  development).
- **Saved servers** with key, stored-password or ask-each-time authentication, and pinned host keys.
- **SSH keys:** generate (Ed25519, ECDSA, RSA 4096) or import. Private keys are encrypted at rest, and only their owner
  can export one, after confirming their password.
- **Sharing:** share a server with any number of people as *use* or *manage*, and choose whether they connect with the
  server's saved credentials (without ever seeing them) or must supply their own. Managers can only share the server
  onwards if the owner allows it. Revoking access closes their open terminals.
- **One-off keys:** paste a private key when connecting and it is used for that session only, never saved.
- **Terminal:** xterm.js over a WebSocket, multiple tabs, and an extra-keys bar (Esc, Tab, Ctrl, Alt, arrows) on touch
  devices.

**Deep links:** `https://<your-host>/#/connect?host=<host>&port=<port>&user=<user>` (port and user optional) signs you in as
usual, then opens a terminal to your saved server with that address, or the add-server form pre-filled if there is none.
Other tools (for example a dashboard) can link to it; Any-SSH works the same without them.

Security design, threat model and known gaps: [docs/SECURITY.md](docs/SECURITY.md). Deployment and scaling:
[docs/DEPLOY.md](docs/DEPLOY.md).

## Quick start (development)

Requires Node 22+.

```bash
npm run install:all
cd server
export ANYSSH_MASTER_KEY=$(npm run -s gen-key)
export ANYSSH_ORIGIN=http://localhost:5173   # the Vite dev server
npm run dev                                   # API on :8080, prints a one-time setup token
```

In another terminal:

```bash
cd web && npm run dev                         # UI on http://localhost:5173
```

Open the UI, paste the setup token from the server log, and create the first administrator.

To try it against an SSH server on the same machine, also set `ANYSSH_ALLOW_LOOPBACK_TARGETS=true` (off by default; see
the SSRF notes in the security doc).

## Production

On a fresh Linux server with a domain pointing at it (ports 80 and 443 open):

```bash
curl -fsSL https://raw.githubusercontent.com/Maffewem/Any-SSH/main/deploy/install.sh | sudo bash
```

It installs Docker if needed, asks for your domain and email, generates the master key and settings, schedules nightly
backups and starts Any-SSH with automatic HTTPS. Update later with `sudo any-ssh update`. Details, hosting choices and
how to scale out are in [docs/DEPLOY.md](docs/DEPLOY.md).

Without Docker:

```bash
npm run install:all
npm run build                     # builds web/dist and server/dist
cp .env.example .env              # fill in ANYSSH_MASTER_KEY and ANYSSH_ORIGIN
set -a; . ./.env; set +a
npm start                         # serves the UI and API on ANYSSH_HOST:ANYSSH_PORT
```

Set the `ANYSSH_SMTP_*` variables in `.env` to send invites and password resets by email.

To rotate the master key later: `npm --prefix server run gen-key`, restart with the new key in `ANYSSH_MASTER_KEY` and the
old one in `ANYSSH_PREVIOUS_MASTER_KEYS`, run `npm --prefix server run rotate-keys`, then remove the old key.

Put it behind a TLS reverse proxy that forwards WebSocket upgrades. Example Caddyfile:

```
ssh.example.com {
  reverse_proxy 127.0.0.1:8080
}
```

The PWA (install to home screen, offline shell) needs HTTPS.

## Tests

```bash
npm test          # server unit + API + end-to-end terminal tests (spins up a real SSH server in-process)
npm run typecheck
```

## Layout

```
server/   Fastify API, SSH proxy, SQLite schema (src/db.ts), tests
web/      React + Vite PWA, xterm.js terminal
docs/     Security and design notes
```
