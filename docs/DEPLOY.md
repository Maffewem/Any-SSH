# Deploying Any-SSH

## Recommendation

Start with **one small Linux VM running Docker Compose**: the Any-SSH container behind Caddy, which handles HTTPS
automatically. That fits how the app is built today, and it is enough for a team of hundreds of users. Grow by giving the
VM more CPU and RAM, and change the architecture only when you actually need more than one instance (see
[Scaling](#scaling)).

Where to run it:

- **Any VM provider** (Hetzner, DigitalOcean, Linode, AWS Lightsail/EC2, Azure, GCP): 2 vCPU / 2 GB RAM is plenty to start.
  Choose a region close to the servers you SSH into, because every keystroke goes browser → Any-SSH → server.
- **Inside your own network** if most targets are private: Any-SSH then reaches them directly, and you expose only
  port 443 (or only on a VPN).
- **Avoid serverless / scale-to-zero platforms** (Cloud Run, Lambda, Vercel, Heroku-style dynos). Terminals are long-lived
  WebSockets, and the database is a local file that needs a persistent disk.

## First deployment

Point a domain (e.g. `ssh.example.com`) at the server, open ports 80 and 443, then run this on it:

```bash
curl -fsSL https://raw.githubusercontent.com/Maffewem/Any-SSH/main/deploy/install.sh | sudo bash
```

It asks for the domain, your email (for certificate notices) and, optionally, SMTP settings for invite and reset emails.
Then it:

1. installs Docker if it isn't there,
2. puts everything in `/opt/any-ssh`: `compose.yaml`, the Caddy config, `.env` with your settings, and a newly generated
   master key in `secrets/master_key` (readable only by the app),
3. schedules a nightly backup (systemd timer),
4. downloads the prebuilt image and starts Any-SSH behind Caddy,
5. prints the one-time setup token for creating your admin account.

Open `https://your-domain/`, paste the token, create the admin account, then turn on 2FA for it. Copy the master key
(`sudo cat /opt/any-ssh/secrets/master_key`) into your password manager.

To read the script before running it, download it first: `curl -fsSLO …/deploy/install.sh && less install.sh`. It also
runs unattended: `sudo ANYSSH_DOMAIN=ssh.example.com ANYSSH_EMAIL=you@example.com bash install.sh`. Running it again keeps
the existing key and settings.

### Day-to-day

The installer adds an `any-ssh` command:

| Command | What it does |
| --- | --- |
| `sudo any-ssh update` | Backs up, downloads the latest version and restarts. Open terminals drop and users reconnect, so pick a quiet time. |
| `sudo any-ssh backup` | Saves a copy of the database to `/opt/any-ssh/backups` (the newest 14 are kept). |
| `sudo any-ssh config` | Edits the settings, e.g. to add SMTP later, and applies them. |
| `any-ssh status`, `any-ssh logs`, `any-ssh version` | Health, logs and the running version. |

`update` replaces `compose.yaml`; put your own Compose changes in `/opt/any-ssh/compose.override.yaml`. To stay on a
release instead of the newest build, set `ANYSSH_VERSION` in `.env` to a version tag such as `1.2` (see below).

### Images

Every push to `main` that passes CI publishes `ghcr.io/maffewem/any-ssh:latest` (and `:sha-<commit>`) for Intel/AMD and
ARM servers. Tagging a release `v1.2.3` also publishes `:1.2.3` and `:1.2`. The server never builds anything.

To build from source instead, clone the repository and run
`docker compose -f compose.yaml -f compose.build.yaml up -d --build`.

### What the setup gives you

- **TLS:** Caddy gets and renews a Let's Encrypt certificate and proxies WebSockets. The app is not published on any
  host port, so the only way in is through Caddy.
- **Container hardening:** the app runs as an unprivileged user with a read-only root filesystem, no Linux capabilities and
  `no-new-privileges`. It can write only to the `/data` volume.
- **Secrets:** the master key is mounted as a Docker secret file, not an environment variable, and is never written to
  the data volume. `.env` (which holds the SMTP password, if any) is readable only by root.

### Without the installer

The same setup by hand, from a clone of the repository:

```bash
mkdir -p secrets
openssl rand -base64 32 > secrets/master_key
sudo chown 1000:1000 secrets/master_key && chmod 600 secrets/master_key
cp .env.example .env     # set ANYSSH_DOMAIN, ANYSSH_ORIGIN and SMTP; leave ANYSSH_MASTER_KEY empty
docker compose up -d
docker compose logs app | grep -A2 "first-run"   # one-time setup token
```

Update with `docker compose pull && docker compose up -d`.

## Where the master key lives

The master key decrypts every stored SSH key and password. Treat it like a root credential.

| Setup | Where the key lives |
| --- | --- |
| Single VM (default) | `secrets/master_key` on the host, `chmod 600`, owned by uid 1000. Keep a copy in a password manager or offline. |
| Cloud | A secret manager (AWS Secrets Manager / SSM, GCP Secret Manager, Azure Key Vault, 1Password, Vault) written to that file at boot. |
| Kubernetes | A `Secret` mounted as a file, with `ANYSSH_MASTER_KEY_FILE` pointing at it. |

Rules:

- **Never store the key next to the database backups.** A backup is useless without the key, which is the point.
- **Lose the key and the stored SSH keys, passwords and 2FA seeds are gone.** Users would have to re-import keys and
  re-enrol 2FA, so keep two separate copies.
- **Rotate the key** if it may have been exposed, or on a schedule. See the README for the steps;
  `docker compose exec app npm run rotate-keys` (from `/opt/any-ssh`) runs the rotation inside the container.

## Backups

Everything except the master key is in one SQLite database on the `any-ssh-data` volume. The installer backs it up
nightly to `/opt/any-ssh/backups`; `sudo any-ssh backup` does it on demand. Backups are consistent even while people
are using Any-SSH.

Ship those files offsite too (S3/B2 with versioning, or `restic`), and never alongside the master key. Test a restore now
and then: stop the stack (`any-ssh stop`), copy the backup into the volume as `/data/any-ssh.db`, start it again, and sign
in.

Without the installer: `docker compose exec app npm run backup` writes to `/data/backups` inside the volume, and
`docker compose cp app:/data/backups ./backups` copies them out.

For continuous backup with point-in-time restore, add [Litestream](https://litestream.io) as a sidecar that streams the
SQLite WAL to object storage. That is the cheapest way to keep data loss to seconds without moving off SQLite.

The audit log is in the same database, and **Admin → Audit → Verify integrity** checks it after a restore.

## Scaling

### What one instance handles

The work per user is small: API calls are lightweight, and each open terminal is one WebSocket plus one SSH connection,
which costs a little CPU for encryption. The heaviest operation is sign-in, because Argon2id uses 64 MB of RAM per
password check by design. A 2 vCPU / 4 GB VM handles hundreds of concurrent terminals. Scale vertically first. It costs
nothing in complexity.

### What ties it to one instance today

These are deliberate simplifications. Each has a known replacement:

| Today | Why it limits scaling | Path past it |
| --- | --- | --- |
| **SQLite** (one file, synchronous `better-sqlite3`) | Only one process can own the database. | **PostgreSQL** (managed: RDS, Cloud SQL, Neon). The SQL is plain and portable. The data layer needs to move to an async driver (e.g. `pg` with Kysely). |
| **Terminal tickets** kept in memory | The `connect` request and the WebSocket must reach the same instance. | Store tickets in **Redis** with a 30 s TTL (`GETDEL` to redeem once), or use sticky sessions at the load balancer. |
| **Live terminal registry** kept in memory (used to close terminals the moment access is revoked) | Revoking access only closes terminals on the instance that handled the request. | **Redis pub/sub**: publish "close terminals for user/server/session", and every instance closes its own. The 30 s session re-check is the fallback until then. |
| **Rate-limit counters** kept in memory | Each instance counts separately, so the real limit is N times higher. | `@fastify/rate-limit` supports a **Redis store** directly. |
| **Audit hash chain** (each row hashes the previous one) | Two instances writing at once could fork the chain. | In Postgres, serialise audit inserts with a transaction-level advisory lock (or a single audit writer). |
| **SSH sessions live in the process** | A restart or deploy drops open terminals. | Drain before deploys: stop routing new terminals to an instance and let existing ones finish. Long term, run the SSH proxy as its own small "gateway" service so web deploys never touch terminals. |

Web sessions are already stored in the database, so they work across instances as soon as the database is shared.

### Multi-instance layout (when you need it)

```
            ┌──────────── Load balancer (TLS, WebSockets, health checks) ─────────────┐
            │                                                                          │
     Any-SSH instance 1        Any-SSH instance 2        …         (stateless; master key from a secret manager)
            │                         │
            ├────────── PostgreSQL (managed, backups and PITR) ─────────┤
            └────────── Redis (tickets, rate limits, revocation pub/sub) ┘
```

Container platforms that fit this well: ECS/Fargate, Azure Container Apps, Fly.io, Kubernetes. Each needs WebSocket
support and long connection timeouts (at least 1 hour) on the load balancer.

Suggested order when the time comes: Postgres first, since it also gives managed backups even on one instance. Then
Redis for tickets, rate limits and revocation. Then a second instance behind the load balancer.
