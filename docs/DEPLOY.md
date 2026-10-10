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

On the VM (Docker and the Compose plugin installed, DNS for your domain pointing at it, ports 80 and 443 open):

```bash
git clone https://github.com/Maffewem/Any-SSH.git && cd Any-SSH

# 1. Master key: a file only the container user (uid 1000) can read. Back it up somewhere safe and separate.
mkdir -p secrets
openssl rand -base64 32 > secrets/master_key
sudo chown 1000:1000 secrets/master_key && chmod 600 secrets/master_key

# 2. Settings
cp .env.example .env
#   ANYSSH_DOMAIN=ssh.example.com
#   ANYSSH_ORIGIN=https://ssh.example.com
#   ANYSSH_SMTP_* for invites and password resets
#   Leave ANYSSH_MASTER_KEY empty: compose passes the key as a file.

# 3. Start
docker compose up -d --build
docker compose logs app | grep -A2 "first-run"   # one-time setup token
```

Open `https://your-domain/`, paste the setup token, create the admin account, then turn on 2FA for it.

What the compose file sets up:

- **TLS:** Caddy gets and renews a Let's Encrypt certificate and proxies WebSockets. The app is not published on any
  host port, so the only way in is through Caddy.
- **Container hardening:** the app runs as an unprivileged user with a read-only root filesystem, no Linux capabilities and
  `no-new-privileges`. It can write only to the `/data` volume.
- **Secrets:** the master key is mounted as a Docker secret file, not an environment variable, and is never written to
  the data volume.

To upgrade: `git pull && docker compose up -d --build`. Open terminals drop when the container restarts, so deploy at a
quiet time. Users only need to reconnect.

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
  `docker compose exec app npm run rotate-keys` runs the rotation inside the container.

## Backups

Everything except the master key is in one SQLite database on the `any-ssh-data` volume.

```bash
# Consistent online backup (safe while running); written to /data/backups inside the volume
docker compose exec app npm run backup

# Copy it off the host
docker compose cp app:/data/backups ./backups
```

Run it from cron (for example nightly) and ship the files offsite (S3/B2 with versioning, or `restic`). Test a restore
now and then: stop the stack, put the backup in place as `/data/any-ssh.db` on the volume, start it again, and sign in.

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
