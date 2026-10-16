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
| `any-ssh update-log` | Shows the update history: every manual or automatic update, with result (updated, failed, rolled back), versions and who started it. Also kept in the app (Settings → Updates, and the audit log) and in `/opt/any-ssh/update.log`. |
| `sudo any-ssh auto-update on` | Installs updates by itself, inside the maintenance window set in Settings (once a day at any time if none is set), only if a newer image was published. Users are warned first. `off` / `status` also work. Off by default. Re-run it once after upgrading from an older version so the new update agent timer replaces the old daily one. |
| `sudo any-ssh web-update on` | Lets admins press **Update now** in Settings. Starts the update agent (see below). `off` / `status` also work. Off by default. |
| `sudo any-ssh backup` | Saves a copy of the database to `/opt/any-ssh/backups` (the newest 14 are kept). Encrypted once a recovery key is set (see Backups). `--push` also stores one at the off-server destination. |
| `any-ssh backup-key` | Makes a recovery key pair for backup encryption. |
| `any-ssh verify-backup <file> <secret-key-file>` | Decrypts a backup and checks it is complete and matches this server's master key. Changes nothing. |
| `sudo any-ssh restore <file> <secret-key-file>` | Verifies a backup, then replaces the database with it (the old one is kept beside it). |
| `sudo any-ssh config` | Edits the settings, e.g. to add SMTP later, and applies them. |
| `sudo any-ssh doctor` | Checks the domain's public DNS, this server's public IP and the HTTPS certificate, and says what to fix. |
| `any-ssh status`, `any-ssh logs`, `any-ssh version` | Health, logs and the running version. |

`update` replaces `compose.yaml`; put your own Compose changes in `/opt/any-ssh/compose.override.yaml`. To stay on a
release instead of the newest build, set `ANYSSH_VERSION` in `.env` to a version tag such as `1.2` (see below).

### If the site shows an SSL or certificate error

Browsers show `ERR_SSL_PROTOCOL_ERROR` (or similar) when Caddy hasn't been able to get a certificate yet. Run
`sudo any-ssh doctor`. The installer runs the same checks. Common causes:

- **No public DNS record.** The domain must resolve *on the internet* to the server's public IP. A name that only
  resolves on your own network (router DNS, `/etc/hosts`) isn't enough, because Let's Encrypt checks from outside.
- **A server at home or behind a router.** Point the A record at your router's public IP and forward TCP ports 80 and
  443 to the server. If your broadband IP changes, use your router's or DNS provider's dynamic DNS.
- **Cloudflare's proxy (orange cloud)** in front of the domain. Set the record to "DNS only".
- **Opening the IP address** instead of the domain. The certificate is only for the domain.

After fixing it, `sudo any-ssh restart` makes Caddy try again straight away.

If you can't or don't want to open ports, put Any-SSH behind a Cloudflare Tunnel instead.

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

- **Never store the key next to the database backups, and never next to the backup recovery key.** A backup is useless without the master key, and unreadable without the recovery key; keep them in different places.
- **Lose the key and the stored SSH keys, passwords and 2FA seeds are gone.** Users would have to re-import keys and
  re-enrol 2FA, so keep two separate copies.
- **Rotate the key** if it may have been exposed, or on a schedule. See the README for the steps;
  `docker compose exec app npm run rotate-keys` (from `/opt/any-ssh`) runs the rotation inside the container.

## Backups

Everything except the master key is in one SQLite database on the `any-ssh-data` volume. The installer backs it up
nightly to `/opt/any-ssh/backups` and before every update; `sudo any-ssh backup` does it on demand. Backups are consistent
even while people are using Any-SSH. A copy on the same disk is not a backup for disk failure, theft or a compromised
server, so set up encrypted off-server backups (below).

### Encrypted off-server backups

In the app: **Settings → Backups** (admins only).

1. **Make a recovery key.** Press *Generate a key pair*, or run `any-ssh backup-key` on a trusted machine so the secret half
   never touches this server. Save the **secret key** in a password manager, **apart from the master key** (you need both to
   restore, and anyone holding both can read everything). The server keeps only the public key, so a stolen server or
   stolen bucket cannot decrypt backups.
2. **Choose a destination.**
   - *S3-compatible storage*: AWS S3, Backblaze B2, Cloudflare R2, Wasabi, MinIO. Give the endpoint (empty for AWS), region,
     bucket, folder and an access key. Use a key that can only write to that bucket; turn on bucket versioning or object lock
     if you want protection from deletion too.
   - *SFTP*: host, port, username, folder, a password or private key, and the server's **host key fingerprint**
     (`ssh-keyscan host | ssh-keygen -lf -`). No connection is made until it is entered; *Test destination* shows what the
     server presents.
   - *This server only*: keeps encrypted copies in the data volume. Better than nothing, not a disaster backup.
3. **Schedule and retention.** Hourly, daily (at a UTC hour) or weekly, and how many backups to keep. After each successful
   backup, older ones beyond that number are deleted from the destination. A slot missed while the server was off runs when it
   is back, and a failure is retried a few times at 30 minute intervals.
4. Press **Test destination**, then **Back up now**.

Changing the key or destination asks for your password again, and saved credentials are dropped if you point at a different
bucket or server without entering new ones.

Each backup is a file `any-ssh-<UTC time>.anybak`. Before it is encrypted, the snapshot is checked (SQLite integrity, schema,
the audit log's hash chain, and that the master key opens every stored secret), so a damaged database is reported rather
than quietly backed up. After upload the destination's reported size must match.

**Failures are not silent.** The Settings page shows the last result, the next run, the full history and a warning when no
backup has succeeded for two schedule periods. Every admin with an email address gets an email when a backup fails (at most
one a day while it keeps failing), and each run is in the audit log (`backup.run`).

For a scripted or one-off push: `sudo any-ssh backup --push`, or `docker compose exec app node dist/cli/backup.js run`.

### Restoring

You need three things: the `.anybak` file, the **recovery secret key**, and the **master key** this server was using when the
backup was made (the database holds your SSH keys and passwords sealed under it).

```bash
# 1. Check a backup without changing anything (do this now, then now and then):
any-ssh verify-backup /path/any-ssh-20261015T031700Z.anybak /path/recovery-secret.txt
# 2. Restore it on the server (stops Any-SSH, replaces the database, starts it again):
sudo any-ssh restore /path/any-ssh-20261015T031700Z.anybak /path/recovery-secret.txt
```

`verify-backup` and `restore` decrypt, authenticate every byte, and run the same checks as above against this server's master
key, so you find out about a wrong key or damaged file *before* anything is replaced. Restore keeps the previous database
beside the new one and takes a fresh backup first. To restore on a new server: run the installer, put the old master key
in `secrets/master_key`, then run `sudo any-ssh restore …`.

Restoring is deliberately not offered in the web UI: it replaces everything, including the accounts that would be used to
click the button, and needs the secret key, which should never be typed into a server that may be compromised.

Without the installer: `docker compose exec app node dist/cli/backup.js file` writes a backup into `/data/backups`
(encrypted if a key is set), and `docker compose run --rm --no-deps -T -e ANYSSH_BACKUP_KEY app node dist/cli/backup.js restore - --verify-only < backup.anybak`
checks one.

Backups made before a key was set are plain `.db` files. Restore them by stopping the stack and copying the file into the
volume as `/data/any-ssh.db`.

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

## Versions and updates

- The admin **Users** page shows the running version and build, and an "Update available" notice when a newer image is
  published for the tag you follow (`ANYSSH_VERSION`). The server finds out by reading the image's labels from ghcr.io
  every few hours (anonymous, read-only; nothing about your server is sent). Set `ANYSSH_UPDATE_CHECK=false` in `.env`
  to stop this entirely.
- Applying an update always happens on the host, never from the web app, so the app has no Docker access.
  `sudo any-ssh update` (manual), **Update now** in the app and `any-ssh auto-update on` (opt-in) all take a database
  backup first, and if the new version does not become healthy the previous image is put back automatically. Every
  update, whoever started it, is listed under Settings → Update history.
- **Update now and the update agent.** `sudo any-ssh web-update on` (or `auto-update on`) installs a systemd timer that
  runs `any-ssh update-poll` every 5 minutes. The app only records an admin's request in its database; the agent reads
  it with `docker compose exec` and runs the normal update. The Update now button stays disabled, with a hint, until the
  agent has checked in. Admins can cancel a scheduled update from the same place.
- **Warning before the restart.** A request is not run at once: it is scheduled 2 minutes ahead. At that moment everyone
  signed in sees a banner and open terminals print a notice. The update then runs at the agent's next check (up to 5
  minutes later) and takes a minute or two. A restart ends the in-memory SSH sessions, so terminals reconnect to a new
  one; the browser keeps retrying for about ten minutes, well beyond a normal restart.
- **Maintenance window.** Settings → Updates sets the days, start time, length and timezone (daylight saving
  is followed) in which *automatic* updates may be installed. Outside it, a new version is only flagged as available.
  The agent looks once per window, and an automatic update is not started if the window would close before the warning
  period ends. With no window set, automatic updates may run at any time, checked once a day. **Update now** is an
  explicit admin action and is not limited by the window.
- A rollback restores the old program, not the database. If the new version already changed the database schema, the
  old one may refuse to start; the pre-update backup is in `/opt/any-ssh/backups`.
- To pin a release instead of following `latest`, set `ANYSSH_VERSION=1.2` in `.env` (tags come from `v*` git tags).
