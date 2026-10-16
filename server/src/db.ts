import Database from 'better-sqlite3';
import { chmodSync, mkdirSync } from 'node:fs';
import path from 'node:path';

export type DB = Database.Database;

/**
 * Forward-only migrations. Each entry runs once, in order, inside a transaction;
 * the applied count is tracked with SQLite's user_version pragma.
 */
const MIGRATIONS: string[] = [
  `
  CREATE TABLE users (
    id                    TEXT PRIMARY KEY,
    username              TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name          TEXT NOT NULL,
    password_hash         TEXT NOT NULL,
    role                  TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    must_change_password  INTEGER NOT NULL DEFAULT 0,
    totp_secret_enc       TEXT,
    totp_enabled          INTEGER NOT NULL DEFAULT 0,
    totp_last_counter     INTEGER,
    failed_logins         INTEGER NOT NULL DEFAULT 0,
    locked_until          INTEGER,
    last_login_at         INTEGER,
    password_changed_at   INTEGER NOT NULL,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
  );

  CREATE TABLE recovery_codes (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    INTEGER
  );
  CREATE INDEX recovery_codes_user ON recovery_codes(user_id);

  -- Session ids are never stored; only their SHA-256 hash.
  CREATE TABLE sessions (
    id_hash       TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stage         TEXT NOT NULL CHECK (stage IN ('mfa', 'full')),
    created_at    INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    ip            TEXT,
    user_agent    TEXT
  );
  CREATE INDEX sessions_user ON sessions(user_id);

  CREATE TABLE ssh_keys (
    id               TEXT PRIMARY KEY,
    owner_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    key_type         TEXT NOT NULL,
    public_key       TEXT NOT NULL,
    fingerprint      TEXT NOT NULL,
    private_key_enc  TEXT NOT NULL,
    created_at       INTEGER NOT NULL
  );
  CREATE INDEX ssh_keys_owner ON ssh_keys(owner_id);

  CREATE TABLE servers (
    id                    TEXT PRIMARY KEY,
    owner_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    host                  TEXT NOT NULL,
    port                  INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    username              TEXT NOT NULL,
    auth_method           TEXT NOT NULL CHECK (auth_method IN ('key', 'password', 'prompt')),
    key_id                TEXT REFERENCES ssh_keys(id) ON DELETE SET NULL,
    password_enc          TEXT,
    host_key_fingerprint  TEXT,
    notes                 TEXT NOT NULL DEFAULT '',
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
  );
  CREATE INDEX servers_owner ON servers(owner_id);

  CREATE TABLE server_shares (
    server_id   TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission  TEXT NOT NULL CHECK (permission IN ('use', 'manage')),
    created_by  TEXT,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (server_id, user_id)
  );
  CREATE INDEX server_shares_user ON server_shares(user_id);

  -- Append-only, hash-chained audit trail. Rows reference users by id *and* keep the
  -- username so history survives account deletion.
  CREATE TABLE audit_log (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              INTEGER NOT NULL,
    actor_id        TEXT,
    actor_username  TEXT,
    action          TEXT NOT NULL,
    target_type     TEXT,
    target_id       TEXT,
    ip              TEXT,
    outcome         TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    details         TEXT NOT NULL DEFAULT '{}',
    prev_hash       TEXT NOT NULL,
    hash            TEXT NOT NULL
  );
  CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
  CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
  `,
  `
  ALTER TABLE users ADD COLUMN email TEXT;
  ALTER TABLE ssh_keys ADD COLUMN last_used_at INTEGER;
  CREATE UNIQUE INDEX users_email ON users(email COLLATE NOCASE) WHERE email IS NOT NULL;

  -- Single-use links sent by email (invites, password resets). Only the SHA-256 is stored.
  CREATE TABLE auth_tokens (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose     TEXT NOT NULL CHECK (purpose IN ('invite', 'reset')),
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
  );
  CREATE INDEX auth_tokens_user ON auth_tokens(user_id);
  `,
  `
  -- 'owner': the grantee connects with the owner's saved key or password.
  -- 'own': the grantee must bring their own credentials; the owner's are never used for them.
  ALTER TABLE server_shares ADD COLUMN credentials TEXT NOT NULL DEFAULT 'owner' CHECK (credentials IN ('owner', 'own'));
  -- Whether a 'manage' grantee may share the server onwards. Off unless the owner turns it on.
  ALTER TABLE server_shares ADD COLUMN can_reshare INTEGER NOT NULL DEFAULT 0;
  `,
  `
  -- Settings an admin changed in the web UI, one JSON row per group. Absent = use the environment.
  -- value_enc holds the group's secret (the SMTP password), sealed under "setting:<id>".
  CREATE TABLE settings (
    id          TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    value_enc   TEXT,
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT
  );
  -- Idle lock: set when a session goes idle past the lock period; cleared by re-entering the password.
  ALTER TABLE sessions ADD COLUMN locked_at INTEGER;
  ALTER TABLE sessions ADD COLUMN unlock_failures INTEGER NOT NULL DEFAULT 0;
  `,
  `
  -- Per-user trusted IP list. Off unless the user turns it on.
  -- 'notify': a session from an unlisted address is allowed but flagged (audit + email).
  -- 'challenge': it is held until the user proves it is them (2FA code or an emailed code).
  ALTER TABLE users ADD COLUMN trusted_ip_enabled INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE users ADD COLUMN trusted_ip_policy TEXT NOT NULL DEFAULT 'notify' CHECK (trusted_ip_policy IN ('notify', 'challenge'));

  CREATE TABLE trusted_ips (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cidr        TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    UNIQUE (user_id, cidr)
  );

  -- ip_challenge = 1: the session came from an untrusted address under the 'challenge' policy.
  -- flagged_ip: the last untrusted address already reported for this session (so we flag once).
  ALTER TABLE sessions ADD COLUMN ip_challenge INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE sessions ADD COLUMN flagged_ip TEXT;

  -- Emailed one-time code for a held session. Only its SHA-256 is stored.
  CREATE TABLE ip_challenges (
    session_hash  TEXT PRIMARY KEY REFERENCES sessions(id_hash) ON DELETE CASCADE,
    code_hash     TEXT NOT NULL,
    expires_at    INTEGER NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0
  );
  `,
  `
  -- What the pinned host key is and who trusted it, for the owner and the admin host key view.
  ALTER TABLE servers ADD COLUMN host_key_type TEXT;
  ALTER TABLE servers ADD COLUMN host_key_pinned_at INTEGER;
  ALTER TABLE servers ADD COLUMN host_key_pinned_by TEXT;
  -- A different key the server presented. Connections stay refused; it waits here until the owner
  -- accepts it (re-entering their password) or dismisses it.
  ALTER TABLE servers ADD COLUMN host_key_pending TEXT;
  ALTER TABLE servers ADD COLUMN host_key_pending_type TEXT;
  ALTER TABLE servers ADD COLUMN host_key_pending_at INTEGER;
  `,
  `
  -- Brute-force protection. One row per failed attempt (login, 2FA, unlock, reset, re-auth); rows
  -- age out of the counting window. ip_lockouts holds addresses that crossed the per-IP threshold.
  CREATE TABLE auth_failures (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    kind     TEXT NOT NULL,
    ip       TEXT,
    user_id  TEXT REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX auth_failures_ip ON auth_failures(ip, ts);
  CREATE INDEX auth_failures_user ON auth_failures(user_id, ts);
  CREATE TABLE ip_lockouts (
    ip            TEXT PRIMARY KEY,
    locked_until  INTEGER NOT NULL,
    failures      INTEGER NOT NULL,
    created_at    INTEGER NOT NULL
  );
  `,
  `
  -- Admin-defined bastions. Each has its own Any-SSH-generated key (the jump host never sees a
  -- target's credentials: the target session runs end to end through it) and a pinned host key.
  CREATE TABLE jump_hosts (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL UNIQUE COLLATE NOCASE,
    host                  TEXT NOT NULL,
    port                  INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    username              TEXT NOT NULL,
    public_key            TEXT NOT NULL,
    fingerprint           TEXT NOT NULL,
    private_key_enc       TEXT NOT NULL,
    host_key_fingerprint  TEXT,
    enabled               INTEGER NOT NULL DEFAULT 1,
    created_by            TEXT,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
  );
  -- 'none': connect directly. 'auto': through the closest enabled jump host. 'fixed': through
  -- jump_host_id, chosen by an admin. A 'fixed' server whose jump host is gone fails closed.
  ALTER TABLE servers ADD COLUMN jump_mode TEXT NOT NULL DEFAULT 'none' CHECK (jump_mode IN ('none', 'auto', 'fixed'));
  ALTER TABLE servers ADD COLUMN jump_host_id TEXT REFERENCES jump_hosts(id) ON DELETE SET NULL;
  `,
  `
  -- Backup history, for the Settings page and for scheduling. Holds names, sizes and error text only.
  CREATE TABLE backup_runs (
    id           TEXT PRIMARY KEY,
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER,
    trigger      TEXT NOT NULL CHECK (trigger IN ('schedule', 'manual', 'cli')),
    outcome      TEXT NOT NULL CHECK (outcome IN ('running', 'success', 'failure')),
    name         TEXT,
    bytes        INTEGER,
    sha256       TEXT,
    destination  TEXT,
    key_id       TEXT,
    error        TEXT,
    warning      TEXT,
    notified     INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX backup_runs_started ON backup_runs(started_at);
  `,
  `
  -- Updates requested from the web app. The host's update agent (any-ssh update-poll) picks up a request once
  -- scheduled_for has passed, which gives connected users time to see the warning first.
  CREATE TABLE update_requests (
    id            TEXT PRIMARY KEY,
    requested_at  INTEGER NOT NULL,
    requested_by  TEXT NOT NULL,
    trigger       TEXT NOT NULL CHECK (trigger IN ('manual', 'auto')),
    scheduled_for INTEGER NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('pending', 'started', 'cancelled')),
    announced     INTEGER NOT NULL DEFAULT 0
  );
  -- Single row: when the host agent last polled, and when it last looked for an automatic update.
  CREATE TABLE update_agent (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    last_seen_at    INTEGER,
    last_auto_check INTEGER
  );
  INSERT INTO update_agent (id) VALUES (1);
  `,
  `
  -- Free-form labels for finding servers (a JSON array of strings, kept in the order given).
  ALTER TABLE servers ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
  `,
];

export const SCHEMA_VERSION = MIGRATIONS.length;

export function openDatabase(file: string): DB {
  if (file !== ':memory:') mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const db = new Database(file);
  if (file !== ':memory:') chmodSync(file, 0o600);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  db.pragma('secure_delete = ON');
  migrate(db);
  return db;
}

function migrate(db: DB): void {
  const current = db.pragma('user_version', { simple: true }) as number;
  for (let i = current; i < MIGRATIONS.length; i++) {
    db.transaction(() => {
      db.exec(MIGRATIONS[i]!);
      db.pragma(`user_version = ${i + 1}`);
    })();
  }
}
