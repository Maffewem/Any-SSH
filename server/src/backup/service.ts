import { randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, rename, rm, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import type { AuditLog } from '../audit.js';
import type { Config } from '../config.js';
import type { SecretBox } from '../crypto.js';
import type { DB } from '../db.js';
import { emails, type Mailer } from '../mail.js';
import { backupReady, type BackupFrequency, type Settings } from '../settings.js';
import { BACKUP_NAME, createTarget, type BackupTarget } from './targets.js';
import { backupKeyId, encryptFile, serverBackupKeyPair, type BackupEncryption } from './format.js';
import { verifyDatabaseFile } from './verify.js';

type Log = { info(obj: object | string, msg?: string): void; warn(obj: object | string, msg?: string): void };

/** A problem the caller can fix (no key set, nowhere to send to). Not recorded as a failed run. */
export class BackupConfigError extends Error {}

export type BackupTrigger = 'schedule' | 'manual' | 'cli';

export interface BackupRun {
  id: string;
  startedAt: number;
  finishedAt: number | null;
  trigger: BackupTrigger;
  outcome: 'running' | 'success' | 'failure';
  name: string | null;
  bytes: number | null;
  sha256: string | null;
  destination: string | null;
  keyId: string | null;
  encryption: BackupEncryption;
  error: string | null;
  warning: string | null;
}

interface RunRow {
  id: string;
  started_at: number;
  finished_at: number | null;
  trigger: BackupTrigger;
  outcome: 'running' | 'success' | 'failure';
  name: string | null;
  bytes: number | null;
  sha256: string | null;
  destination: string | null;
  key_id: string | null;
  encryption: BackupEncryption;
  error: string | null;
  warning: string | null;
}

const toRun = (r: RunRow): BackupRun => ({
  id: r.id,
  startedAt: r.started_at,
  finishedAt: r.finished_at,
  trigger: r.trigger,
  outcome: r.outcome,
  name: r.name,
  bytes: r.bytes,
  sha256: r.sha256,
  destination: r.destination,
  keyId: r.key_id,
  encryption: r.encryption,
  error: r.error,
  warning: r.warning,
});

const HOUR = 3600_000;
const DAY = 24 * HOUR;
const PERIOD: Record<BackupFrequency, number> = { hourly: HOUR, daily: DAY, weekly: 7 * DAY };
const RETRY_AFTER = 30 * 60_000;
const MAX_RETRIES_PER_SLOT = 3;
const NOTICE_EVERY = DAY;
const STALE_RUN = HOUR;

/** The most recent moment (UTC) a scheduled backup was due. */
export function lastSlot(now: number, s: { frequency: BackupFrequency; hourUtc: number; weekday: number }): number {
  const d = new Date(now);
  if (s.frequency === 'hourly') return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), d.getUTCHours());
  let slot = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), s.hourUtc);
  if (slot > now) slot -= DAY;
  if (s.frequency === 'weekly') {
    const back = (new Date(slot).getUTCDay() - s.weekday + 7) % 7;
    slot -= back * DAY;
  }
  return slot;
}

const stampOf = (t: number) => new Date(t).toISOString().replace(/[-:]|\.\d{3}/g, '');
async function sha256Of(file: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

const clipError = (err: unknown) => (err instanceof Error ? err.message : String(err)).replace(/\s+/g, ' ').trim().slice(0, 400);

export class BackupService {
  private timer: NodeJS.Timeout | null = null;
  private busy = false;

  constructor(
    private readonly deps: {
      db: DB;
      settings: Settings;
      box: SecretBox;
      audit: AuditLog;
      mailer: Mailer;
      config: Pick<Config, 'dataDir' | 'allowLoopbackTargets' | 'masterKey'>;
      log: Log;
    },
  ) {}

  private get dir(): string {
    return path.join(this.deps.config.dataDir, 'backups');
  }

  /** Builds the destination from the saved settings, or explains what is missing. */
  target(): BackupTarget {
    const { settings, config } = this.deps;
    const b = settings.backup;
    const secrets = settings.backupSecrets();
    const t = b.target;
    if (t.kind === 'none') throw new BackupConfigError('Choose where backups go first.');
    if (b.encryption === 'recovery' && !b.publicKey) throw new BackupConfigError('Set a recovery key first, or choose another kind of encryption.');
    if (t.kind === 'local') return createTarget({ kind: 'local', dir: this.dir });
    if (t.kind === 's3') {
      if (!secrets.s3SecretKey) throw new BackupConfigError('Enter the S3 secret access key.');
      return createTarget({ ...t, secretKey: secrets.s3SecretKey, allowLoopback: config.allowLoopbackTargets });
    }
    if (!t.hostKeyFingerprint) throw new BackupConfigError('Enter the SFTP server’s host key fingerprint first (the connection test shows the one it presents).');
    if (!secrets.sftpPassword && !secrets.sftpPrivateKey) throw new BackupConfigError('Enter an SFTP password or private key.');
    return createTarget({
      ...t,
      ...(secrets.sftpPassword ? { password: secrets.sftpPassword } : {}),
      ...(secrets.sftpPrivateKey ? { privateKey: secrets.sftpPrivateKey } : {}),
      allowLoopback: config.allowLoopbackTargets,
    });
  }

  /** The SFTP test has to be able to read the presented host key before it is trusted, so it is allowed without one. */
  async test(): Promise<{ destination: string }> {
    const { settings, config } = this.deps;
    const t = settings.backup.target;
    if (t.kind === 'sftp' && !t.hostKeyFingerprint) {
      const secrets = settings.backupSecrets();
      const target = createTarget({
        ...t,
        ...(secrets.sftpPassword ? { password: secrets.sftpPassword } : {}),
        ...(secrets.sftpPrivateKey ? { privateKey: secrets.sftpPrivateKey } : {}),
        allowLoopback: config.allowLoopbackTargets,
      });
      await target.probe();
      return { destination: target.label };
    }
    const target = this.target();
    await target.probe();
    return { destination: target.label };
  }

  recent(limit = 15): BackupRun[] {
    return (this.deps.db.prepare('SELECT * FROM backup_runs ORDER BY started_at DESC LIMIT ?').all(limit) as RunRow[]).map(toRun);
  }

  status(now = Date.now()) {
    const b = this.deps.settings.backup;
    const lastRow = this.deps.db.prepare("SELECT * FROM backup_runs WHERE outcome != 'running' ORDER BY started_at DESC LIMIT 1").get() as RunRow | undefined;
    const successRow = this.deps.db.prepare("SELECT * FROM backup_runs WHERE outcome = 'success' ORDER BY started_at DESC LIMIT 1").get() as RunRow | undefined;
    const running = !!this.deps.db.prepare("SELECT 1 FROM backup_runs WHERE outcome = 'running' AND started_at > ?").get(now - STALE_RUN);
    const configured = backupReady(b);
    const lastSuccessAt = successRow?.started_at ?? null;
    // A schedule that has produced nothing for two periods is a problem even without a recorded failure.
    const stale = b.enabled && configured && (lastSuccessAt === null ? now - this.firstEnabledGuess(now) > 2 * PERIOD[b.frequency] : now - lastSuccessAt > 2 * PERIOD[b.frequency]);
    return {
      configured,
      scheduled: b.enabled && configured,
      running,
      last: lastRow ? toRun(lastRow) : null,
      lastSuccess: successRow ? toRun(successRow) : null,
      nextRunAt: b.enabled && configured ? lastSlot(now, b) + (b.frequency === 'hourly' ? HOUR : b.frequency === 'daily' ? DAY : 7 * DAY) : null,
      stale,
    };
  }

  private firstEnabledGuess(now: number): number {
    const first = this.deps.db.prepare('SELECT MIN(started_at) AS t FROM backup_runs').get() as { t: number | null };
    return first.t ?? now;
  }

  /**
   * Takes a backup now: snapshot, verify, encrypt, store, prune. Failures are recorded, audited and emailed rather
   * than thrown; only a missing key or destination throws (BackupConfigError).
   */
  async run(trigger: BackupTrigger, actor?: { id: string; username: string; ip?: string }): Promise<BackupRun> {
    const { db, settings, box, audit } = this.deps;
    const cfg = settings.backup;
    const target = this.target();
    if (this.busy || db.prepare("SELECT 1 FROM backup_runs WHERE outcome = 'running' AND started_at > ?").get(Date.now() - STALE_RUN)) {
      throw new BackupConfigError('A backup is already running.');
    }
    this.busy = true;
    const id = randomUUID();
    const startedAt = Date.now();
    const encryption = cfg.encryption;
    // The system key is re-derived from the current master key each time, so it follows key rotation.
    const publicKey = encryption === 'recovery' ? cfg.publicKey : encryption === 'system' ? serverBackupKeyPair(this.deps.config.masterKey).publicKey : null;
    const name = `any-ssh-${stampOf(startedAt)}.${publicKey ? 'anybak' : 'db'}`;
    const keyId = publicKey ? backupKeyId(publicKey) : null;
    db.prepare("INSERT INTO backup_runs (id, started_at, trigger, outcome, name, destination, key_id, encryption) VALUES (?, ?, ?, 'running', ?, ?, ?, ?)").run(
      id,
      startedAt,
      trigger,
      name,
      target.label,
      keyId,
      encryption,
    );
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    const snapshot = path.join(this.dir, `.snapshot-${id}.db`);
    const outgoing = path.join(this.dir, `.${name}.tmp`);
    let warning: string | null = null;
    try {
      await db.backup(snapshot);
      const report = verifyDatabaseFile(snapshot, box);
      if (!report.ok) {
        const bad = report.checks.find((c) => !c.ok)!;
        throw new Error(`The database failed its check (${bad.name}: ${bad.detail}), so it was not backed up.`);
      }
      let bytes: number;
      let sha256: string;
      if (publicKey) {
        ({ bytes, sha256 } = await encryptFile(snapshot, outgoing, publicKey));
        await rm(snapshot, { force: true });
      } else {
        await rename(snapshot, outgoing);
        bytes = await fileSize(outgoing);
        sha256 = await sha256Of(outgoing);
      }
      const stored = await target.put(outgoing, name);
      if (stored !== bytes) throw new Error(`The destination reports ${stored} bytes for a ${bytes} byte backup, so the upload is not trusted.`);
      try {
        await this.prune(target, cfg.keep);
      } catch (err) {
        warning = `The backup was saved, but removing old ones failed: ${clipError(err)}`;
      }
      db.prepare("UPDATE backup_runs SET outcome = 'success', finished_at = ?, bytes = ?, sha256 = ?, warning = ? WHERE id = ?").run(Date.now(), bytes, sha256, warning, id);
      audit.record({ actorId: actor?.id ?? null, actorUsername: actor?.username ?? null, action: 'backup.run', targetType: 'backup', targetId: name, ip: actor?.ip ?? null, details: { trigger, destination: target.label, bytes, encryption, keyId } });
      this.deps.log.info({ name, bytes, destination: target.label }, 'Backup stored');
    } catch (err) {
      const message = clipError(err);
      db.prepare("UPDATE backup_runs SET outcome = 'failure', finished_at = ?, error = ? WHERE id = ?").run(Date.now(), message, id);
      audit.record({ actorId: actor?.id ?? null, actorUsername: actor?.username ?? null, action: 'backup.run', targetType: 'backup', targetId: name, ip: actor?.ip ?? null, outcome: 'failure', details: { trigger, destination: target.label, error: message } });
      this.deps.log.warn({ err: message }, 'Backup failed');
      await this.notifyFailure(id, message, target.label);
    } finally {
      this.busy = false;
      await rm(snapshot, { force: true });
      await rm(outgoing, { force: true });
    }
    return toRun(db.prepare('SELECT * FROM backup_runs WHERE id = ?').get(id) as RunRow);
  }

  private async prune(target: BackupTarget, keep: number): Promise<void> {
    const names = (await target.list()).filter((n) => BACKUP_NAME.test(n)).sort().reverse();
    for (const old of names.slice(keep)) await target.remove(old);
  }

  /** Emails every admin with an address, at most once a day while backups keep failing. */
  private async notifyFailure(runId: string, error: string, destination: string): Promise<void> {
    const { db, mailer } = this.deps;
    const recent = db.prepare("SELECT 1 FROM backup_runs WHERE outcome = 'failure' AND notified = 1 AND started_at > ?").get(Date.now() - NOTICE_EVERY);
    if (recent) return;
    db.prepare('UPDATE backup_runs SET notified = 1 WHERE id = ?').run(runId);
    const admins = db.prepare("SELECT email, display_name FROM users WHERE role = 'admin' AND status = 'active' AND email IS NOT NULL").all() as { email: string; display_name: string }[];
    for (const a of admins) {
      await mailer.send(emails.backupFailed({ to: a.email, displayName: a.display_name, destination, error })).catch((err: unknown) => {
        this.deps.log.warn({ err: clipError(err) }, 'Could not send the backup failure email');
      });
    }
  }

  /** Is a scheduled backup due? Missed slots (server was off) run as soon as the server is back. */
  due(now = Date.now()): boolean {
    const b = this.deps.settings.backup;
    if (!b.enabled || !backupReady(b)) return false;
    const slot = lastSlot(now, b);
    const last = this.deps.db.prepare("SELECT started_at, outcome FROM backup_runs WHERE trigger = 'schedule' ORDER BY started_at DESC LIMIT 1").get() as { started_at: number; outcome: string } | undefined;
    const anySuccess = this.deps.db.prepare("SELECT 1 FROM backup_runs WHERE outcome = 'success' AND started_at >= ?").get(slot);
    if (anySuccess) return false;
    if (!last || last.started_at < slot) return true;
    if (last.outcome !== 'failure' || now - last.started_at < RETRY_AFTER) return false;
    const tries = (this.deps.db.prepare("SELECT COUNT(*) AS n FROM backup_runs WHERE trigger = 'schedule' AND started_at >= ?").get(slot) as { n: number }).n;
    return tries <= MAX_RETRIES_PER_SLOT;
  }

  async tick(now = Date.now()): Promise<void> {
    if (!this.due(now)) return;
    try {
      await this.run('schedule');
    } catch (err) {
      if (!(err instanceof BackupConfigError)) this.deps.log.warn({ err: clipError(err) }, 'Scheduled backup could not start');
    }
  }

  /** Starts the scheduler: checks once a minute. Runs left "running" by a crash are closed as interrupted. */
  start(everyMs = 60_000): void {
    if (this.timer) return;
    this.deps.db.prepare("UPDATE backup_runs SET outcome = 'failure', finished_at = ?, error = 'The server stopped while this backup was running.' WHERE outcome = 'running'").run(Date.now());
    this.timer = setInterval(() => void this.tick(), everyMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}

export async function fileSize(file: string): Promise<number> {
  return (await stat(file)).size;
}
