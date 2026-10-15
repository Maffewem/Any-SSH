import Database from 'better-sqlite3';
import { rmSync } from 'node:fs';
import { AuditLog } from '../audit.js';
import type { SecretBox } from '../crypto.js';
import { SCHEMA_VERSION, type DB } from '../db.js';
import { checkSecrets } from '../rotate.js';

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface VerifyReport {
  ok: boolean;
  checks: VerifyCheck[];
}

/**
 * Opens a database file read-only and checks that it is a sound, complete Any-SSH database: SQLite's own integrity
 * check, the schema version, the audit log's hash chain and, when the master key is given, that it opens every secret.
 */
export function verifyDatabaseFile(file: string, box?: SecretBox): VerifyReport {
  const checks: VerifyCheck[] = [];
  let db: DB | undefined;
  try {
    db = new Database(file, { readonly: true, fileMustExist: true });
    const integrity = db.pragma('integrity_check', { simple: true });
    checks.push({ name: 'Database integrity', ok: integrity === 'ok', detail: String(integrity) });

    const version = db.pragma('user_version', { simple: true }) as number;
    const hasTables = (['users', 'audit_log', 'servers'] as const).every((t) => db!.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(t));
    checks.push({
      name: 'Schema',
      ok: hasTables && version >= 1 && version <= SCHEMA_VERSION,
      detail: !hasTables
        ? 'This is not an Any-SSH database.'
        : version > SCHEMA_VERSION
          ? `Made by a newer Any-SSH (schema ${version}, this one understands ${SCHEMA_VERSION}). Update first.`
          : `Schema ${version} of ${SCHEMA_VERSION}`,
    });

    if (hasTables) {
      const count = (t: string) => (db!.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get() as { n: number }).n;
      checks.push({ name: 'Contents', ok: true, detail: `${count('users')} user(s), ${count('servers')} server(s), ${count('ssh_keys')} key(s)` });
      const audit = new AuditLog(db).verify();
      checks.push({
        name: 'Audit log chain',
        ok: audit.ok,
        detail: audit.ok ? `${audit.checked} entries intact` : `Broken at entry ${audit.brokenAt}`,
      });
      if (box) {
        const secrets = checkSecrets(db, box);
        checks.push({
          name: 'Master key',
          ok: secrets.failed === 0,
          detail: secrets.failed === 0 ? `Opens all ${secrets.checked} stored secret(s)` : `Cannot open ${secrets.failed} of ${secrets.checked} secret(s): this is not the master key these backups were made with`,
        });
      }
    }
  } catch (err) {
    checks.push({ name: 'Open database', ok: false, detail: err instanceof Error ? err.message : String(err) });
  } finally {
    db?.close();
    // Opening a WAL-mode snapshot leaves empty side files behind.
    for (const ext of ['-wal', '-shm']) rmSync(`${file}${ext}`, { force: true });
  }
  return { ok: checks.every((c) => c.ok), checks };
}
