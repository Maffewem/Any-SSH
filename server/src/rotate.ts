import type { SecretBox } from './crypto.js';
import type { DB } from './db.js';
import { keyContext } from './routes/keys.js';
import { serverPasswordContext } from './routes/servers.js';
import { settingContext } from './settings.js';

export const jumpHostContext = (id: string) => `jump_host:${id}:private`;
const totpContext = (userId: string) => `user:${userId}:totp`;

/** Every sealed column, with the AAD context each row was sealed under. */
const SEALED_COLUMNS = [
  { table: 'ssh_keys', column: 'private_key_enc', context: keyContext },
  { table: 'servers', column: 'password_enc', context: serverPasswordContext },
  { table: 'jump_hosts', column: 'private_key_enc', context: jumpHostContext },
  { table: 'users', column: 'totp_secret_enc', context: totpContext },
  { table: 'settings', column: 'value_enc', context: settingContext },
] as const;

/**
 * Re-seals every secret still encrypted with a retired master key under the current one.
 * Safe to run repeatedly and while the server is up: each row is updated in its own
 * statement and only if it has not changed in the meantime.
 */
export function rotateSecrets(db: DB, box: SecretBox): { resealed: number; remainingStale: number } {
  let resealed = 0;
  for (const { table, column, context } of SEALED_COLUMNS) {
    const rows = db.prepare(`SELECT id, ${column} AS sealed FROM ${table} WHERE ${column} IS NOT NULL`).all() as {
      id: string;
      sealed: string;
    }[];
    const update = db.prepare(`UPDATE ${table} SET ${column} = ? WHERE id = ? AND ${column} = ?`);
    for (const row of rows) {
      if (!box.isStale(row.sealed)) continue;
      resealed += update.run(box.reseal(row.sealed, context(row.id)), row.id, row.sealed).changes;
    }
  }
  return { resealed, remainingStale: countStale(db, box) };
}

export function countStale(db: DB, box: SecretBox): number {
  let stale = 0;
  for (const { table, column } of SEALED_COLUMNS) {
    const rows = db.prepare(`SELECT ${column} AS sealed FROM ${table} WHERE ${column} IS NOT NULL`).all() as { sealed: string }[];
    stale += rows.filter((r) => box.isStale(r.sealed)).length;
  }
  return stale;
}

/** Tries to open every sealed value with the current keys. Used to prove a restored database matches the master key. */
export function checkSecrets(db: DB, box: SecretBox): { checked: number; failed: number } {
  let checked = 0;
  let failed = 0;
  for (const { table, column, context } of SEALED_COLUMNS) {
    const rows = db.prepare(`SELECT id, ${column} AS sealed FROM ${table} WHERE ${column} IS NOT NULL`).all() as { id: string; sealed: string }[];
    for (const row of rows) {
      checked++;
      try {
        box.open(row.sealed, context(row.id));
      } catch {
        failed++;
      }
    }
  }
  return { checked, failed };
}
