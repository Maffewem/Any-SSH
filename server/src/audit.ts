import { createHash } from 'node:crypto';
import type { DB } from './db.js';

export interface AuditEntry {
  actorId?: string | null;
  actorUsername?: string | null;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  ip?: string | null;
  outcome?: 'success' | 'failure';
  details?: Record<string, unknown>;
}

export interface AuditRow {
  seq: number;
  ts: number;
  actor_id: string | null;
  actor_username: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
  outcome: 'success' | 'failure';
  details: string;
  prev_hash: string;
  hash: string;
}

const GENESIS = '0'.repeat(64);

function rowHash(prevHash: string, r: Omit<AuditRow, 'seq' | 'hash' | 'prev_hash'>): string {
  const canonical = JSON.stringify([
    r.ts, r.actor_id, r.actor_username, r.action, r.target_type, r.target_id, r.ip, r.outcome, r.details,
  ]);
  return createHash('sha256').update(prevHash).update(canonical).digest('hex');
}

/**
 * Append-only audit log. Each row carries the SHA-256 of the previous row, so any edit or
 * deletion made directly in the database breaks the chain and shows up in verify().
 * Secrets must never be passed in `details`.
 */
export class AuditLog {
  constructor(private readonly db: DB) {}

  record(e: AuditEntry): void {
    const row = {
      ts: Date.now(),
      actor_id: e.actorId ?? null,
      actor_username: e.actorUsername ?? null,
      action: e.action,
      target_type: e.targetType ?? null,
      target_id: e.targetId ?? null,
      ip: e.ip ?? null,
      outcome: e.outcome ?? 'success',
      details: JSON.stringify(e.details ?? {}),
    };
    this.db.transaction(() => {
      const last = this.db.prepare('SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1').get() as
        | { hash: string }
        | undefined;
      const prev = last?.hash ?? GENESIS;
      this.db
        .prepare(
          `INSERT INTO audit_log (ts, actor_id, actor_username, action, target_type, target_id, ip, outcome, details, prev_hash, hash)
           VALUES (@ts, @actor_id, @actor_username, @action, @target_type, @target_id, @ip, @outcome, @details, @prev_hash, @hash)`,
        )
        .run({ ...row, prev_hash: prev, hash: rowHash(prev, row) });
    }).immediate();
  }

  list(opts: { limit: number; beforeSeq?: number; actorId?: string; action?: string }): AuditRow[] {
    const where: string[] = [];
    const params: Record<string, unknown> = { limit: opts.limit };
    if (opts.beforeSeq) {
      where.push('seq < @before');
      params.before = opts.beforeSeq;
    }
    if (opts.actorId) {
      where.push('actor_id = @actor');
      params.actor = opts.actorId;
    }
    if (opts.action) {
      where.push('action LIKE @action');
      params.action = `${opts.action}%`;
    }
    const sql = `SELECT * FROM audit_log ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY seq DESC LIMIT @limit`;
    return this.db.prepare(sql).all(params) as AuditRow[];
  }

  /** Walks the whole chain. Returns the first broken sequence number, or null if intact. */
  verify(): { ok: boolean; checked: number; brokenAt: number | null } {
    let prev = GENESIS;
    let checked = 0;
    for (const r of this.db.prepare('SELECT * FROM audit_log ORDER BY seq ASC').iterate() as Iterable<AuditRow>) {
      if (r.prev_hash !== prev || rowHash(prev, r) !== r.hash) return { ok: false, checked, brokenAt: r.seq };
      prev = r.hash;
      checked++;
    }
    return { ok: true, checked, brokenAt: null };
  }
}
