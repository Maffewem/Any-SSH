import type { FastifyBaseLogger } from 'fastify';
import { notify } from './accountTokens.js';
import type { AuditLog } from './audit.js';
import type { DB } from './db.js';
import { HttpError } from './http.js';
import { normaliseIp } from './ipTrust.js';
import type { Settings } from './settings.js';
import type { AppContext, UserRow } from './types.js';

/** What was being attempted. Every kind counts towards the per-IP limit; those with a user also towards the account's. */
export type FailureKind = 'login' | 'mfa' | 'unlock' | 'reset' | 'challenge' | 'reauth' | 'setup' | 'captcha' | 'register';

export interface FailureResult {
  accountLockedUntil: number | null;
  ipLockedUntil: number | null;
  failures: number;
}

/**
 * Sliding-window brute-force protection shared by sign-in, the second factor, screen unlock,
 * password reset and re-entering the password for sensitive actions. Thresholds come from the
 * admin Settings page. Crossing the per-account threshold locks the account (users.locked_until);
 * crossing the per-IP threshold blocks the address from the unauthenticated routes. The counters
 * restart after each lockout, so a persistent attacker is locked again every `threshold` tries.
 */
export class BruteForce {
  constructor(
    private readonly db: DB,
    private readonly settings: Settings,
    private readonly audit: AuditLog,
  ) {}

  private key(ip: string | null | undefined): string | null {
    return ip ? (normaliseIp(ip) ?? ip) : null;
  }

  ipLockedUntil(ip: string | null | undefined): number | null {
    const k = this.key(ip);
    if (!k) return null;
    const row = this.db.prepare('SELECT locked_until FROM ip_lockouts WHERE ip = ?').get(k) as { locked_until: number } | undefined;
    return row && row.locked_until > Date.now() ? row.locked_until : null;
  }

  recordFailure(o: { kind: FailureKind; ip: string | null; user?: UserRow | null }): FailureResult {
    const s = this.settings.security;
    const now = Date.now();
    const since = now - s.windowMinutes * 60_000;
    const ip = this.key(o.ip);
    const user = o.user ?? null;
    this.db.prepare('INSERT INTO auth_failures (ts, kind, ip, user_id) VALUES (?, ?, ?, ?)').run(now, o.kind, ip, user?.id ?? null);

    const result: FailureResult = { accountLockedUntil: null, ipLockedUntil: null, failures: 0 };
    if (user) {
      this.db.prepare('UPDATE users SET failed_logins = failed_logins + 1 WHERE id = ?').run(user.id);
      const n = (this.db.prepare('SELECT COUNT(*) AS n FROM auth_failures WHERE user_id = ? AND ts > ?').get(user.id, since) as { n: number }).n;
      const alreadyLocked = user.locked_until !== null && user.locked_until > now;
      if (n >= s.accountThreshold && !alreadyLocked) {
        const until = now + s.lockoutMinutes * 60_000;
        this.db.prepare('UPDATE users SET locked_until = ? WHERE id = ?').run(until, user.id);
        this.db.prepare('DELETE FROM auth_failures WHERE user_id = ?').run(user.id);
        this.audit.record({
          actorId: user.id, actorUsername: user.username, action: 'auth.lockout', targetType: 'user', targetId: user.id, ip, outcome: 'failure',
          details: { scope: 'account', failures: n, kind: o.kind, until },
        });
        result.accountLockedUntil = until;
        result.failures = n;
      }
    }
    if (ip && this.ipLockedUntil(ip) === null) {
      const n = (this.db.prepare('SELECT COUNT(*) AS n FROM auth_failures WHERE ip = ? AND ts > ?').get(ip, since) as { n: number }).n;
      if (n >= s.ipThreshold) {
        const until = now + s.lockoutMinutes * 60_000;
        this.db
          .prepare(
            `INSERT INTO ip_lockouts (ip, locked_until, failures, created_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(ip) DO UPDATE SET locked_until = excluded.locked_until, failures = excluded.failures, created_at = excluded.created_at`,
          )
          .run(ip, until, n, now);
        this.db.prepare('DELETE FROM auth_failures WHERE ip = ?').run(ip);
        this.audit.record({ action: 'auth.lockout', targetType: 'ip', targetId: ip, ip, outcome: 'failure', details: { scope: 'ip', failures: n, kind: o.kind, until } });
        result.ipLockedUntil = until;
      }
    }
    return result;
  }

  /** A successful sign-in or an admin unlock wipes the account's counter. */
  clearUser(userId: string): void {
    this.db.prepare('DELETE FROM auth_failures WHERE user_id = ?').run(userId);
  }

  listIpLockouts(): { ip: string; lockedUntil: number; failures: number; createdAt: number }[] {
    const rows = this.db
      .prepare('SELECT * FROM ip_lockouts WHERE locked_until > ? ORDER BY locked_until DESC')
      .all(Date.now()) as { ip: string; locked_until: number; failures: number; created_at: number }[];
    return rows.map((r) => ({ ip: r.ip, lockedUntil: r.locked_until, failures: r.failures, createdAt: r.created_at }));
  }

  unlockIp(ip: string): boolean {
    const k = this.key(ip) ?? ip;
    this.db.prepare('DELETE FROM auth_failures WHERE ip = ?').run(k);
    return this.db.prepare('DELETE FROM ip_lockouts WHERE ip = ?').run(k).changes > 0;
  }

  purge(): void {
    const now = Date.now();
    this.db.prepare('DELETE FROM auth_failures WHERE ts < ?').run(now - Math.max(this.settings.security.windowMinutes * 60_000, 60 * 60_000));
    this.db.prepare('DELETE FROM ip_lockouts WHERE locked_until < ?').run(now - 24 * 3600_000);
  }
}

/** Throws 429 when the caller's address is locked out. Call before doing any work on unauthenticated routes. */
export function assertIpAllowed(ctx: AppContext, ip: string): void {
  if (ctx.bruteForce.ipLockedUntil(ip) !== null) {
    throw new HttpError(429, 'Too many failed attempts from this IP address. Try again later.', 'ip_locked');
  }
}

/** Records a failed attempt and, when it tips an account into lockout, emails the owner. */
export function recordAuthFailure(
  ctx: AppContext,
  log: FastifyBaseLogger,
  ip: string,
  kind: FailureKind,
  user?: UserRow | null,
): FailureResult {
  const res = ctx.bruteForce.recordFailure({ kind, ip, user: user ?? null });
  if (user && res.accountLockedUntil && ctx.settings.security.notifyOwner) {
    const mins = Math.max(1, Math.round((res.accountLockedUntil - Date.now()) / 60_000));
    notify(
      ctx, log, user,
      `your account was locked for ${mins} minute${mins === 1 ? '' : 's'} after ${res.failures} failed attempts (latest from ${ip}). It will unlock automatically, or an administrator can unlock it sooner. If this wasn’t you, consider changing your password`,
    );
  }
  return res;
}

/**
 * A wrong password on a signed-in action (changing the password, 2FA, exporting a key...). A stolen
 * session must not be a free password-guessing oracle: enough misses lock the account and end every session.
 */
export function recordReauthFailure(ctx: AppContext, log: FastifyBaseLogger, ip: string, user: UserRow): void {
  const res = recordAuthFailure(ctx, log, ip, 'reauth', user);
  if (res.accountLockedUntil) {
    ctx.sessions.destroyAllForUser(user.id);
    ctx.terminals.closeForUser(user.id, 'Your account was locked after too many failed attempts.');
  }
}
