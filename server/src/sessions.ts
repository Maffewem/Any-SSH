import type { Config } from './config.js';
import { randomToken, sha256 } from './crypto.js';
import type { DB } from './db.js';
import type { SessionRow, UserRow } from './types.js';

/** A login that has passed the password step but still owes a TOTP code. */
const MFA_STAGE_TTL_MS = 5 * 60 * 1000;
/** Wrong passwords on the lock screen before the session is thrown away and a full sign-in is needed. */
export const MAX_UNLOCK_FAILURES = 5;
/** Activity is written at most this often. Small, so the idle lock is accurate across tabs. */
const TOUCH_INTERVAL_MS = 15_000;

export type SessionState = 'active' | 'locked' | 'dead';

export interface ResolvedSession {
  session: SessionRow;
  user: UserRow;
}

/**
 * Server-side sessions. The browser holds a random 256-bit token in an HttpOnly cookie;
 * the database holds only its SHA-256, so a leaked database cannot be replayed as cookies.
 * Sessions expire after an idle period and an absolute lifetime, and are revocable.
 *
 * Before the idle sign-out, a quieter idle period locks the session: it stays signed in (and its
 * SSH terminals stay connected but paused), yet every API call and terminal keystroke is refused
 * until the user re-enters their password. Locking is decided here, server-side, from the last
 * real activity, so hiding the lock screen in the browser unlocks nothing.
 */
export class SessionStore {
  private onRevoke: ((idHashes: string[]) => void) | null = null;
  private onLockChange: ((idHash: string, locked: boolean) => void) | null = null;

  constructor(
    private readonly db: DB,
    /** Read on every use, so settings changed in the web UI apply at once. */
    private readonly config: Pick<Config, 'sessionLockMinutes' | 'sessionIdleMinutes' | 'sessionMaxHours'>,
  ) {}

  /** Lets the terminal registry close live SSH sessions when a web session dies. */
  setRevokeListener(fn: (idHashes: string[]) => void): void {
    this.onRevoke = fn;
  }

  /** Lets the terminal registry pause and resume live SSH sessions as a web session locks and unlocks. */
  setLockListener(fn: (idHash: string, locked: boolean) => void): void {
    this.onLockChange = fn;
  }

  /** Classifies a stored session at `now`, locking it in the database if it has just gone idle. */
  private evaluate(s: SessionRow, now = Date.now()): SessionState {
    if (now > s.expires_at) return 'dead';
    if (s.stage !== 'full') return 'active';
    if (now > s.last_seen_at + this.config.sessionIdleMinutes * 60_000) return 'dead';
    if (s.locked_at !== null) return 'locked';
    const lock = this.config.sessionLockMinutes;
    if (lock > 0 && now > s.last_seen_at + lock * 60_000) {
      const res = this.db.prepare('UPDATE sessions SET locked_at = ? WHERE id_hash = ? AND locked_at IS NULL').run(now, s.id_hash);
      s.locked_at = now;
      if (res.changes) this.onLockChange?.(s.id_hash, true);
      return 'locked';
    }
    return 'active';
  }

  create(userId: string, stage: SessionRow['stage'], ip: string | null, userAgent: string | null): string {
    const token = randomToken(32);
    const now = Date.now();
    const expires = stage === 'mfa' ? now + MFA_STAGE_TTL_MS : now + this.config.sessionMaxHours * 3600_000;
    this.db
      .prepare(
        `INSERT INTO sessions (id_hash, user_id, stage, created_at, last_seen_at, expires_at, ip, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(sha256(token), userId, stage, now, now, expires, ip, userAgent?.slice(0, 300) ?? null);
    return token;
  }

  resolve(token: string | undefined): ResolvedSession | null {
    if (!token || token.length > 100) return null;
    const idHash = sha256(token);
    const session = this.db.prepare('SELECT * FROM sessions WHERE id_hash = ?').get(idHash) as SessionRow | undefined;
    if (!session) return null;
    if (this.evaluate(session) === 'dead') {
      this.destroyByHash(idHash);
      return null;
    }
    const user = this.db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id) as UserRow | undefined;
    if (!user || user.status !== 'active') {
      this.destroyByHash(idHash);
      return null;
    }
    return { session, user };
  }

  /** Records activity (never on a locked session), at most every few seconds to keep writes low. */
  touch(session: SessionRow): void {
    const now = Date.now();
    if (session.locked_at !== null) return;
    if (now - session.last_seen_at > TOUCH_INTERVAL_MS) {
      this.db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?').run(now, session.id_hash);
      session.last_seen_at = now;
    }
  }

  /**
   * Current state, polled by long-lived terminal connections to notice locking and expiry.
   * Keystrokes in a terminal count as activity (they call touch), so only a genuinely idle
   * terminal locks or times out.
   */
  state(idHash: string): SessionState {
    const s = this.db.prepare('SELECT * FROM sessions WHERE id_hash = ?').get(idHash) as SessionRow | undefined;
    // A session held by the trusted-IP challenge is not usable, so live terminals on it close.
    if (!s || s.stage !== 'full' || s.ip_challenge === 1) return 'dead';
    return this.evaluate(s);
  }

  /** Milliseconds of inactivity left before this session locks, or null if locking is off. */
  msUntilLock(session: SessionRow): number | null {
    const lock = this.config.sessionLockMinutes;
    if (lock <= 0 || session.stage !== 'full') return null;
    return Math.max(0, session.last_seen_at + lock * 60_000 - Date.now());
  }

  /** Locks now (the user pressed "Lock"). */
  lock(session: SessionRow): void {
    if (session.locked_at !== null) return;
    const now = Date.now();
    this.db.prepare('UPDATE sessions SET locked_at = ? WHERE id_hash = ? AND locked_at IS NULL').run(now, session.id_hash);
    session.locked_at = now;
    this.onLockChange?.(session.id_hash, true);
  }

  /** Clears the lock after the password was re-entered; counts as activity. */
  unlock(session: SessionRow): void {
    const now = Date.now();
    this.db.prepare('UPDATE sessions SET locked_at = NULL, unlock_failures = 0, last_seen_at = ? WHERE id_hash = ?').run(now, session.id_hash);
    session.locked_at = null;
    session.last_seen_at = now;
    this.onLockChange?.(session.id_hash, false);
  }

  /** Records a wrong lock-screen password. Returns true when the session was destroyed for it. */
  unlockFailed(session: SessionRow): boolean {
    this.db.prepare('UPDATE sessions SET unlock_failures = unlock_failures + 1 WHERE id_hash = ?').run(session.id_hash);
    const row = this.db.prepare('SELECT unlock_failures FROM sessions WHERE id_hash = ?').get(session.id_hash) as
      | { unlock_failures: number }
      | undefined;
    if (!row || row.unlock_failures >= MAX_UNLOCK_FAILURES) {
      this.destroyByHash(session.id_hash);
      return true;
    }
    return false;
  }

  destroy(token: string): void {
    this.destroyByHash(sha256(token));
  }

  destroyByHash(idHash: string): void {
    this.db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
    this.onRevoke?.([idHash]);
  }

  destroyAllForUser(userId: string, exceptIdHash?: string): number {
    const rows = this.db
      .prepare('SELECT id_hash FROM sessions WHERE user_id = ? AND id_hash != ?')
      .all(userId, exceptIdHash ?? '') as { id_hash: string }[];
    this.db.prepare('DELETE FROM sessions WHERE user_id = ? AND id_hash != ?').run(userId, exceptIdHash ?? '');
    if (rows.length) this.onRevoke?.(rows.map((r) => r.id_hash));
    return rows.length;
  }

  listForUser(userId: string): SessionRow[] {
    return this.db
      .prepare("SELECT * FROM sessions WHERE user_id = ? AND stage = 'full' ORDER BY last_seen_at DESC")
      .all(userId) as SessionRow[];
  }

  purgeExpired(): void {
    const now = Date.now();
    const idleCutoff = now - this.config.sessionIdleMinutes * 60_000;
    this.db
      .prepare("DELETE FROM sessions WHERE expires_at < ? OR (stage = 'full' AND last_seen_at < ?)")
      .run(now, idleCutoff);
  }
}
