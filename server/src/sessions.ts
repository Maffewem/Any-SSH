import type { Config } from './config.js';
import { randomToken, sha256 } from './crypto.js';
import type { DB } from './db.js';
import type { SessionRow, UserRow } from './types.js';

/** A login that has passed the password step but still owes a TOTP code. */
const MFA_STAGE_TTL_MS = 5 * 60 * 1000;

export interface ResolvedSession {
  session: SessionRow;
  user: UserRow;
}

/**
 * Server-side sessions. The browser holds a random 256-bit token in an HttpOnly cookie;
 * the database holds only its SHA-256, so a leaked database cannot be replayed as cookies.
 * Sessions expire after an idle period and an absolute lifetime, and are revocable.
 */
export class SessionStore {
  private onRevoke: ((idHashes: string[]) => void) | null = null;

  constructor(
    private readonly db: DB,
    private readonly config: Pick<Config, 'sessionIdleMinutes' | 'sessionMaxHours'>,
  ) {}

  /** Lets the terminal registry close live SSH sessions when a web session dies. */
  setRevokeListener(fn: (idHashes: string[]) => void): void {
    this.onRevoke = fn;
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
    const now = Date.now();
    const idleLimit = session.last_seen_at + this.config.sessionIdleMinutes * 60_000;
    if (now > session.expires_at || (session.stage === 'full' && now > idleLimit)) {
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

  /** Records activity, at most once a minute to keep writes low. */
  touch(session: SessionRow): void {
    const now = Date.now();
    if (now - session.last_seen_at > 60_000) {
      this.db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?').run(now, session.id_hash);
      session.last_seen_at = now;
    }
  }

  /**
   * Still valid? Polled by long-lived terminal connections to notice expiry. Keystrokes in a
   * terminal count as activity (they call touch), so only a genuinely idle terminal times out.
   */
  isAlive(idHash: string): boolean {
    const s = this.db.prepare('SELECT * FROM sessions WHERE id_hash = ?').get(idHash) as SessionRow | undefined;
    if (!s || s.stage !== 'full' || s.ip_challenge === 1) return false;
    const now = Date.now();
    return now <= s.expires_at && now <= s.last_seen_at + this.config.sessionIdleMinutes * 60_000;
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
