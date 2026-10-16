import type { FastifyBaseLogger } from 'fastify';
import { randomToken, sha256 } from './crypto.js';
import { emails } from './mail.js';
import type { AppContext, UserRow } from './types.js';

export type TokenPurpose = 'invite' | 'reset' | 'verify';

export const TOKEN_TTL_MS: Record<TokenPurpose, number> = {
  invite: 72 * 3600_000,
  reset: 30 * 60_000,
  verify: 24 * 3600_000,
};

/**
 * Issues a single-use link token. Any earlier unused token of the same purpose is revoked,
 * so only the most recent email works.
 */
export function issueToken(ctx: AppContext, userId: string, purpose: TokenPurpose): string {
  const token = randomToken(32);
  const now = Date.now();
  ctx.db.transaction(() => {
    ctx.db.prepare('DELETE FROM auth_tokens WHERE user_id = ? AND purpose = ? AND used_at IS NULL').run(userId, purpose);
    ctx.db
      .prepare('INSERT INTO auth_tokens (token_hash, user_id, purpose, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(sha256(token), userId, purpose, now, now + TOKEN_TTL_MS[purpose]);
  })();
  return token;
}

export interface TokenRow {
  token_hash: string;
  user_id: string;
  purpose: TokenPurpose;
  created_at: number;
  expires_at: number;
  used_at: number | null;
}

/** Finds a usable token and its (active) user, or null. Does not consume it. */
export function findToken(ctx: AppContext, token: string): { row: TokenRow; user: UserRow } | null {
  if (!token || token.length > 100) return null;
  const row = ctx.db.prepare('SELECT * FROM auth_tokens WHERE token_hash = ?').get(sha256(token)) as TokenRow | undefined;
  if (!row || row.used_at !== null || row.expires_at < Date.now()) return null;
  // Verification links belong to accounts that are not active yet; see findVerifyToken.
  if (row.purpose === 'verify') return null;
  const user = ctx.db.prepare("SELECT * FROM users WHERE id = ? AND status = 'active'").get(row.user_id) as UserRow | undefined;
  return user ? { row, user } : null;
}

/** Finds a usable email verification token and the self-registered account it belongs to, or null. */
export function findVerifyToken(ctx: AppContext, token: string): { row: TokenRow; user: UserRow } | null {
  if (!token || token.length > 100) return null;
  const row = ctx.db.prepare('SELECT * FROM auth_tokens WHERE token_hash = ?').get(sha256(token)) as TokenRow | undefined;
  if (!row || row.purpose !== 'verify' || row.used_at !== null || row.expires_at < Date.now()) return null;
  const user = ctx.db.prepare("SELECT * FROM users WHERE id = ? AND registration_state = 'unverified'").get(row.user_id) as UserRow | undefined;
  return user ? { row, user } : null;
}

/** Marks the token used. Returns false if someone else consumed it first. */
export function consumeToken(ctx: AppContext, tokenHash: string): boolean {
  return ctx.db.prepare('UPDATE auth_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL').run(Date.now(), tokenHash).changes === 1;
}

/** Links carry the token in the URL fragment, which browsers never send to servers or in Referer headers. */
export function tokenUrl(ctx: AppContext, purpose: TokenPurpose, token: string): string {
  return `${ctx.config.publicUrl}/#/${purpose === 'invite' ? 'welcome' : purpose === 'verify' ? 'verify' : 'reset'}?token=${token}`;
}

/**
 * Best-effort security notice to the account's email address. Never fails the request:
 * the change has already happened and is in the audit log.
 */
export function notify(ctx: AppContext, log: FastifyBaseLogger, user: Pick<UserRow, 'email' | 'display_name'>, what: string, to?: string): void {
  const address = to ?? user.email;
  if (!address) return;
  ctx.mailer.send(emails.securityNotice({ to: address, displayName: user.display_name, what })).catch((err: unknown) => {
    log.warn({ err }, 'Failed to send security notice email');
  });
}
