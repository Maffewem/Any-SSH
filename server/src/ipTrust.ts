import { BlockList, isIP } from 'node:net';
import { randomInt, randomUUID } from 'node:crypto';
import type { FastifyBaseLogger } from 'fastify';
import { notify } from './accountTokens.js';
import { sha256 } from './crypto.js';
import { emails } from './mail.js';
import type { AppContext, SessionRow, UserRow } from './types.js';

/** Smallest range a user may trust, so "trust everything" cannot be typed by accident. */
const MIN_PREFIX = { 4: 8, 6: 32 } as const;
const CODE_TTL_MS = 10 * 60_000;
export const CODE_RESEND_MS = 60_000;
export const MAX_CODE_ATTEMPTS = 5;

export type IpPolicy = 'notify' | 'challenge';

/** Unwraps IPv4-mapped IPv6 (::ffff:1.2.3.4) and drops any zone id, so one address has one spelling. */
export function normaliseIp(ip: string | null | undefined): string | null {
  if (!ip) return null;
  let v = ip.trim().toLowerCase().split('%')[0]!;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v);
  if (mapped) v = mapped[1]!;
  return isIP(v) ? v : null;
}

/** Validates an address or CIDR range typed by a user. Returns the canonical text or an error message. */
export function parseTrustedEntry(raw: string): { value: string } | { error: string } {
  const text = raw.trim();
  const [addrPart, prefixPart, ...rest] = text.split('/');
  const addr = normaliseIp(addrPart);
  if (!addr || rest.length) return { error: 'Enter an IP address (1.2.3.4 or 2001:db8::1) or a range such as 203.0.113.0/24.' };
  const family = isIP(addr) as 4 | 6;
  if (prefixPart === undefined) return { value: addr };
  if (!/^\d{1,3}$/.test(prefixPart)) return { error: 'The range size after “/” must be a number.' };
  const prefix = Number(prefixPart);
  const max = family === 4 ? 32 : 128;
  if (prefix > max) return { error: `The range size for ${family === 4 ? 'IPv4' : 'IPv6'} can be at most /${max}.` };
  if (prefix < MIN_PREFIX[family]) {
    return { error: `That range is too wide to be a useful trust boundary (minimum /${MIN_PREFIX[family]} for ${family === 4 ? 'IPv4' : 'IPv6'}).` };
  }
  return { value: prefix === max ? addr : `${addr}/${prefix}` };
}

export function isTrustedIp(entries: string[], ip: string | null): boolean {
  const addr = normaliseIp(ip);
  if (!addr) return false;
  const list = new BlockList();
  for (const e of entries) {
    const [a, p] = e.split('/');
    const family = isIP(a!) === 4 ? 'ipv4' : 'ipv6';
    if (p === undefined) list.addAddress(a!, family);
    else list.addSubnet(a!, Number(p), family);
  }
  return list.check(addr, isIP(addr) === 4 ? 'ipv4' : 'ipv6');
}

export function trustedEntries(ctx: AppContext, userId: string): string[] {
  return (ctx.db.prepare('SELECT cidr FROM trusted_ips WHERE user_id = ?').all(userId) as { cidr: string }[]).map((r) => r.cidr);
}

export interface IpVerdict {
  /** The session is held until the user proves it is them. */
  challenged: boolean;
}

/**
 * Compares the address a request really came from with the user's trusted list.
 * Runs on every API request of a signed-in session and on every terminal WebSocket connect, so a
 * stolen cookie used from another network is caught, not only a fresh login.
 *
 * `ip` must come from `clientIp(req)`, which is Fastify's proxy-aware address (the reverse proxy's
 * X-Forwarded-For when ANYSSH_TRUST_PROXY is on, the socket address otherwise). No header is read here.
 */
export function checkSessionIp(
  ctx: AppContext,
  log: FastifyBaseLogger,
  user: UserRow,
  session: SessionRow,
  ip: string | null,
  opts: { verifiedByMfa?: boolean } = {},
): IpVerdict {
  if (!user.trusted_ip_enabled || session.stage !== 'full') return { challenged: session.ip_challenge === 1 };
  const addr = normaliseIp(ip);
  if (addr && isTrustedIp(trustedEntries(ctx, user.id), addr)) return { challenged: session.ip_challenge === 1 };
  // Already dealt with this address on this session.
  if (session.flagged_ip === (addr ?? 'unknown')) return { challenged: session.ip_challenge === 1 };

  const shown = addr ?? 'an unknown address';
  const hold = user.trusted_ip_policy === 'challenge' && !opts.verifiedByMfa;
  ctx.db
    .prepare('UPDATE sessions SET flagged_ip = ?, ip_challenge = ? WHERE id_hash = ?')
    .run(addr ?? 'unknown', hold ? 1 : session.ip_challenge, session.id_hash);
  session.flagged_ip = addr ?? 'unknown';
  if (hold) session.ip_challenge = 1;
  ctx.audit.record({
    actorId: user.id,
    actorUsername: user.username,
    action: 'auth.untrusted_ip',
    ip: addr,
    details: { policy: user.trusted_ip_policy, held: hold, ...(opts.verifiedByMfa ? { verifiedBy: 'mfa' } : {}) },
  });
  notify(
    ctx,
    log,
    user,
    hold
      ? `a sign-in from ${shown}, which is not on your trusted IP list, was held until it is verified`
      : `a sign-in from ${shown}, which is not on your trusted IP list${opts.verifiedByMfa ? ' (verified with your two-factor code)' : ''}`,
  );
  return { challenged: hold || session.ip_challenge === 1 };
}

/** Emails a one-time code that releases a held session. Returns false when throttled or there is no address. */
export function sendChallengeCode(ctx: AppContext, log: FastifyBaseLogger, user: UserRow, session: SessionRow): boolean {
  if (!user.email) return false;
  const existing = ctx.db.prepare('SELECT expires_at FROM ip_challenges WHERE session_hash = ?').get(session.id_hash) as
    | { expires_at: number }
    | undefined;
  if (existing && existing.expires_at - CODE_TTL_MS > Date.now() - CODE_RESEND_MS) return false;
  const code = String(randomInt(0, 100_000_000)).padStart(8, '0');
  ctx.db
    .prepare(
      `INSERT INTO ip_challenges (session_hash, code_hash, expires_at, attempts) VALUES (?, ?, ?, 0)
       ON CONFLICT(session_hash) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at, attempts = 0`,
    )
    .run(session.id_hash, sha256(code), Date.now() + CODE_TTL_MS);
  ctx.mailer
    .send(emails.ipChallenge({ to: user.email, displayName: user.display_name, code, ip: session.flagged_ip ?? 'unknown', minutes: CODE_TTL_MS / 60_000 }))
    .catch((err: unknown) => log.warn({ err }, 'Failed to send sign-in verification email'));
  return true;
}

/** Checks an emailed code. Burns the challenge after too many wrong tries (caller then ends the session). */
export function checkChallengeCode(ctx: AppContext, session: SessionRow, code: string): 'ok' | 'bad' | 'exhausted' {
  const row = ctx.db.prepare('SELECT * FROM ip_challenges WHERE session_hash = ?').get(session.id_hash) as
    | { code_hash: string; expires_at: number; attempts: number }
    | undefined;
  if (!row || row.expires_at < Date.now() || row.attempts >= MAX_CODE_ATTEMPTS) return 'exhausted';
  if (sha256(code) === row.code_hash) {
    ctx.db.prepare('DELETE FROM ip_challenges WHERE session_hash = ?').run(session.id_hash);
    return 'ok';
  }
  ctx.db.prepare('UPDATE ip_challenges SET attempts = attempts + 1 WHERE session_hash = ?').run(session.id_hash);
  return row.attempts + 1 >= MAX_CODE_ATTEMPTS ? 'exhausted' : 'bad';
}

export function newTrustedId(): string {
  return randomUUID();
}
