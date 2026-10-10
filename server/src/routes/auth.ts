import type { FastifyInstance } from 'fastify';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { sha256 } from '../crypto.js';
import {
  HttpError,
  badRequest,
  clearSessionCookie,
  clientIp,
  parse,
  requireUser,
  sessionToken,
  setSessionCookie,
} from '../http.js';
import { checkPasswordPolicy, hashPassword, needsRehash, verifyDummy, verifyPassword } from '../passwords.js';
import {
  generateRecoveryCodes,
  generateTotpSecret,
  normalizeRecoveryCode,
  totpUri,
  verifyTotp,
} from '../totp.js';
import { publicUser, type AppContext, type UserRow } from '../types.js';

const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const GENERIC_LOGIN_ERROR = 'Invalid username or password.';

const loginBody = z.object({
  username: z.string().trim().min(1).max(64),
  password: z.string().min(1).max(1024),
});
const mfaBody = z.union([
  z.object({ code: z.string().trim().regex(/^\d{6}$/, 'Enter the 6-digit code') }),
  z.object({ recoveryCode: z.string().trim().min(8).max(32) }),
]);
const passwordBody = z.object({ currentPassword: z.string().min(1).max(1024), newPassword: z.string().max(1024) });
const confirmPasswordBody = z.object({ password: z.string().min(1).max(1024) });
const confirmPasswordAndCodeBody = z.object({
  password: z.string().min(1).max(1024),
  code: z.string().trim().regex(/^\d{6}$/, 'Enter the 6-digit code'),
});

export function registerAuthRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { db, sessions, audit, box } = ctx;
  const totpContext = (userId: string) => `user:${userId}:totp`;

  const getUser = (id: string) => db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow;

  function registerFailure(user: UserRow): void {
    const failures = user.failed_logins + 1;
    const lockedUntil = failures % LOCKOUT_THRESHOLD === 0 ? Date.now() + LOCKOUT_MS : user.locked_until;
    db.prepare('UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?').run(failures, lockedUntil, user.id);
  }

  function completeLogin(user: UserRow, ip: string, ua: string | null): string {
    db.prepare('UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE id = ?').run(
      Date.now(),
      user.id,
    );
    return sessions.create(user.id, 'full', ip, ua);
  }

  function checkTotp(user: UserRow, code: string): boolean {
    if (!user.totp_secret_enc) return false;
    const secret = box.openString(user.totp_secret_enc, totpContext(user.id));
    const counter = verifyTotp(secret, code, user.totp_last_counter);
    if (counter === null) return false;
    db.prepare('UPDATE users SET totp_last_counter = ? WHERE id = ?').run(counter, user.id);
    return true;
  }

  function useRecoveryCode(user: UserRow, code: string): boolean {
    const hash = sha256(normalizeRecoveryCode(code));
    const res = db
      .prepare('UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL')
      .run(Date.now(), user.id, hash);
    return res.changes === 1;
  }

  function issueRecoveryCodes(userId: string): string[] {
    const codes = generateRecoveryCodes();
    db.transaction(() => {
      db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId);
      const ins = db.prepare('INSERT INTO recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)');
      for (const c of codes) ins.run(randomUUID(), userId, sha256(normalizeRecoveryCode(c)));
    })();
    return codes;
  }

  const loginRateLimit = { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } };

  app.post('/api/auth/login', loginRateLimit, async (req, reply) => {
    const body = parse(loginBody, req.body);
    const ip = clientIp(req);
    const ua = req.headers['user-agent'] ?? null;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(body.username) as UserRow | undefined;

    if (!user) {
      await verifyDummy(body.password);
      audit.record({ action: 'auth.login', outcome: 'failure', ip, details: { username: body.username, reason: 'unknown_user' } });
      throw new HttpError(401, GENERIC_LOGIN_ERROR, 'invalid_credentials');
    }

    const locked = user.locked_until !== null && user.locked_until > Date.now();
    const passwordOk = await verifyPassword(user.password_hash, body.password);
    if (locked || !passwordOk || user.status !== 'active') {
      if (!locked && !passwordOk) registerFailure(user);
      const reason = locked ? 'locked' : !passwordOk ? 'bad_password' : 'disabled';
      audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.login', outcome: 'failure', ip, details: { reason } });
      throw new HttpError(401, GENERIC_LOGIN_ERROR, 'invalid_credentials');
    }

    if (needsRehash(user.password_hash)) {
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await hashPassword(body.password), user.id);
    }

    const existing = sessionToken(ctx, req);
    if (existing) sessions.destroy(existing);

    if (user.totp_enabled) {
      setSessionCookie(ctx, reply, sessions.create(user.id, 'mfa', ip, ua));
      audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.password_ok', ip, details: { mfa: 'pending' } });
      return { mfaRequired: true };
    }

    setSessionCookie(ctx, reply, completeLogin(user, ip, ua));
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.login', ip });
    return { mfaRequired: false, user: publicUser(getUser(user.id)) };
  });

  app.post('/api/auth/mfa', loginRateLimit, async (req, reply) => {
    const auth = req.auth;
    if (!auth || auth.session.stage !== 'mfa') throw new HttpError(401, 'Sign in again', 'unauthenticated');
    const body = parse(mfaBody, req.body);
    const ip = clientIp(req);
    const user = auth.user;

    const ok = 'code' in body ? checkTotp(user, body.code) : useRecoveryCode(user, body.recoveryCode);
    if (!ok) {
      registerFailure(user);
      const fresh = getUser(user.id);
      // Too many bad codes: throw away the half-finished login so the password is needed again.
      if (fresh.locked_until && fresh.locked_until > Date.now()) sessions.destroyByHash(auth.session.id_hash);
      audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.mfa', outcome: 'failure', ip });
      throw new HttpError(401, 'That code is not valid.', 'invalid_mfa');
    }

    // New token after the second factor: the pre-MFA cookie value is never promoted.
    sessions.destroyByHash(auth.session.id_hash);
    setSessionCookie(ctx, reply, completeLogin(user, ip, req.headers['user-agent'] ?? null));
    audit.record({
      actorId: user.id,
      actorUsername: user.username,
      action: 'auth.login',
      ip,
      details: { mfa: 'code' in body ? 'totp' : 'recovery_code' },
    });
    return { user: publicUser(getUser(user.id)) };
  });

  app.post('/api/auth/logout', async (req, reply) => {
    const token = sessionToken(ctx, req);
    if (token) sessions.destroy(token);
    clearSessionCookie(ctx, reply);
    if (req.auth) audit.record({ actorId: req.auth.user.id, actorUsername: req.auth.user.username, action: 'auth.logout', ip: clientIp(req) });
    return { ok: true };
  });

  app.get('/api/auth/me', async (req) => {
    const auth = req.auth;
    if (!auth) throw new HttpError(401, 'Not signed in', 'unauthenticated');
    if (auth.session.stage === 'mfa') return { mfaRequired: true };
    return { user: publicUser(auth.user) };
  });

  app.post('/api/auth/password', async (req, reply) => {
    const { user, session } = requireUser(req, { allowPendingPasswordChange: true });
    const body = parse(passwordBody, req.body);
    if (!(await verifyPassword(user.password_hash, body.currentPassword))) {
      audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.password_change', outcome: 'failure', ip: clientIp(req) });
      throw badRequest('Current password is incorrect.');
    }
    const problem = checkPasswordPolicy(body.newPassword, user.username);
    if (problem) throw badRequest(problem);
    if (body.newPassword === body.currentPassword) throw badRequest('Choose a different password.');

    const now = Date.now();
    db.prepare(
      'UPDATE users SET password_hash = ?, must_change_password = 0, password_changed_at = ?, updated_at = ? WHERE id = ?',
    ).run(await hashPassword(body.newPassword), now, now, user.id);
    // Sign out everywhere else, and rotate this session's token.
    sessions.destroyAllForUser(user.id, session.id_hash);
    sessions.destroyByHash(session.id_hash);
    setSessionCookie(ctx, reply, sessions.create(user.id, 'full', clientIp(req), req.headers['user-agent'] ?? null));
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.password_change', ip: clientIp(req) });
    return { user: publicUser(getUser(user.id)) };
  });

  // ---- Sessions (devices) ----

  app.get('/api/auth/sessions', async (req) => {
    const { user, session } = requireUser(req);
    return {
      sessions: sessions.listForUser(user.id).map((s) => ({
        id: s.id_hash,
        current: s.id_hash === session.id_hash,
        createdAt: s.created_at,
        lastSeenAt: s.last_seen_at,
        ip: s.ip,
        userAgent: s.user_agent,
      })),
    };
  });

  app.delete('/api/auth/sessions/:id', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(z.object({ id: z.string().regex(/^[0-9a-f]{64}$/) }), req.params);
    const res = db.prepare('SELECT 1 FROM sessions WHERE id_hash = ? AND user_id = ?').get(id, user.id);
    if (res) sessions.destroyByHash(id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.session_revoke', ip: clientIp(req) });
    return { ok: true };
  });

  // ---- MFA enrolment ----

  app.post('/api/auth/mfa/setup', async (req) => {
    const { user } = requireUser(req);
    const body = parse(confirmPasswordBody, req.body);
    if (!(await verifyPassword(user.password_hash, body.password))) throw badRequest('Password is incorrect.');
    if (user.totp_enabled) throw badRequest('Two-factor authentication is already on.');
    const secret = generateTotpSecret();
    db.prepare('UPDATE users SET totp_secret_enc = ?, totp_last_counter = NULL WHERE id = ?').run(
      box.seal(secret, totpContext(user.id)),
      user.id,
    );
    return { secret, uri: totpUri(secret, user.username) };
  });

  app.post('/api/auth/mfa/enable', async (req) => {
    const { user } = requireUser(req);
    const { code } = parse(z.object({ code: z.string().trim().regex(/^\d{6}$/, 'Enter the 6-digit code') }), req.body);
    if (user.totp_enabled) throw badRequest('Two-factor authentication is already on.');
    if (!user.totp_secret_enc) throw badRequest('Start setup first.');
    if (!checkTotp(user, code)) throw badRequest('That code is not valid. Check the time on your device.');
    db.prepare('UPDATE users SET totp_enabled = 1, updated_at = ? WHERE id = ?').run(Date.now(), user.id);
    const recoveryCodes = issueRecoveryCodes(user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.mfa_enable', ip: clientIp(req) });
    return { recoveryCodes };
  });

  app.post('/api/auth/mfa/disable', async (req) => {
    const { user } = requireUser(req);
    const body = parse(confirmPasswordAndCodeBody, req.body);
    if (!user.totp_enabled) throw badRequest('Two-factor authentication is not on.');
    if (!(await verifyPassword(user.password_hash, body.password)) || !checkTotp(user, body.code)) {
      audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.mfa_disable', outcome: 'failure', ip: clientIp(req) });
      throw badRequest('Password or code is incorrect.');
    }
    db.prepare(
      'UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_last_counter = NULL, updated_at = ? WHERE id = ?',
    ).run(Date.now(), user.id);
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.mfa_disable', ip: clientIp(req) });
    return { ok: true };
  });

  app.post('/api/auth/mfa/recovery-codes', async (req) => {
    const { user } = requireUser(req);
    const body = parse(confirmPasswordAndCodeBody, req.body);
    if (!user.totp_enabled) throw badRequest('Two-factor authentication is not on.');
    if (!(await verifyPassword(user.password_hash, body.password)) || !checkTotp(user, body.code)) {
      throw badRequest('Password or code is incorrect.');
    }
    const recoveryCodes = issueRecoveryCodes(user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.recovery_codes_regenerate', ip: clientIp(req) });
    return { recoveryCodes };
  });
}
