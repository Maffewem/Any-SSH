import type { FastifyInstance, FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { notify } from '../accountTokens.js';
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
import { assertIpAllowed, recordAuthFailure, recordReauthFailure } from '../bruteForce.js';
import { checkChallengeCode, checkSessionIp, sendChallengeCode } from '../ipTrust.js';
import { checkPasswordPolicy, hashPassword, needsRehash, verifyDummy, verifyPassword } from '../passwords.js';
import {
  generateRecoveryCodes,
  generateTotpSecret,
  normalizeRecoveryCode,
  totpUri,
  verifyTotp,
} from '../totp.js';
import { publicUser, type AppContext, type UserRow } from '../types.js';

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

  function completeLogin(user: UserRow, ip: string, ua: string | null): string {
    db.prepare('UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE id = ?').run(
      Date.now(),
      user.id,
    );
    ctx.bruteForce.clearUser(user.id);
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
    assertIpAllowed(ctx, ip);
    const ua = req.headers['user-agent'] ?? null;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(body.username) as UserRow | undefined;

    if (!user) {
      await verifyDummy(body.password);
      recordAuthFailure(ctx, req.log, ip, 'login');
      audit.record({ action: 'auth.login', outcome: 'failure', ip, details: { username: body.username, reason: 'unknown_user' } });
      throw new HttpError(401, GENERIC_LOGIN_ERROR, 'invalid_credentials');
    }

    const locked = user.locked_until !== null && user.locked_until > Date.now();
    const passwordOk = await verifyPassword(user.password_hash, body.password);
    if (locked || !passwordOk || user.status !== 'active') {
      if (!locked && !passwordOk) recordAuthFailure(ctx, req.log, ip, 'login', user);
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

    const token = completeLogin(user, ip, ua);
    setSessionCookie(ctx, reply, token);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.login', ip });
    const created = sessions.resolve(token)!;
    const { challenged } = checkSessionIp(ctx, req.log, created.user, created.session, ip);
    return { mfaRequired: false, ipChallenge: challenged, user: publicUser(getUser(user.id)) };
  });

  app.post('/api/auth/mfa', loginRateLimit, async (req, reply) => {
    const auth = req.auth;
    if (!auth || auth.session.stage !== 'mfa') throw new HttpError(401, 'Your session has ended. Sign in again.', 'unauthenticated');
    const body = parse(mfaBody, req.body);
    const ip = clientIp(req);
    assertIpAllowed(ctx, ip);
    const user = auth.user;

    const ok = 'code' in body ? checkTotp(user, body.code) : useRecoveryCode(user, body.recoveryCode);
    if (!ok) {
      recordAuthFailure(ctx, req.log, ip, 'mfa', user);
      const fresh = getUser(user.id);
      // Too many bad codes: throw away the half-finished login so the password is needed again.
      if (fresh.locked_until && fresh.locked_until > Date.now()) sessions.destroyByHash(auth.session.id_hash);
      audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.mfa', outcome: 'failure', ip });
      throw new HttpError(401, 'That code is not valid.', 'invalid_mfa');
    }

    // New token after the second factor: the pre-MFA cookie value is never promoted.
    sessions.destroyByHash(auth.session.id_hash);
    const token = completeLogin(user, ip, req.headers['user-agent'] ?? null);
    setSessionCookie(ctx, reply, token);
    // A fresh second-factor code is the proof the trusted-IP challenge asks for, so the sign-in is
    // let through; the user is still told it came from an unlisted address.
    const created = sessions.resolve(token)!;
    checkSessionIp(ctx, req.log, created.user, created.session, ip, { verifiedByMfa: true });
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
    if (!auth) throw new HttpError(401, 'You are not signed in.', 'unauthenticated');
    if (auth.session.stage === 'mfa') return { mfaRequired: true };
    // A locked session learns only enough to draw the lock screen.
    if (auth.session.locked_at !== null) return { locked: true, username: auth.user.username, displayName: auth.user.display_name };
    return { user: publicUser(auth.user), ipChallenge: auth.session.ip_challenge === 1 };
  });

  // ---- Idle lock ----

  // Polled by the browser to decide when to show the lock screen. Not counted as activity.
  app.get('/api/auth/state', async (req) => {
    const auth = req.auth;
    if (!auth || auth.session.stage !== 'full') throw new HttpError(401, 'You are not signed in.', 'unauthenticated');
    if (auth.session.locked_at !== null) return { locked: true };
    return { locked: false, msUntilLock: sessions.msUntilLock(auth.session) };
  });

  // The browser reports keyboard/pointer activity that made no other request (reading, scrolling).
  app.post('/api/auth/heartbeat', async (req) => {
    requireUser(req, { allowPendingPasswordChange: true });
    return { ok: true };
  });

  app.post('/api/auth/lock', async (req) => {
    const { user, session } = requireUser(req, { allowPendingPasswordChange: true });
    sessions.lock(session);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.lock', ip: clientIp(req) });
    return { ok: true };
  });

  // Unlocking needs only the account password: the session already passed 2FA when it signed in,
  // and the idle sign-out and absolute lifetime still apply. Repeated failures end the session.
  app.post('/api/auth/unlock', loginRateLimit, async (req, reply) => {
    const auth = req.auth;
    if (!auth || auth.session.stage !== 'full') throw new HttpError(401, 'Your session has ended. Sign in again.', 'unauthenticated');
    const { user, session } = auth;
    if (session.locked_at === null) return { user: publicUser(user) };
    const { password } = parse(confirmPasswordBody, req.body);
    const ip = clientIp(req);
    assertIpAllowed(ctx, ip);
    const accountLocked = user.locked_until !== null && user.locked_until > Date.now();
    if (accountLocked || !(await verifyPassword(user.password_hash, password))) {
      if (!accountLocked) recordAuthFailure(ctx, req.log, ip, 'unlock', user);
      const ended = accountLocked || sessions.unlockFailed(session) || getUser(user.id).locked_until !== null;
      if (ended) sessions.destroyByHash(session.id_hash);
      audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.unlock', outcome: 'failure', ip, details: { ended } });
      if (ended) {
        clearSessionCookie(ctx, reply);
        throw new HttpError(401, 'Too many attempts. Sign in again.', 'unauthenticated');
      }
      throw new HttpError(401, 'The password is incorrect.', 'invalid_credentials');
    }
    sessions.unlock(session);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.unlock', ip });
    return { user: publicUser(user) };
  });

  app.post('/api/auth/password', async (req, reply) => {
    const { user, session } = requireUser(req, { allowPendingPasswordChange: true });
    const body = parse(passwordBody, req.body);
    if (!(await verifyPassword(user.password_hash, body.currentPassword))) {
      recordReauthFailure(ctx, req.log, clientIp(req), user);
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
    notify(ctx, req.log, user, 'your password was changed');
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
    if (!(await verifyPassword(user.password_hash, body.password))) {
      recordReauthFailure(ctx, req.log, clientIp(req), user);
      audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.mfa_setup', outcome: 'failure', ip: clientIp(req) });
      throw badRequest('Password is incorrect.');
    }
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
    if (!user.totp_secret_enc) throw badRequest('Begin two-factor setup first.');
    if (!checkTotp(user, code)) throw badRequest('That code is not valid. Check the time on your device.');
    db.prepare('UPDATE users SET totp_enabled = 1, updated_at = ? WHERE id = ?').run(Date.now(), user.id);
    const recoveryCodes = issueRecoveryCodes(user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.mfa_enable', ip: clientIp(req) });
    notify(ctx, req.log, user, 'two-factor authentication was turned on');
    return { recoveryCodes };
  });

  app.post('/api/auth/mfa/disable', async (req) => {
    const { user } = requireUser(req);
    const body = parse(confirmPasswordAndCodeBody, req.body);
    if (!user.totp_enabled) throw badRequest('Two-factor authentication is not on.');
    if (!(await verifyPassword(user.password_hash, body.password)) || !checkTotp(user, body.code)) {
      recordReauthFailure(ctx, req.log, clientIp(req), user);
      audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.mfa_disable', outcome: 'failure', ip: clientIp(req) });
      throw badRequest('Password or code is incorrect.');
    }
    db.prepare(
      'UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_last_counter = NULL, updated_at = ? WHERE id = ?',
    ).run(Date.now(), user.id);
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.mfa_disable', ip: clientIp(req) });
    notify(ctx, req.log, user, 'two-factor authentication was turned off');
    return { ok: true };
  });

  app.post('/api/auth/mfa/recovery-codes', async (req) => {
    const { user } = requireUser(req);
    const body = parse(confirmPasswordAndCodeBody, req.body);
    if (!user.totp_enabled) throw badRequest('Two-factor authentication is not on.');
    if (!(await verifyPassword(user.password_hash, body.password)) || !checkTotp(user, body.code)) {
      recordReauthFailure(ctx, req.log, clientIp(req), user);
      audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.recovery_codes_regenerate', outcome: 'failure', ip: clientIp(req) });
      throw badRequest('Password or code is incorrect.');
    }
    const recoveryCodes = issueRecoveryCodes(user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.recovery_codes_regenerate', ip: clientIp(req) });
    notify(ctx, req.log, user, 'new two-factor recovery codes were generated (the old ones no longer work)');
    return { recoveryCodes };
  });

  // ---- Trusted IP challenge: releases a session held because it came from an unlisted address ----

  const challengeLimit = { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } };
  const challengeBody = z.union([
    z.object({ code: z.string().trim().regex(/^\d{6,8}$/, 'Enter the code') }),
    z.object({ recoveryCode: z.string().trim().min(8).max(32) }),
  ]);

  function heldSession(req: FastifyRequest) {
    const auth = requireUser(req, { allowIpChallenge: true, allowPendingPasswordChange: true });
    if (auth.session.ip_challenge !== 1) throw badRequest('This sign-in does not need verifying.');
    return auth;
  }

  app.get('/api/auth/ip-challenge', async (req) => {
    const { user, session } = heldSession(req);
    return {
      ip: session.flagged_ip,
      methods: [...(user.totp_enabled ? ['totp'] : []), ...(user.email ? ['email'] : [])],
    };
  });

  app.post('/api/auth/ip-challenge/send', challengeLimit, async (req) => {
    const { user, session } = heldSession(req);
    if (!user.email) throw badRequest('No email address on this account. Use your authenticator app, or ask an administrator.');
    const sent = sendChallengeCode(ctx, req.log, user, session);
    return { sent };
  });

  app.post('/api/auth/ip-challenge/verify', challengeLimit, async (req) => {
    const { user, session } = heldSession(req);
    const body = parse(challengeBody, req.body);
    const ip = clientIp(req);
    assertIpAllowed(ctx, ip);
    let ok = false;
    let method = 'email';
    if ('recoveryCode' in body) {
      method = 'recovery_code';
      ok = user.totp_enabled === 1 && useRecoveryCode(user, body.recoveryCode);
    } else if (user.totp_enabled && checkTotp(user, body.code)) {
      method = 'totp';
      ok = true;
    } else if (body.code.length === 8) {
      const res = checkChallengeCode(ctx, session, body.code);
      ok = res === 'ok';
      if (res === 'exhausted') {
        audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.ip_challenge', outcome: 'failure', ip, details: { reason: 'too_many_attempts' } });
        sessions.destroyByHash(session.id_hash);
        throw new HttpError(401, 'Too many wrong codes. Sign in again.', 'unauthenticated');
      }
    }
    if (!ok) {
      recordAuthFailure(ctx, req.log, ip, 'challenge', user);
      audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.ip_challenge', outcome: 'failure', ip });
      const fresh = getUser(user.id);
      if (fresh.locked_until && fresh.locked_until > Date.now()) sessions.destroyByHash(session.id_hash);
      throw new HttpError(400, 'That code is not valid.', 'invalid_code');
    }
    db.prepare('UPDATE sessions SET ip_challenge = 0 WHERE id_hash = ?').run(session.id_hash);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.ip_challenge', ip, details: { method } });
    return { user: publicUser(getUser(user.id)), ip: session.flagged_ip };
  });
}
