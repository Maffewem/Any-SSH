import type { FastifyInstance } from 'fastify';
import { randomInt, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { TOKEN_TTL_MS, consumeToken, findVerifyToken, issueToken, tokenUrl } from '../accountTokens.js';
import { assertIpAllowed, recordAuthFailure } from '../bruteForce.js';
import { HttpError, badRequest, clientIp, idParam, notFound, parse, requireAdmin } from '../http.js';
import { emails } from '../mail.js';
import { checkPasswordPolicy, hashPassword } from '../passwords.js';
import { requireHuman } from '../turnstile.js';
import { publicUser, type AppContext, type UserRow } from '../types.js';
import { emailSchema } from './account.js';

/** More waiting registrations than this and sign-ups pause, so a flood can’t fill the user table. */
const MAX_UNVERIFIED = 500;

const registerBody = z.object({
  displayName: z.string().trim().min(1, 'Enter your name').max(100),
  email: emailSchema,
  password: z.string().max(1024),
  captchaToken: z.string().max(2048).optional(),
});

/** Self-service account creation, email verification and the admin approval queue. */
export function registerRegistrationRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { db, audit, settings } = ctx;
  const strict = { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } };

  /** What the sign-in and Create account pages need before anyone is signed in. No secrets. */
  app.get('/api/auth/config', async () => {
    const t = settings.turnstile;
    return {
      registration: settings.registration.mode,
      turnstile: settings.turnstileConfigured && (t.signup || t.reset || t.login) ? { siteKey: t.siteKey, signup: t.signup, reset: t.reset, login: t.login } : null,
    };
  });

  /** A free username derived from the email address (people sign in with their email, so it is rarely typed). */
  function availableUsername(email: string, exceptId = ''): string {
    let base = (email.split('@')[0] ?? '').toLowerCase().replace(/[^a-z0-9._-]+/g, '.').replace(/^[^a-z0-9]+|[^a-z0-9]+$/g, '').slice(0, 40);
    if (base.length < 2) base = 'user';
    let candidate = base;
    while (db.prepare('SELECT 1 FROM users WHERE username = ? AND id != ?').get(candidate, exceptId)) candidate = `${base}${randomInt(1000, 10000)}`;
    return candidate;
  }

  app.post('/api/auth/register', strict, async (req) => {
    const body = parse(registerBody, req.body);
    const ip = clientIp(req);
    assertIpAllowed(ctx, ip);
    const mode = settings.registration.mode;
    if (mode === 'invite') throw new HttpError(403, 'Creating an account isn’t available. Ask an administrator for an invitation.', 'registration_closed');
    if (settings.mail.smtp === null) throw new HttpError(503, 'Creating an account isn’t available right now.', 'registration_unavailable');
    await requireHuman(ctx, req, 'signup', body.captchaToken);

    const existing = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(body.email) as UserRow | undefined;
    const username = availableUsername(body.email, existing?.registration_state === 'unverified' ? existing.id : '');
    const problem = checkPasswordPolicy(body.password, username);
    if (problem) throw badRequest(problem);
    // Hashed before looking for an existing account, so the response time doesn't reveal one.
    const passwordHash = await hashPassword(body.password);

    if (existing && existing.registration_state !== 'unverified') {
      // The same answer as a new registration; the address owner is told by email instead.
      ctx.mailer.send(emails.registrationExists({ to: existing.email! })).catch((err: unknown) => req.log.warn({ err }, 'Failed to send registration notice'));
      audit.record({ action: 'auth.register', outcome: 'failure', ip, details: { reason: 'email_in_use' } });
      return { ok: true };
    }
    const waiting = (db.prepare("SELECT COUNT(*) AS n FROM users WHERE registration_state = 'unverified'").get() as { n: number }).n;
    if (waiting >= MAX_UNVERIFIED && !existing) throw new HttpError(429, 'Too many accounts are waiting to be confirmed. Try again later.', 'rate_limited');

    const now = Date.now();
    const id = randomUUID();
    db.transaction(() => {
      // Registering again before confirming replaces the earlier, never-used attempt.
      if (existing) db.prepare('DELETE FROM users WHERE id = ?').run(existing.id);
      db.prepare(
        `INSERT INTO users (id, username, display_name, email, password_hash, role, status, registration_state, must_change_password, password_changed_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'user', 'disabled', 'unverified', 0, ?, ?, ?)`,
      ).run(id, username, body.displayName, body.email, passwordHash, now, now, now);
    })();

    const token = issueToken(ctx, id, 'verify');
    ctx.mailer
      .send(emails.verifyEmail({ to: body.email, displayName: body.displayName, url: tokenUrl(ctx, 'verify', token), hours: TOKEN_TTL_MS.verify / 3600_000 }))
      .catch((err: unknown) => req.log.warn({ err }, 'Failed to send verification email'));
    audit.record({ actorId: id, actorUsername: username, action: 'auth.register', targetType: 'user', targetId: id, ip, details: { mode } });
    return { ok: true };
  });

  app.post('/api/auth/verify', strict, async (req) => {
    const { token } = parse(z.object({ token: z.string().min(1).max(100) }), req.body);
    const ip = clientIp(req);
    assertIpAllowed(ctx, ip);
    const found = findVerifyToken(ctx, token);
    if (!found) {
      recordAuthFailure(ctx, req.log, ip, 'register');
      throw new HttpError(400, 'This link isn’t valid or has expired. Create your account again to get a new one.', 'invalid_token');
    }
    const { row, user } = found;
    if (!consumeToken(ctx, row.token_hash)) throw new HttpError(400, 'This link has already been used.', 'invalid_token');

    const now = Date.now();
    const open = settings.registration.mode === 'open';
    db.prepare(
      `UPDATE users SET email_verified_at = ?, status = ?, registration_state = ?, updated_at = ? WHERE id = ?`,
    ).run(now, open ? 'active' : 'disabled', open ? null : 'pending_approval', now, user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.email_verified', targetType: 'user', targetId: user.id, ip, details: { result: open ? 'active' : 'pending_approval' } });

    if (!open) {
      const admins = db.prepare("SELECT * FROM users WHERE role = 'admin' AND status = 'active' AND email IS NOT NULL").all() as UserRow[];
      for (const admin of admins) {
        ctx.mailer
          .send(emails.approvalNeeded({ to: admin.email!, displayName: admin.display_name, applicant: user.display_name, email: user.email!, url: `${ctx.config.publicUrl}/#/users` }))
          .catch((err: unknown) => req.log.warn({ err }, 'Failed to send approval notice'));
      }
    }
    return { status: open ? 'active' : 'pending_approval' };
  });

  // ---- Approval queue (administrators) ----

  const pendingUser = (id: string): UserRow => {
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
    if (!u) throw notFound('User not found.');
    return u;
  };

  app.post('/api/admin/users/:id/approve', async (req) => {
    const { user: admin } = requireAdmin(req);
    const { id } = parse(idParam, req.params);
    const target = pendingUser(id);
    if (target.registration_state !== 'pending_approval') throw badRequest('This account isn’t waiting for approval.');
    db.prepare("UPDATE users SET status = 'active', registration_state = NULL, updated_at = ? WHERE id = ?").run(Date.now(), id);
    audit.record({ actorId: admin.id, actorUsername: admin.username, action: 'admin.user_approve', targetType: 'user', targetId: id, ip: clientIp(req), details: { username: target.username } });
    if (target.email) {
      ctx.mailer
        .send(emails.accountApproved({ to: target.email, displayName: target.display_name, url: ctx.config.publicUrl }))
        .catch((err: unknown) => req.log.warn({ err }, 'Failed to send approval email'));
    }
    return { user: publicUser(pendingUser(id)) };
  });

  app.post('/api/admin/users/:id/reject', async (req) => {
    const { user: admin } = requireAdmin(req);
    const { id } = parse(idParam, req.params);
    const target = pendingUser(id);
    if (!target.registration_state) throw badRequest('Only accounts that registered themselves can be declined.');
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    audit.record({ actorId: admin.id, actorUsername: admin.username, action: 'admin.user_reject', targetType: 'user', targetId: id, ip: clientIp(req), details: { username: target.username, email: target.email } });
    return { ok: true };
  });
}
