import type { FastifyBaseLogger, FastifyInstance } from 'fastify';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { TOKEN_TTL_MS, issueToken, notify, tokenUrl } from '../accountTokens.js';
import { changes } from '../audit.js';
import { assertIpAllowed, recordAuthFailure } from '../bruteForce.js';
import { randomToken, safeEqual } from '../crypto.js';
import { emails } from '../mail.js';
import { emailSchema } from './account.js';
import { HttpError, badRequest, clientIp, forbidden, idParam, notFound, parse, requireAdmin, requireUser } from '../http.js';
import { checkPasswordPolicy, generateTemporaryPassword, hashPassword } from '../passwords.js';
import { publicUser, type AppContext, type UserRow } from '../types.js';

const username = z
  .string()
  .trim()
  .min(2)
  .max(64)
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/, 'Use letters, numbers, dot, dash or underscore');
const displayName = z.string().trim().min(1).max(100);
const role = z.enum(['admin', 'user']);

const createUserBody = z.object({ username, displayName: displayName.optional(), email: emailSchema.optional(), role: role.default('user') });
const updateUserBody = z
  .object({
    displayName: displayName.optional(),
    email: emailSchema.nullable().optional(),
    role: role.optional(),
    status: z.enum(['active', 'disabled']).optional(),
  })
  .refine((b) => Object.keys(b).length > 0, 'Nothing to update');
const setupBody = z.object({
  setupToken: z.string().min(1).max(200),
  username,
  displayName: displayName.optional(),
  email: emailSchema.optional(),
  password: z.string().max(1024),
});

export function registerUserRoutes(app: FastifyInstance, ctx: AppContext, setup: { token: string | null }): void {
  const { db, audit, sessions, terminals } = ctx;

  const userCount = () => (db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number }).n;
  const activeAdminCount = () =>
    (db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND status = 'active'").get() as { n: number }).n;
  const findUser = (id: string) => db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;

  function assertEmailFree(email: string | null | undefined, exceptId = '') {
    if (email && db.prepare('SELECT 1 FROM users WHERE email = ? COLLATE NOCASE AND id != ?').get(email, exceptId)) {
      throw new HttpError(409, 'That email address is already in use.', 'conflict');
    }
  }

  function insertUser(u: {
    username: string;
    displayName: string;
    email?: string | undefined;
    role: 'admin' | 'user';
    passwordHash: string;
    mustChange: boolean;
  }) {
    const exists = db.prepare('SELECT 1 FROM users WHERE username = ?').get(u.username);
    if (exists) throw new HttpError(409, 'That username is taken.', 'conflict');
    assertEmailFree(u.email);
    const id = randomUUID();
    const now = Date.now();
    db.prepare(
      `INSERT INTO users (id, username, display_name, email, password_hash, role, must_change_password, password_changed_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, u.username, u.displayName, u.email ?? null, u.passwordHash, u.role, u.mustChange ? 1 : 0, now, now, now);
    return findUser(id)!;
  }

  // ---- First-run bootstrap: create the first administrator with the one-time token from the server log ----

  app.get('/api/setup', async () => ({ needed: userCount() === 0 }));

  app.post('/api/setup', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req) => {
    const body = parse(setupBody, req.body);
    assertIpAllowed(ctx, clientIp(req));
    if (userCount() > 0 || !setup.token) throw forbidden('Setup has already been completed.');
    if (!safeEqual(body.setupToken.trim(), setup.token)) {
      recordAuthFailure(ctx, req.log, clientIp(req), 'setup');
      audit.record({ action: 'setup.create_admin', outcome: 'failure', ip: clientIp(req) });
      throw forbidden('The setup token is incorrect.');
    }
    const problem = checkPasswordPolicy(body.password, body.username);
    if (problem) throw badRequest(problem);
    const user = insertUser({
      username: body.username,
      displayName: body.displayName ?? body.username,
      email: body.email,
      role: 'admin',
      passwordHash: await hashPassword(body.password),
      mustChange: false,
    });
    setup.token = null;
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'setup.create_admin', targetType: 'user', targetId: user.id, ip: clientIp(req) });
    return { user: publicUser(user) };
  });

  // ---- Directory: lets people find each other when sharing servers ----

  app.get('/api/users/directory', async (req) => {
    requireUser(req);
    const { q } = parse(z.object({ q: z.string().trim().max(64).default('') }), req.query);
    const like = `%${q.replace(/[%_\\]/g, (c) => `\\${c}`)}%`;
    const rows = db
      .prepare(
        `SELECT id, username, display_name FROM users
         WHERE status = 'active' AND (username LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\')
         ORDER BY username LIMIT 20`,
      )
      .all(like, like) as Pick<UserRow, 'id' | 'username' | 'display_name'>[];
    return { users: rows.map((r) => ({ id: r.id, username: r.username, displayName: r.display_name })) };
  });

  // ---- Administration ----

  app.get('/api/admin/users', async (req) => {
    requireAdmin(req);
    const rows = db.prepare('SELECT * FROM users ORDER BY username').all() as UserRow[];
    return {
      users: rows.map((u) => ({ ...publicUser(u), locked: u.locked_until !== null && u.locked_until > Date.now() })),
    };
  });

  /**
   * Emails a single-use link: an invite if they have never signed in, otherwise a password
   * reset. Without SMTP the link is returned to the admin to pass on, like a temporary password.
   */
  async function sendAccountLink(user: UserRow, invitedBy: string, log: FastifyBaseLogger) {
    const purpose = user.last_login_at === null ? 'invite' : 'reset';
    const url = tokenUrl(ctx, purpose, issueToken(ctx, user.id, purpose));
    const msg =
      purpose === 'invite'
        ? emails.invite({
            to: user.email!, displayName: user.display_name, username: user.username, invitedBy, url, hours: TOKEN_TTL_MS.invite / 3600_000,
          })
        : emails.passwordReset({
            to: user.email!, displayName: user.display_name, username: user.username, url, minutes: TOKEN_TTL_MS.reset / 60_000,
          });
    try {
      await ctx.mailer.send(msg);
    } catch (err) {
      log.warn({ err }, 'Failed to send account email');
      return { purpose, sent: false, error: 'The email could not be sent. Share this link with them yourself.', url };
    }
    return ctx.mailer.delivery === 'smtp' ? { purpose, sent: true } : { purpose, sent: false, url };
  }

  app.post('/api/admin/users', async (req) => {
    const admin = requireAdmin(req).user;
    const body = parse(createUserBody, req.body);
    const invite = !!body.email;
    // Invited users get an unusable random password until they follow their link.
    const temporaryPassword = invite ? null : generateTemporaryPassword();
    const user = insertUser({
      username: body.username,
      displayName: body.displayName ?? body.username,
      email: body.email,
      role: body.role,
      passwordHash: await hashPassword(temporaryPassword ?? randomToken(32)),
      mustChange: !invite,
    });
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_create', targetType: 'user', targetId: user.id,
      ip: clientIp(req), details: { username: user.username, role: user.role, email: user.email, invited: invite },
    });
    if (invite) return { user: publicUser(user), invite: await sendAccountLink(user, admin.display_name, req.log) };
    return { user: publicUser(user), temporaryPassword };
  });

  app.post('/api/admin/users/:id/send-link', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req) => {
    const admin = requireAdmin(req).user;
    const { id } = parse(idParam, req.params);
    const target = findUser(id);
    if (!target) throw notFound('User not found');
    if (!target.email) throw badRequest('This user has no email address.');
    if (target.status !== 'active') throw badRequest('This account is disabled.');
    const result = await sendAccountLink(target, admin.display_name, req.log);
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: `admin.user_send_${result.purpose}`, targetType: 'user', targetId: id,
      ip: clientIp(req), details: { username: target.username, sent: result.sent },
    });
    return result;
  });

  app.patch('/api/admin/users/:id', async (req) => {
    const admin = requireAdmin(req).user;
    const { id } = parse(idParam, req.params);
    const body = parse(updateUserBody, req.body);
    const target = findUser(id);
    if (!target) throw notFound('User not found');

    const losesAdmin =
      target.role === 'admin' && target.status === 'active' && (body.role === 'user' || body.status === 'disabled');
    if (target.id === admin.id && (body.role || body.status)) throw badRequest('You cannot change your own role or status.');
    if (losesAdmin && activeAdminCount() <= 1) throw badRequest('There must be at least one active administrator.');
    const emailChanging = body.email !== undefined && (body.email ?? null)?.toLowerCase() !== target.email?.toLowerCase();
    if (emailChanging) assertEmailFree(body.email, id);

    db.prepare(
      `UPDATE users SET display_name = COALESCE(?, display_name), role = COALESCE(?, role),
         status = COALESCE(?, status), email = ?, updated_at = ? WHERE id = ?`,
    ).run(body.displayName ?? null, body.role ?? null, body.status ?? null, emailChanging ? (body.email ?? null) : target.email, Date.now(), id);
    if (emailChanging) {
      db.prepare("DELETE FROM auth_tokens WHERE user_id = ? AND purpose = 'reset' AND used_at IS NULL").run(id);
      notify(ctx, req.log, target, `an administrator changed your email address to ${body.email ?? '(none)'}`, target.email ?? undefined);
    }
    if (body.status === 'disabled') db.prepare('DELETE FROM auth_tokens WHERE user_id = ? AND used_at IS NULL').run(id);

    if (body.status === 'disabled' || (body.role && body.role !== target.role)) {
      // Privilege changes take effect immediately: drop sessions and live terminals.
      sessions.destroyAllForUser(id);
      terminals.closeForUser(id, 'Your account was changed by an administrator.');
    }
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_update', targetType: 'user', targetId: id,
      ip: clientIp(req),
      details: {
        username: target.username,
        changes: changes(
          { displayName: target.display_name, role: target.role, status: target.status, email: target.email },
          { displayName: body.displayName ?? target.display_name, role: body.role ?? target.role, status: body.status ?? target.status, email: emailChanging ? (body.email ?? null) : target.email },
        ),
      },
    });
    return { user: publicUser(findUser(id)!) };
  });

  app.post('/api/admin/users/:id/reset-password', async (req) => {
    const admin = requireAdmin(req).user;
    const { id } = parse(idParam, req.params);
    const target = findUser(id);
    if (!target) throw notFound('User not found');
    if (target.id === admin.id) throw badRequest('Use your account page to change your own password.');
    const temporaryPassword = generateTemporaryPassword();
    const now = Date.now();
    db.prepare(
      `UPDATE users SET password_hash = ?, must_change_password = 1, failed_logins = 0, locked_until = NULL,
         password_changed_at = ?, updated_at = ? WHERE id = ?`,
    ).run(await hashPassword(temporaryPassword), now, now, id);
    sessions.destroyAllForUser(id);
    terminals.closeForUser(id, 'Your password was reset by an administrator.');
    notify(ctx, req.log, target, 'an administrator reset your password');
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_reset_password', targetType: 'user', targetId: id,
      ip: clientIp(req), details: { username: target.username },
    });
    return { temporaryPassword };
  });

  app.post('/api/admin/users/:id/reset-mfa', async (req) => {
    const admin = requireAdmin(req).user;
    const { id } = parse(idParam, req.params);
    const target = findUser(id);
    if (!target) throw notFound('User not found');
    db.prepare(
      'UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_last_counter = NULL, updated_at = ? WHERE id = ?',
    ).run(Date.now(), id);
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(id);
    sessions.destroyAllForUser(id);
    notify(ctx, req.log, target, 'an administrator turned off your two-factor authentication');
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_reset_mfa', targetType: 'user', targetId: id,
      ip: clientIp(req), details: { username: target.username },
    });
    return { ok: true };
  });

  // Recovery for someone held out by their trusted IP list (for example after moving house).
  app.post('/api/admin/users/:id/reset-trusted-ips', async (req) => {
    const admin = requireAdmin(req).user;
    const { id } = parse(idParam, req.params);
    const target = findUser(id);
    if (!target) throw notFound('User not found');
    db.prepare('UPDATE users SET trusted_ip_enabled = 0, updated_at = ? WHERE id = ?').run(Date.now(), id);
    db.prepare('UPDATE sessions SET ip_challenge = 0 WHERE user_id = ?').run(id);
    notify(ctx, req.log, target, 'an administrator turned off your trusted IP list');
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_reset_trusted_ips', targetType: 'user', targetId: id,
      ip: clientIp(req), details: { username: target.username },
    });
    return { ok: true };
  });

  app.post('/api/admin/users/:id/unlock', async (req) => {
    const admin = requireAdmin(req).user;
    const { id } = parse(idParam, req.params);
    const target = findUser(id);
    if (!target) throw notFound('User not found');
    db.prepare('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?').run(id);
    ctx.bruteForce.clearUser(id);
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_unlock', targetType: 'user', targetId: id,
      ip: clientIp(req), details: { username: target.username, wasLocked: target.locked_until !== null && target.locked_until > Date.now() },
    });
    return { ok: true };
  });

  app.get('/api/admin/lockouts', async (req) => {
    requireAdmin(req);
    return { ips: ctx.bruteForce.listIpLockouts() };
  });

  app.delete('/api/admin/lockouts/ip/:ip', async (req) => {
    const admin = requireAdmin(req).user;
    const { ip } = parse(z.object({ ip: z.string().min(2).max(64) }), req.params);
    if (!ctx.bruteForce.unlockIp(ip)) throw notFound('That address is not locked out');
    audit.record({ actorId: admin.id, actorUsername: admin.username, action: 'admin.ip_unlock', targetType: 'ip', targetId: ip, ip: clientIp(req) });
    return { ok: true };
  });

  app.get('/api/admin/audit', async (req) => {
    requireAdmin(req);
    const q = parse(
      z.object({
        limit: z.coerce.number().int().min(1).max(500).default(100),
        before: z.coerce.number().int().positive().optional(),
        action: z.string().max(64).optional(),
        actorId: z.uuid().optional(),
      }),
      req.query,
    );
    const rows = audit.list({ limit: q.limit, beforeSeq: q.before, action: q.action, actorId: q.actorId });
    return {
      entries: rows.map((r) => ({
        seq: r.seq, ts: r.ts, actorId: r.actor_id, actorUsername: r.actor_username, action: r.action,
        targetType: r.target_type, targetId: r.target_id, ip: r.ip, outcome: r.outcome, details: JSON.parse(r.details),
      })),
    };
  });

  app.get('/api/admin/audit/verify', async (req) => {
    requireAdmin(req);
    return audit.verify();
  });
}
