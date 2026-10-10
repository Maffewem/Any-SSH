import type { FastifyInstance } from 'fastify';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { safeEqual } from '../crypto.js';
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

const createUserBody = z.object({ username, displayName: displayName.optional(), role: role.default('user') });
const updateUserBody = z
  .object({ displayName: displayName.optional(), role: role.optional(), status: z.enum(['active', 'disabled']).optional() })
  .refine((b) => Object.keys(b).length > 0, 'Nothing to update');
const setupBody = z.object({
  setupToken: z.string().min(1).max(200),
  username,
  displayName: displayName.optional(),
  password: z.string().max(1024),
});

export function registerUserRoutes(app: FastifyInstance, ctx: AppContext, setup: { token: string | null }): void {
  const { db, audit, sessions, terminals } = ctx;

  const userCount = () => (db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number }).n;
  const activeAdminCount = () =>
    (db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND status = 'active'").get() as { n: number }).n;
  const findUser = (id: string) => db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;

  function insertUser(u: { username: string; displayName: string; role: 'admin' | 'user'; passwordHash: string; mustChange: boolean }) {
    const exists = db.prepare('SELECT 1 FROM users WHERE username = ?').get(u.username);
    if (exists) throw new HttpError(409, 'That username is taken.', 'conflict');
    const id = randomUUID();
    const now = Date.now();
    db.prepare(
      `INSERT INTO users (id, username, display_name, password_hash, role, must_change_password, password_changed_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, u.username, u.displayName, u.passwordHash, u.role, u.mustChange ? 1 : 0, now, now, now);
    return findUser(id)!;
  }

  // ---- First-run bootstrap: create the first administrator with the one-time token from the server log ----

  app.get('/api/setup', async () => ({ needed: userCount() === 0 }));

  app.post('/api/setup', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req) => {
    const body = parse(setupBody, req.body);
    if (userCount() > 0 || !setup.token) throw forbidden('Setup has already been completed.');
    if (!safeEqual(body.setupToken.trim(), setup.token)) {
      audit.record({ action: 'setup.create_admin', outcome: 'failure', ip: clientIp(req) });
      throw forbidden('Setup token is incorrect.');
    }
    const problem = checkPasswordPolicy(body.password, body.username);
    if (problem) throw badRequest(problem);
    const user = insertUser({
      username: body.username,
      displayName: body.displayName ?? body.username,
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

  app.post('/api/admin/users', async (req) => {
    const admin = requireAdmin(req).user;
    const body = parse(createUserBody, req.body);
    const temporaryPassword = generateTemporaryPassword();
    const user = insertUser({
      username: body.username,
      displayName: body.displayName ?? body.username,
      role: body.role,
      passwordHash: await hashPassword(temporaryPassword),
      mustChange: true,
    });
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_create', targetType: 'user', targetId: user.id,
      ip: clientIp(req), details: { username: user.username, role: user.role },
    });
    return { user: publicUser(user), temporaryPassword };
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

    db.prepare(
      `UPDATE users SET display_name = COALESCE(?, display_name), role = COALESCE(?, role),
         status = COALESCE(?, status), updated_at = ? WHERE id = ?`,
    ).run(body.displayName ?? null, body.role ?? null, body.status ?? null, Date.now(), id);

    if (body.status === 'disabled' || (body.role && body.role !== target.role)) {
      // Privilege changes take effect immediately: drop sessions and live terminals.
      sessions.destroyAllForUser(id);
      terminals.closeForUser(id, 'Your account was changed by an administrator.');
    }
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_update', targetType: 'user', targetId: id,
      ip: clientIp(req), details: { username: target.username, ...body },
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
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_reset_mfa', targetType: 'user', targetId: id,
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
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_unlock', targetType: 'user', targetId: id,
      ip: clientIp(req), details: { username: target.username },
    });
    return { ok: true };
  });

  app.delete('/api/admin/users/:id', async (req) => {
    const admin = requireAdmin(req).user;
    const { id } = parse(idParam, req.params);
    const target = findUser(id);
    if (!target) throw notFound('User not found');
    if (target.id === admin.id) throw badRequest('You cannot delete your own account.');
    if (target.role === 'admin' && target.status === 'active' && activeAdminCount() <= 1) {
      throw badRequest('There must be at least one active administrator.');
    }
    terminals.closeForUser(id, 'Your account was removed.');
    sessions.destroyAllForUser(id);
    // Cascades remove their keys, servers (and those servers' shares) and shares granted to them.
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_delete', targetType: 'user', targetId: id,
      ip: clientIp(req), details: { username: target.username },
    });
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
