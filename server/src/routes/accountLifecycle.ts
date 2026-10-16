import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { notify } from '../accountTokens.js';
import { recordReauthFailure } from '../bruteForce.js';
import { HttpError, badRequest, clearSessionCookie, clientIp, idParam, notFound, parse, requireAdmin, requireUser } from '../http.js';
import { verifyPassword } from '../passwords.js';
import { verifyTotp } from '../totp.js';
import type { AppContext, UserRow } from '../types.js';

const totpContext = (userId: string) => `user:${userId}:totp`;

const deleteBody = z.object({
  password: z.string().min(1).max(1024),
  /** Required when two-factor authentication is on. */
  code: z.string().trim().regex(/^\d{6}$/, 'Enter the 6-digit code').optional(),
  /** Hand the servers that are shared with other people to this user instead of deleting them. */
  transferTo: z.uuid().optional(),
  /** The word "delete", typed to acknowledge that shared servers are removed for everyone they were shared with. */
  confirm: z.string().trim().max(20).optional(),
});

/**
 * Signing out every device, and closing an account: its keys, servers and shares go with it.
 * Servers that other people use can be handed to another user first instead of being deleted.
 */
export function registerAccountLifecycleRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { db, audit, sessions, terminals, box } = ctx;
  const findUser = (id: string) => db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
  const activeAdminCount = () => (db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND status = 'active'").get() as { n: number }).n;

  /** What closing this account would remove, and who else would lose access. */
  function owned(userId: string) {
    const servers = db.prepare('SELECT id, name FROM servers WHERE owner_id = ? ORDER BY name').all(userId) as { id: string; name: string }[];
    const shares = db
      .prepare(
        `SELECT s.server_id, u.id AS user_id, u.username, u.display_name FROM server_shares s
         JOIN users u ON u.id = s.user_id JOIN servers v ON v.id = s.server_id WHERE v.owner_id = ? ORDER BY u.username`,
      )
      .all(userId) as { server_id: string; user_id: string; username: string; display_name: string }[];
    const keys = (db.prepare('SELECT COUNT(*) AS n FROM ssh_keys WHERE owner_id = ?').get(userId) as { n: number }).n;
    return {
      keys,
      servers: servers.map((s) => ({
        id: s.id,
        name: s.name,
        sharedWith: shares.filter((x) => x.server_id === s.id).map((x) => ({ id: x.user_id, username: x.username, displayName: x.display_name })),
      })),
    };
  }

  /** Moves the shared servers (and the saved keys they use) to another user, who stops being a mere grantee. */
  function transferShared(from: UserRow, to: UserRow): { id: string; name: string }[] {
    const moved = owned(from.id).servers.filter((s) => s.sharedWith.length > 0);
    db.transaction(() => {
      for (const s of moved) {
        db.prepare('UPDATE servers SET owner_id = ?, updated_at = ? WHERE id = ?').run(to.id, Date.now(), s.id);
        db.prepare('DELETE FROM server_shares WHERE server_id = ? AND user_id = ?').run(s.id, to.id);
        db.prepare('UPDATE ssh_keys SET owner_id = ? WHERE owner_id = ? AND id = (SELECT key_id FROM servers WHERE id = ?)').run(to.id, from.id, s.id);
      }
    })();
    return moved.map((s) => ({ id: s.id, name: s.name }));
  }

  function checkSecondFactor(user: UserRow, code: string | undefined): boolean {
    if (!user.totp_enabled) return true;
    if (!code || !user.totp_secret_enc) return false;
    const counter = verifyTotp(box.openString(user.totp_secret_enc, totpContext(user.id)), code, user.totp_last_counter);
    if (counter === null) return false;
    db.prepare('UPDATE users SET totp_last_counter = ? WHERE id = ?').run(counter, user.id);
    return true;
  }

  function removeAccount(user: UserRow, reason: string) {
    terminals.closeForUser(user.id, reason);
    sessions.destroyAllForUser(user.id);
    // Cascades remove their keys, servers (and those servers' shares) and shares granted to them.
    db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
  }

  // ---- Sign out every device ----

  app.post('/api/auth/sessions/revoke-all', async (req, reply) => {
    const { user } = requireUser(req);
    const count = sessions.destroyAllForUser(user.id);
    terminals.closeForUser(user.id, 'You signed out of all devices.');
    clearSessionCookie(ctx, reply);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'auth.sign_out_everywhere', ip: clientIp(req), details: { sessions: count } });
    return { ok: true, sessions: count };
  });

  app.post('/api/admin/users/:id/sign-out', async (req) => {
    const admin = requireAdmin(req).user;
    const { id } = parse(idParam, req.params);
    const target = findUser(id);
    if (!target) throw notFound('User not found');
    const count = sessions.destroyAllForUser(id);
    terminals.closeForUser(id, 'An administrator signed you out of all devices.');
    if (target.id !== admin.id) notify(ctx, req.log, target, 'an administrator signed you out of all devices');
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_sign_out', targetType: 'user', targetId: id,
      ip: clientIp(req), details: { username: target.username, sessions: count },
    });
    return { ok: true, sessions: count };
  });

  // ---- Closing an account ----

  app.get('/api/account/deletion-preview', async (req) => {
    const { user } = requireUser(req);
    return owned(user.id);
  });

  app.get('/api/admin/users/:id/deletion-preview', async (req) => {
    requireAdmin(req);
    const { id } = parse(idParam, req.params);
    if (!findUser(id)) throw notFound('User not found');
    return owned(id);
  });

  app.post('/api/account/delete', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { user } = requireUser(req);
    const body = parse(deleteBody, req.body);
    const base = { actorId: user.id, actorUsername: user.username, action: 'user.account_delete', ip: clientIp(req) };
    if (!(await verifyPassword(user.password_hash, body.password)) || !checkSecondFactor(user, body.code)) {
      recordReauthFailure(ctx, req.log, clientIp(req), user);
      audit.record({ ...base, outcome: 'failure' });
      throw badRequest('The password or code isn’t correct.');
    }
    if (user.role === 'admin' && activeAdminCount() <= 1) throw badRequest('You’re the only administrator. Make someone else an administrator first.');

    const shared = owned(user.id).servers.filter((s) => s.sharedWith.length > 0);
    let transferred: { id: string; name: string }[] = [];
    if (body.transferTo) {
      const to = findUser(body.transferTo);
      if (!to || to.status !== 'active' || to.id === user.id) throw badRequest('Choose an active user to take over the shared servers.');
      transferred = transferShared(user, to);
      if (transferred.length) notify(ctx, req.log, to, `${user.display_name} (@${user.username}) closed their account and transferred ${transferred.length === 1 ? 'a server' : `${transferred.length} servers`} to you: ${transferred.map((s) => s.name).join(', ')}`);
    } else if (shared.length > 0 && body.confirm?.toLowerCase() !== 'delete') {
      throw badRequest('Type “delete” to confirm that servers shared with other people will be deleted, or transfer them to another user.');
    }

    removeAccount(user, 'Your account was deleted.');
    audit.record({
      ...base, targetType: 'user', targetId: user.id,
      details: { username: user.username, transferredTo: body.transferTo ?? null, transferred: transferred.map((s) => s.name), deletedShared: body.transferTo ? [] : shared.map((s) => s.name) },
    });
    clearSessionCookie(ctx, reply);
    return { ok: true };
  });

  /** Admin: hand a user's shared servers to someone else, typically before deleting the account. */
  app.post('/api/admin/users/:id/transfer-servers', async (req) => {
    const admin = requireAdmin(req).user;
    const { id } = parse(idParam, req.params);
    const { to: toId } = parse(z.object({ to: z.uuid() }), req.body);
    const from = findUser(id);
    const to = findUser(toId);
    if (!from) throw notFound('User not found');
    if (!to || to.status !== 'active' || to.id === from.id) throw badRequest('Choose an active user to take over the servers.');
    const moved = transferShared(from, to);
    if (moved.length) notify(ctx, req.log, to, `an administrator transferred ${moved.length === 1 ? 'a server' : `${moved.length} servers`} from @${from.username} to you: ${moved.map((s) => s.name).join(', ')}`);
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.servers_transfer', targetType: 'user', targetId: id,
      ip: clientIp(req), details: { from: from.username, to: to.username, servers: moved.map((s) => s.name) },
    });
    return { moved };
  });

  // Admin deletion: shared servers are deleted unless transferred first (see above); the UI asks for typed confirmation.
  app.delete('/api/admin/users/:id', async (req) => {
    const admin = requireAdmin(req).user;
    const { id } = parse(idParam, req.params);
    const { confirm } = parse(z.object({ confirm: z.string().trim().max(20).optional() }), req.query);
    const target = findUser(id);
    if (!target) throw notFound('User not found');
    if (target.id === admin.id) throw badRequest('To delete your own account, go to My account.');
    if (target.role === 'admin' && target.status === 'active' && activeAdminCount() <= 1) throw badRequest('There must be at least one active administrator.');
    const shared = owned(id).servers.filter((s) => s.sharedWith.length > 0);
    if (shared.length > 0 && confirm?.toLowerCase() !== 'delete') {
      throw new HttpError(400, 'This user owns servers that are shared with other people. Transfer them first, or type “delete” to delete them.', 'confirmation_required');
    }
    removeAccount(target, 'Your account was deleted.');
    audit.record({
      actorId: admin.id, actorUsername: admin.username, action: 'admin.user_delete', targetType: 'user', targetId: id,
      ip: clientIp(req), details: { username: target.username, deletedShared: shared.map((s) => s.name) },
    });
    return { ok: true };
  });
}
