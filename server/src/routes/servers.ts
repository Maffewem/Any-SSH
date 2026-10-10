import type { FastifyInstance } from 'fastify';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { z } from 'zod';
import { HttpError, badRequest, clientIp, forbidden, idParam, notFound, parse, requireUser } from '../http.js';
import type { AppContext, ServerAccess, ServerRow, SharePermission, SshKeyRow, UserRow } from '../types.js';

const hostname = z
  .string()
  .trim()
  .min(1)
  .max(253)
  .refine(
    (h) => isIP(h) !== 0 || /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$/.test(h),
    'Enter a valid hostname or IP address',
  );
const sshUser = z.string().trim().min(1).max(64).regex(/^[a-zA-Z0-9._@\\-]+$/, 'Invalid SSH username');

const serverFields = {
  name: z.string().trim().min(1).max(100),
  host: hostname,
  port: z.coerce.number().int().min(1).max(65535).default(22),
  username: sshUser,
  authMethod: z.enum(['key', 'password', 'prompt']),
  keyId: z.uuid().nullable().optional(),
  password: z.string().min(1).max(1024).optional(),
  notes: z.string().max(2000).default(''),
};
const createBody = z.object(serverFields);
const updateBody = z
  .object({
    name: serverFields.name.optional(),
    host: hostname.optional(),
    port: z.coerce.number().int().min(1).max(65535).optional(),
    username: sshUser.optional(),
    authMethod: serverFields.authMethod.optional(),
    keyId: z.uuid().nullable().optional(),
    password: z.string().min(1).max(1024).optional(),
    notes: z.string().max(2000).optional(),
  })
  .refine((b) => Object.keys(b).length > 0, 'Nothing to update');
const shareBody = z.object({ permission: z.enum(['use', 'manage']) });
const shareParams = z.object({ id: z.uuid(), userId: z.uuid() });

/** Fields a "manage" grantee may change. Connection details and credentials stay with the owner. */
const MANAGER_EDITABLE = new Set(['name', 'notes']);

export const serverPasswordContext = (serverId: string) => `server:${serverId}:password`;

export function getServerAccess(ctx: AppContext, userId: string, serverId: string): { server: ServerRow; access: ServerAccess } | null {
  const server = ctx.db.prepare('SELECT * FROM servers WHERE id = ?').get(serverId) as ServerRow | undefined;
  if (!server) return null;
  if (server.owner_id === userId) return { server, access: 'owner' };
  const share = ctx.db
    .prepare('SELECT permission FROM server_shares WHERE server_id = ? AND user_id = ?')
    .get(serverId, userId) as { permission: SharePermission } | undefined;
  return share ? { server, access: share.permission } : null;
}

export function registerServerRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { db, box, audit, terminals } = ctx;

  function view(server: ServerRow, access: ServerAccess) {
    const owner = db.prepare('SELECT username, display_name FROM users WHERE id = ?').get(server.owner_id) as
      | Pick<UserRow, 'username' | 'display_name'>
      | undefined;
    const key =
      access === 'owner' && server.key_id
        ? (db.prepare('SELECT id, name, fingerprint FROM ssh_keys WHERE id = ?').get(server.key_id) as
            | Pick<SshKeyRow, 'id' | 'name' | 'fingerprint'>
            | undefined)
        : undefined;
    const shareCount = (db.prepare('SELECT COUNT(*) AS n FROM server_shares WHERE server_id = ?').get(server.id) as { n: number }).n;
    return {
      id: server.id,
      name: server.name,
      host: server.host,
      port: server.port,
      username: server.username,
      authMethod: server.auth_method,
      // Only the owner learns which key is attached; nobody ever gets the secret material.
      key: key ? { id: key.id, name: key.name, fingerprint: key.fingerprint } : null,
      hasStoredPassword: server.password_enc !== null,
      hostKeyFingerprint: server.host_key_fingerprint,
      notes: server.notes,
      access,
      owner: owner ? { id: server.owner_id, username: owner.username, displayName: owner.display_name } : null,
      shareCount,
      createdAt: server.created_at,
      updatedAt: server.updated_at,
    };
  }

  function load(userId: string, serverId: string, allowed: ServerAccess[]) {
    const found = getServerAccess(ctx, userId, serverId);
    // Same 404 whether the server is missing or just not shared with you.
    if (!found) throw notFound('Server not found');
    if (!allowed.includes(found.access)) throw forbidden('You do not have permission to do that on this server.');
    return found;
  }

  function assertOwnKey(ownerId: string, keyId: string | null | undefined) {
    if (!keyId) return;
    const ok = db.prepare('SELECT 1 FROM ssh_keys WHERE id = ? AND owner_id = ?').get(keyId, ownerId);
    if (!ok) throw badRequest('Choose one of your own SSH keys.');
  }

  function validateCredentials(authMethod: ServerRow['auth_method'], keyId: string | null, hasPassword: boolean) {
    if (authMethod === 'key' && !keyId) throw badRequest('Choose an SSH key for key authentication.');
    if (authMethod === 'password' && !hasPassword) throw badRequest('Enter the password to store.');
  }

  app.get('/api/servers', async (req) => {
    const { user } = requireUser(req);
    const owned = db.prepare('SELECT * FROM servers WHERE owner_id = ?').all(user.id) as ServerRow[];
    const shared = db
      .prepare(
        `SELECT s.*, sh.permission AS _permission FROM servers s
         JOIN server_shares sh ON sh.server_id = s.id WHERE sh.user_id = ?`,
      )
      .all(user.id) as (ServerRow & { _permission: SharePermission })[];
    const servers = [
      ...owned.map((s) => view(s, 'owner')),
      ...shared.map(({ _permission, ...s }) => view(s, _permission)),
    ].sort((a, b) => a.name.localeCompare(b.name));
    return { servers };
  });

  app.get('/api/servers/:id', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    const { server, access } = load(user.id, id, ['owner', 'manage', 'use']);
    return { server: view(server, access) };
  });

  app.post('/api/servers', async (req) => {
    const { user } = requireUser(req);
    const body = parse(createBody, req.body);
    assertOwnKey(user.id, body.keyId);
    validateCredentials(body.authMethod, body.keyId ?? null, !!body.password);
    const id = randomUUID();
    const now = Date.now();
    db.prepare(
      `INSERT INTO servers (id, owner_id, name, host, port, username, auth_method, key_id, password_enc, notes, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id, user.id, body.name, body.host, body.port, body.username, body.authMethod,
      body.authMethod === 'key' ? body.keyId : null,
      body.authMethod === 'password' && body.password ? box.seal(body.password, serverPasswordContext(id)) : null,
      body.notes, now, now,
    );
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'server.create', targetType: 'server', targetId: id,
      ip: clientIp(req), details: { name: body.name, host: body.host, port: body.port, username: body.username, authMethod: body.authMethod },
    });
    return { server: view(db.prepare('SELECT * FROM servers WHERE id = ?').get(id) as ServerRow, 'owner') };
  });

  app.patch('/api/servers/:id', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    const body = parse(updateBody, req.body);
    const { server, access } = load(user.id, id, ['owner', 'manage']);
    if (access !== 'owner') {
      const disallowed = Object.keys(body).filter((k) => !MANAGER_EDITABLE.has(k));
      if (disallowed.length) throw forbidden('Only the owner can change connection details or credentials.');
    }
    assertOwnKey(server.owner_id, body.keyId);

    const authMethod = body.authMethod ?? server.auth_method;
    const keyId = authMethod === 'key' ? (body.keyId !== undefined ? body.keyId : server.key_id) : null;
    let passwordEnc = authMethod === 'password' ? server.password_enc : null;
    if (authMethod === 'password' && body.password) passwordEnc = box.seal(body.password, serverPasswordContext(id));
    validateCredentials(authMethod, keyId, passwordEnc !== null);

    const host = body.host ?? server.host;
    const port = body.port ?? server.port;
    // A different endpoint is a different machine: its host key must be verified afresh.
    const endpointChanged = host !== server.host || port !== server.port;

    db.prepare(
      `UPDATE servers SET name = ?, host = ?, port = ?, username = ?, auth_method = ?, key_id = ?, password_enc = ?,
         host_key_fingerprint = ?, notes = ?, updated_at = ? WHERE id = ?`,
    ).run(
      body.name ?? server.name, host, port, body.username ?? server.username, authMethod, keyId, passwordEnc,
      endpointChanged ? null : server.host_key_fingerprint, body.notes ?? server.notes, Date.now(), id,
    );
    const { password: _omit, ...logged } = body;
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'server.update', targetType: 'server', targetId: id,
      ip: clientIp(req), details: { ...logged, passwordChanged: !!body.password },
    });
    return { server: view(db.prepare('SELECT * FROM servers WHERE id = ?').get(id) as ServerRow, access) };
  });

  app.delete('/api/servers/:id', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    const { server } = load(user.id, id, ['owner']);
    terminals.closeForServer(id, 'This server was deleted.');
    db.prepare('DELETE FROM servers WHERE id = ?').run(id);
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'server.delete', targetType: 'server', targetId: id,
      ip: clientIp(req), details: { name: server.name, host: server.host },
    });
    return { ok: true };
  });

  app.post('/api/servers/:id/forget-host-key', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    const { server } = load(user.id, id, ['owner', 'manage']);
    db.prepare('UPDATE servers SET host_key_fingerprint = NULL, updated_at = ? WHERE id = ?').run(Date.now(), id);
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'server.host_key_forget', targetType: 'server', targetId: id,
      ip: clientIp(req), details: { previous: server.host_key_fingerprint },
    });
    return { ok: true };
  });

  // ---- Sharing ----

  app.get('/api/servers/:id/shares', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    load(user.id, id, ['owner', 'manage']);
    const rows = db
      .prepare(
        `SELECT sh.user_id, sh.permission, sh.created_at, u.username, u.display_name FROM server_shares sh
         JOIN users u ON u.id = sh.user_id WHERE sh.server_id = ? ORDER BY u.username`,
      )
      .all(id) as { user_id: string; permission: SharePermission; created_at: number; username: string; display_name: string }[];
    return {
      shares: rows.map((r) => ({
        userId: r.user_id, username: r.username, displayName: r.display_name, permission: r.permission, createdAt: r.created_at,
      })),
    };
  });

  app.put('/api/servers/:id/shares/:userId', async (req) => {
    const { user } = requireUser(req);
    const { id, userId } = parse(shareParams, req.params);
    const { permission } = parse(shareBody, req.body);
    const { server, access } = load(user.id, id, ['owner', 'manage']);

    const target = db.prepare("SELECT * FROM users WHERE id = ? AND status = 'active'").get(userId) as UserRow | undefined;
    if (!target) throw notFound('User not found');
    if (target.id === server.owner_id) throw badRequest('The owner already has full access.');
    const existing = db.prepare('SELECT permission FROM server_shares WHERE server_id = ? AND user_id = ?').get(id, userId) as
      | { permission: SharePermission }
      | undefined;
    if (access === 'manage' && (permission === 'manage' || existing?.permission === 'manage')) {
      throw forbidden('Only the owner can grant or change manage access.');
    }

    db.prepare(
      `INSERT INTO server_shares (server_id, user_id, permission, created_by, created_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (server_id, user_id) DO UPDATE SET permission = excluded.permission`,
    ).run(id, userId, permission, user.id, Date.now());
    audit.record({
      actorId: user.id, actorUsername: user.username, action: existing ? 'share.update' : 'share.grant', targetType: 'server',
      targetId: id, ip: clientIp(req), details: { server: server.name, grantee: target.username, permission },
    });
    return { ok: true };
  });

  app.delete('/api/servers/:id/shares/:userId', async (req) => {
    const { user } = requireUser(req);
    const { id, userId } = parse(shareParams, req.params);
    const found = getServerAccess(ctx, user.id, id);
    if (!found) throw notFound('Server not found');
    const share = db.prepare('SELECT permission FROM server_shares WHERE server_id = ? AND user_id = ?').get(id, userId) as
      | { permission: SharePermission }
      | undefined;
    if (!share) throw notFound('Share not found');

    const leaving = userId === user.id;
    const canRevoke = found.access === 'owner' || (found.access === 'manage' && share.permission === 'use');
    if (!leaving && !canRevoke) throw forbidden('You cannot remove that person’s access.');

    db.prepare('DELETE FROM server_shares WHERE server_id = ? AND user_id = ?').run(id, userId);
    terminals.closeForUserServer(userId, id, 'Your access to this server was removed.');
    const grantee = db.prepare('SELECT username FROM users WHERE id = ?').get(userId) as { username: string } | undefined;
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'share.revoke', targetType: 'server', targetId: id,
      ip: clientIp(req), details: { server: found.server.name, grantee: grantee?.username, self: leaving },
    });
    return { ok: true };
  });

  // ---- Connecting: a short-lived, single-use ticket that the terminal WebSocket must present ----

  app.post('/api/servers/:id/connect', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req) => {
    const { user, session } = requireUser(req);
    const { id } = parse(idParam, req.params);
    const { server, access } = load(user.id, id, ['owner', 'manage', 'use']);
    if (terminals.countForUser(user.id) >= ctx.config.maxTerminalsPerUser) {
      throw new HttpError(429, 'You have too many open terminals. Close one first.', 'too_many_terminals');
    }
    if (server.auth_method === 'key' && !server.key_id) throw badRequest('This server has no SSH key attached.');
    return { ticket: terminals.issueTicket({ userId: user.id, serverId: server.id, sessionIdHash: session.id_hash, access }) };
  });
}
