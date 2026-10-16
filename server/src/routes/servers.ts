import type { FastifyInstance } from 'fastify';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { z } from 'zod';
import { notify } from '../accountTokens.js';
import { HttpError, badRequest, clientIp, forbidden, idParam, notFound, parse, requireAdmin, requireUser } from '../http.js';
import { verifyPassword } from '../passwords.js';
import type { ConnectCredential } from '../ssh/registry.js';
import type { AppContext, ServerAccess, ServerRow, ServerShareRow, ShareCredentials, SharePermission, SshKeyRow, UserRow } from '../types.js';
import { inspectPrivateKey, normalisePrivateKey } from './keys.js';

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
  jumpMode: z.enum(['none', 'auto', 'fixed']).default('none'),
  jumpHostId: z.uuid().nullable().optional(),
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
    jumpMode: z.enum(['none', 'auto', 'fixed']).optional(),
    jumpHostId: z.uuid().nullable().optional(),
  })
  .refine((b) => Object.keys(b).length > 0, 'Nothing to update');
const shareBody = z.object({
  permission: z.enum(['use', 'manage']),
  /** Omitted: keep the current setting (new shares use the owner's credentials). */
  credentials: z.enum(['owner', 'own']).optional(),
  /** Only meaningful with `manage`, and only the owner may set it. */
  canReshare: z.boolean().optional(),
});
const connectBody = z
  .object({
    credential: z
      .discriminatedUnion('type', [
        z.object({ type: z.literal('saved') }),
        z.object({ type: z.literal('key'), keyId: z.uuid() }),
        z.object({ type: z.literal('oneoff'), privateKey: z.string().min(1).max(64 * 1024), passphrase: z.string().max(1024).optional() }),
        z.object({ type: z.literal('password') }),
      ])
      .default({ type: 'saved' }),
    username: sshUser.optional(),
    /** Id of a detached terminal to re-attach to. The credential choice is ignored for it. */
    resume: z.string().min(20).max(100).optional(),
  })
  .default({ credential: { type: 'saved' } });
const shareParams = z.object({ id: z.uuid(), userId: z.uuid() });

/** Fields a "manage" grantee may change. Connection details and credentials stay with the owner. */
const MANAGER_EDITABLE = new Set(['name', 'notes']);
const JUMP_FIELDS = ['jumpMode', 'jumpHostId'] as const;

export const serverPasswordContext = (serverId: string) => `server:${serverId}:password`;

export interface ServerGrant {
  server: ServerRow;
  access: ServerAccess;
  /** Whose credentials this user may connect with. Always 'owner' for the owner. */
  credentials: ShareCredentials;
  /** Whether this user may share the server with others. */
  canShare: boolean;
}

function hostKeyView(s: ServerRow) {
  return s.host_key_fingerprint
    ? { fingerprint: s.host_key_fingerprint, type: s.host_key_type, pinnedAt: s.host_key_pinned_at, pinnedBy: s.host_key_pinned_by }
    : null;
}

function hostKeyChangeView(s: ServerRow) {
  return s.host_key_pending ? { fingerprint: s.host_key_pending, type: s.host_key_pending_type, seenAt: s.host_key_pending_at } : null;
}

export function getServerAccess(ctx: AppContext, userId: string, serverId: string): ServerGrant | null {
  const server = ctx.db.prepare('SELECT * FROM servers WHERE id = ?').get(serverId) as ServerRow | undefined;
  if (!server) return null;
  if (server.owner_id === userId) return { server, access: 'owner', credentials: 'owner', canShare: true };
  const share = ctx.db.prepare('SELECT * FROM server_shares WHERE server_id = ? AND user_id = ?').get(serverId, userId) as
    | ServerShareRow
    | undefined;
  if (!share) return null;
  return {
    server,
    access: share.permission,
    credentials: share.credentials,
    canShare: share.permission === 'manage' && share.can_reshare === 1,
  };
}

export function registerServerRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { db, box, audit, terminals } = ctx;

  function view({ server, access, credentials, canShare }: ServerGrant) {
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
      jump: jumpView(server),
      hostKey: hostKeyView(server),
      hostKeyChange: hostKeyChangeView(server),
      notes: server.notes,
      access,
      credentials,
      canShare,
      owner: owner ? { id: server.owner_id, username: owner.username, displayName: owner.display_name } : null,
      shareCount,
      createdAt: server.created_at,
      updatedAt: server.updated_at,
    };
  }

  function jumpView(server: ServerRow) {
    const host = server.jump_host_id
      ? (db.prepare('SELECT id, name, enabled FROM jump_hosts WHERE id = ?').get(server.jump_host_id) as { id: string; name: string; enabled: number } | undefined)
      : undefined;
    return {
      mode: server.jump_mode,
      host: host ? { id: host.id, name: host.name, enabled: host.enabled === 1 } : null,
    };
  }

  /**
   * Who may route a server through a jump host. Anyone who owns the server may send it through
   * 'auto' or turn jumping off, but naming a specific jump host is an admin decision, and once an
   * admin has fixed one a non-admin owner cannot move the server off it.
   */
  function resolveJump(
    user: UserRow,
    current: ServerRow | null,
    want: { jumpMode?: ServerRow['jump_mode'] | undefined; jumpHostId?: string | null | undefined },
  ): { mode: ServerRow['jump_mode']; hostId: string | null } {
    const mode = want.jumpMode ?? current?.jump_mode ?? 'none';
    let hostId = mode === 'fixed' ? (want.jumpHostId !== undefined ? want.jumpHostId : (current?.jump_host_id ?? null)) : null;
    const changing = current ? mode !== current.jump_mode || hostId !== current.jump_host_id : mode !== 'none';
    if (changing) {
      if (user.role !== 'admin' && (mode === 'fixed' || current?.jump_mode === 'fixed')) {
        throw forbidden('Only an admin can choose or change a specific jump host.');
      }
      if (mode === 'fixed') {
        if (!hostId) throw badRequest('Choose a jump host.');
        if (!db.prepare('SELECT 1 FROM jump_hosts WHERE id = ?').get(hostId)) throw badRequest('That jump host does not exist.');
      }
      if (mode === 'auto' && !db.prepare('SELECT 1 FROM jump_hosts WHERE enabled = 1').get()) {
        throw badRequest('No jump host has been set up yet. Ask an admin to add one.');
      }
    }
    if (mode !== 'fixed') hostId = null;
    return { mode, hostId };
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
    const owned = db.prepare('SELECT id FROM servers WHERE owner_id = ?').all(user.id) as { id: string }[];
    const shared = db.prepare('SELECT server_id AS id FROM server_shares WHERE user_id = ?').all(user.id) as { id: string }[];
    const servers = [...owned, ...shared]
      .map(({ id }) => getServerAccess(ctx, user.id, id))
      .filter((g): g is ServerGrant => g !== null)
      .map(view)
      .sort((a, b) => a.name.localeCompare(b.name));
    return { servers };
  });

  app.get('/api/servers/:id', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    return { server: view(load(user.id, id, ['owner', 'manage', 'use'])) };
  });

  app.post('/api/servers', async (req) => {
    const { user } = requireUser(req);
    const body = parse(createBody, req.body);
    assertOwnKey(user.id, body.keyId);
    validateCredentials(body.authMethod, body.keyId ?? null, !!body.password);
    const jump = resolveJump(user, null, body);
    const id = randomUUID();
    const now = Date.now();
    db.prepare(
      `INSERT INTO servers (id, owner_id, name, host, port, username, auth_method, key_id, password_enc, notes, jump_mode, jump_host_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id, user.id, body.name, body.host, body.port, body.username, body.authMethod,
      body.authMethod === 'key' ? body.keyId : null,
      body.authMethod === 'password' && body.password ? box.seal(body.password, serverPasswordContext(id)) : null,
      body.notes, jump.mode, jump.hostId, now, now,
    );
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'server.create', targetType: 'server', targetId: id,
      ip: clientIp(req), details: { name: body.name, host: body.host, port: body.port, username: body.username, authMethod: body.authMethod, jumpMode: jump.mode, jumpHostId: jump.hostId },
    });
    return { server: view(getServerAccess(ctx, user.id, id)!) };
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
    const jump = JUMP_FIELDS.some((f) => body[f] !== undefined) ? resolveJump(user, server, body) : { mode: server.jump_mode, hostId: server.jump_host_id };

    const authMethod = body.authMethod ?? server.auth_method;
    const keyId = authMethod === 'key' ? (body.keyId !== undefined ? body.keyId : server.key_id) : null;
    let passwordEnc = authMethod === 'password' ? server.password_enc : null;
    if (authMethod === 'password' && body.password) passwordEnc = box.seal(body.password, serverPasswordContext(id));
    validateCredentials(authMethod, keyId, passwordEnc !== null);

    const host = body.host ?? server.host;
    const port = body.port ?? server.port;
    // A different endpoint is a different machine: its host key must be verified afresh.
    const endpointChanged = host !== server.host || port !== server.port;
    const jumpChanged = jump.mode !== server.jump_mode || jump.hostId !== server.jump_host_id;

    db.transaction(() => {
      db.prepare(
        `UPDATE servers SET name = ?, host = ?, port = ?, username = ?, auth_method = ?, key_id = ?, password_enc = ?,
           notes = ?, jump_mode = ?, jump_host_id = ?, updated_at = ? WHERE id = ?`,
      ).run(
        body.name ?? server.name, host, port, body.username ?? server.username, authMethod, keyId, passwordEnc,
        body.notes ?? server.notes, jump.mode, jump.hostId, Date.now(), id,
      );
      if (endpointChanged) clearHostKey(id);
    })();
    // A new route is a new vantage point: terminals already open keep the old path only until closed.
    if (jumpChanged) terminals.closeForServer(id, 'This server’s jump host setting was changed. Reconnect to use it.');
    const { password: _omit, ...logged } = body;
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'server.update', targetType: 'server', targetId: id,
      ip: clientIp(req), details: { ...logged, passwordChanged: !!body.password },
    });
    return { server: view(getServerAccess(ctx, user.id, id)!) };
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

  // ---- Host keys ----
  // Trust on first use is offered to the owner or a manager. After that, only the owner can let a
  // different key in: by accepting the exact change Any-SSH recorded (with their password), or by
  // forgetting the pin and verifying afresh.

  function clearHostKey(id: string) {
    db.prepare(
      `UPDATE servers SET host_key_fingerprint = NULL, host_key_type = NULL, host_key_pinned_at = NULL, host_key_pinned_by = NULL,
         host_key_pending = NULL, host_key_pending_type = NULL, host_key_pending_at = NULL WHERE id = ?`,
    ).run(id);
  }

  app.post('/api/servers/:id/forget-host-key', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    const { server } = load(user.id, id, ['owner']);
    db.transaction(() => {
      clearHostKey(id);
      db.prepare('UPDATE servers SET updated_at = ? WHERE id = ?').run(Date.now(), id);
    })();
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'server.host_key_forget', targetType: 'server', targetId: id,
      ip: clientIp(req), details: { host: server.host, port: server.port, previous: server.host_key_fingerprint, pending: server.host_key_pending },
    });
    return { ok: true };
  });

  app.post('/api/servers/:id/host-key/accept', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    const body = parse(z.object({ fingerprint: z.string().min(1).max(200), password: z.string().min(1).max(1024) }), req.body);
    const { server } = load(user.id, id, ['owner']);
    const auditBase = { actorId: user.id, actorUsername: user.username, action: 'server.host_key_accept', targetType: 'server', targetId: id, ip: clientIp(req) };
    // Accept exactly the key that was shown, never whatever turned up since.
    if (!server.host_key_pending || server.host_key_pending !== body.fingerprint) {
      throw new HttpError(409, 'That host key change is no longer pending. Reload and review it again.', 'conflict');
    }
    if (!(await verifyPassword(user.password_hash, body.password))) {
      audit.record({ ...auditBase, outcome: 'failure', details: { reason: 'bad_password', presented: body.fingerprint } });
      throw badRequest('Password is incorrect.');
    }
    const now = Date.now();
    db.prepare(
      `UPDATE servers SET host_key_fingerprint = host_key_pending, host_key_type = host_key_pending_type, host_key_pinned_at = ?,
         host_key_pinned_by = ?, host_key_pending = NULL, host_key_pending_type = NULL, host_key_pending_at = NULL, updated_at = ?
       WHERE id = ? AND host_key_pending = ?`,
    ).run(now, user.username, now, id, body.fingerprint);
    audit.record({
      ...auditBase,
      details: { host: server.host, port: server.port, previous: server.host_key_fingerprint, fingerprint: body.fingerprint, keyType: server.host_key_pending_type },
    });
    notify(ctx, req.log, user, `you accepted a new host key for "${server.name}" (${server.host}:${server.port}): ${body.fingerprint}`);
    return { server: view(getServerAccess(ctx, user.id, id)!) };
  });

  app.post('/api/servers/:id/host-key/dismiss', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    const { server } = load(user.id, id, ['owner']);
    if (!server.host_key_pending) return { server: view(getServerAccess(ctx, user.id, id)!) };
    db.prepare('UPDATE servers SET host_key_pending = NULL, host_key_pending_type = NULL, host_key_pending_at = NULL WHERE id = ?').run(id);
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'server.host_key_dismiss', targetType: 'server', targetId: id,
      ip: clientIp(req), details: { host: server.host, port: server.port, pinned: server.host_key_fingerprint, dismissed: server.host_key_pending },
    });
    return { server: view(getServerAccess(ctx, user.id, id)!) };
  });

  // Admins see every pinned fingerprint (no credentials, no access) so they can spot a host whose
  // key changed, one nobody has verified, or the same host pinned to different keys by different people.
  app.get('/api/admin/host-keys', async (req) => {
    requireAdmin(req);
    const rows = db
      .prepare(
        `SELECT s.*, u.username AS owner_username, u.display_name AS owner_display_name
         FROM servers s JOIN users u ON u.id = s.owner_id ORDER BY lower(s.host), s.port, lower(s.name)`,
      )
      .all() as (ServerRow & { owner_username: string; owner_display_name: string })[];
    const pinsByEndpoint = new Map<string, Set<string>>();
    for (const r of rows) {
      if (!r.host_key_fingerprint) continue;
      const k = `${r.host.toLowerCase()}:${r.port}`;
      if (!pinsByEndpoint.has(k)) pinsByEndpoint.set(k, new Set());
      pinsByEndpoint.get(k)!.add(r.host_key_fingerprint);
    }
    return {
      hosts: rows.map((r) => ({
        serverId: r.id,
        name: r.name,
        host: r.host,
        port: r.port,
        owner: { id: r.owner_id, username: r.owner_username, displayName: r.owner_display_name },
        hostKey: hostKeyView(r),
        hostKeyChange: hostKeyChangeView(r),
        // Another saved server for the same host and port trusts a different key.
        conflict: (pinsByEndpoint.get(`${r.host.toLowerCase()}:${r.port}`)?.size ?? 0) > 1,
      })),
    };
  });

  // ---- Sharing ----
  // The owner shares freely. A manager may share onwards only if the owner allowed it, only for
  // `use`, and never with more than they have themselves (no handing out the owner's credentials
  // if they were made to bring their own).

  function requireCanShare(grant: ServerGrant) {
    if (!grant.canShare) throw forbidden('The owner has not allowed you to share this server with anyone else.');
  }

  app.get('/api/servers/:id/shares', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    load(user.id, id, ['owner', 'manage']);
    const rows = db
      .prepare(
        `SELECT sh.*, u.username, u.display_name, c.username AS created_by_username FROM server_shares sh
         JOIN users u ON u.id = sh.user_id LEFT JOIN users c ON c.id = sh.created_by
         WHERE sh.server_id = ? ORDER BY u.username`,
      )
      .all(id) as (ServerShareRow & { username: string; display_name: string; created_by_username: string | null })[];
    return {
      shares: rows.map((r) => ({
        userId: r.user_id,
        username: r.username,
        displayName: r.display_name,
        permission: r.permission,
        credentials: r.credentials,
        canReshare: r.can_reshare === 1,
        sharedBy: r.created_by_username,
        createdAt: r.created_at,
      })),
    };
  });

  app.put('/api/servers/:id/shares/:userId', async (req) => {
    const { user } = requireUser(req);
    const { id, userId } = parse(shareParams, req.params);
    const body = parse(shareBody, req.body);
    const grant = load(user.id, id, ['owner', 'manage']);
    const { server, access } = grant;
    const target = db.prepare("SELECT * FROM users WHERE id = ? AND status = 'active'").get(userId) as UserRow | undefined;
    if (!target) throw notFound('User not found');
    if (target.id === server.owner_id) throw badRequest('The owner already has full access.');
    if (target.id === user.id) throw badRequest('You cannot change your own access.');
    requireCanShare(grant);
    const existing = db.prepare('SELECT * FROM server_shares WHERE server_id = ? AND user_id = ?').get(id, userId) as
      | ServerShareRow
      | undefined;

    const permission = body.permission;
    const credentials: ShareCredentials = body.credentials ?? existing?.credentials ?? 'owner';
    const canReshare = permission === 'manage' && (body.canReshare ?? existing?.can_reshare === 1);

    if (access === 'manage') {
      if (permission === 'manage' || existing?.permission === 'manage') {
        throw forbidden('Only the owner can grant or change manage access.');
      }
      if (body.canReshare) throw forbidden('Only the owner can allow re-sharing.');
      if (credentials === 'owner' && grant.credentials === 'own') {
        throw forbidden('You connect with your own credentials, so anyone you share with must bring theirs too.');
      }
    }

    db.prepare(
      `INSERT INTO server_shares (server_id, user_id, permission, credentials, can_reshare, created_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (server_id, user_id) DO UPDATE SET
         permission = excluded.permission, credentials = excluded.credentials, can_reshare = excluded.can_reshare`,
    ).run(id, userId, permission, credentials, canReshare ? 1 : 0, user.id, Date.now());
    // Someone who must now bring their own credentials loses any session using the owner's.
    if (existing?.credentials === 'owner' && credentials === 'own') {
      terminals.closeForUserServer(userId, id, 'The owner now requires you to use your own credentials for this server.');
    }
    audit.record({
      actorId: user.id, actorUsername: user.username, action: existing ? 'share.update' : 'share.grant', targetType: 'server',
      targetId: id, ip: clientIp(req), details: { server: server.name, grantee: target.username, permission, credentials, canReshare },
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
    const canRevoke = found.access === 'owner' || (found.canShare && share.permission === 'use');
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
    const body = parse(connectBody, req.body ?? undefined);
    const grant = load(user.id, id, ['owner', 'manage', 'use']);
    const { server, access } = grant;
    if (body.resume) {
      const live = terminals.resumable(user.id, body.resume);
      if (!live || live.serverId !== server.id) throw new HttpError(404, 'That terminal is no longer running.', 'session_gone');
      return { ticket: terminals.issueTicket({ userId: user.id, serverId: server.id, sessionIdHash: session.id_hash, access, credential: { type: 'saved' }, username: server.username, resume: body.resume }) };
    }
    if (terminals.countForUser(user.id) >= ctx.settings.terminalLimit(user.role)) {
      throw new HttpError(429, 'You have reached the maximum number of open terminals for your account. Close one to open another.', 'too_many_terminals');
    }

    let credential: ConnectCredential;
    const choice = body.credential;
    if (choice.type === 'saved') {
      if (grant.credentials === 'own') {
        throw new HttpError(400, 'The owner asked you to connect with your own credentials.', 'own_credentials_required');
      }
      // The owner's credentials belong to the owner's login on that server.
      if (body.username && body.username !== server.username) {
        throw badRequest('Choose your own credentials to log in as a different user.');
      }
      if (server.auth_method === 'key' && !server.key_id) throw badRequest('This server has no SSH key attached.');
      credential = choice;
    } else if (choice.type === 'key') {
      assertOwnKey(user.id, choice.keyId);
      credential = choice;
    } else if (choice.type === 'oneoff') {
      // Checked now so a bad paste fails here, not mid-handshake. Kept in memory only.
      const privateKey = normalisePrivateKey(choice.privateKey);
      const { fingerprint } = inspectPrivateKey(privateKey, choice.passphrase || undefined);
      credential = { type: 'oneoff', privateKey, fingerprint, ...(choice.passphrase ? { passphrase: choice.passphrase } : {}) };
    } else {
      credential = choice;
    }

    const ticket = terminals.issueTicket({
      userId: user.id, serverId: server.id, sessionIdHash: session.id_hash, access, credential,
      username: body.username ?? server.username,
    });
    return { ticket };
  });
}
