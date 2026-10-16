import type { FastifyInstance } from 'fastify';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { z } from 'zod';
import { HttpError, badRequest, clientIp, idParam, notFound, parse, requireAdmin } from '../http.js';
import { jumpHostContext } from '../rotate.js';
import { forgetLatency, testJumpHost } from '../ssh/jump.js';
import type { AppContext, JumpHostRow } from '../types.js';
import { generateKeyPair, inspectPrivateKey, type StoredPrivateKey } from './keys.js';

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
const name = z.string().trim().min(1).max(100);

const createBody = z.object({ name, host: hostname, port: z.coerce.number().int().min(1).max(65535).default(22), username: sshUser });
const updateBody = z
  .object({
    name: name.optional(),
    host: hostname.optional(),
    port: z.coerce.number().int().min(1).max(65535).optional(),
    username: sshUser.optional(),
    enabled: z.boolean().optional(),
  })
  .refine((b) => Object.keys(b).length > 0, 'Nothing to update');
const pinBody = z.object({ fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]{20,100}$/) });

/**
 * Jump hosts (bastions) are an admin-only resource. Each has an Any-SSH-generated key whose
 * private half never leaves the server, and a host key an admin must verify before the jump host
 * can be used. Servers reach their targets through one by opening a channel; the target session
 * itself is end to end (see ssh/jump.ts).
 */
export function registerJumpHostRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { db, box, audit, terminals } = ctx;

  const view = (j: JumpHostRow) => ({
    id: j.id,
    name: j.name,
    host: j.host,
    port: j.port,
    username: j.username,
    publicKey: j.public_key,
    keyFingerprint: j.fingerprint,
    hostKeyFingerprint: j.host_key_fingerprint,
    enabled: j.enabled === 1,
    serverCount: (db.prepare('SELECT COUNT(*) AS n FROM servers WHERE jump_host_id = ?').get(j.id) as { n: number }).n,
    createdAt: j.created_at,
  });

  const find = (id: string) => {
    const row = db.prepare('SELECT * FROM jump_hosts WHERE id = ?').get(id) as JumpHostRow | undefined;
    if (!row) throw notFound('Jump host not found');
    return row;
  };
  const auditBase = (req: Parameters<typeof requireAdmin>[0]) => {
    const { user } = requireAdmin(req);
    return { actorId: user.id, actorUsername: user.username, targetType: 'jump_host', ip: clientIp(req) };
  };
  const assertNameFree = (n: string, exceptId = '') => {
    if (db.prepare('SELECT 1 FROM jump_hosts WHERE name = ? COLLATE NOCASE AND id != ?').get(n, exceptId)) {
      throw new HttpError(409, 'A jump host with that name already exists.', 'conflict');
    }
  };

  app.get('/api/admin/jump-hosts', async (req) => {
    requireAdmin(req);
    const rows = db.prepare('SELECT * FROM jump_hosts ORDER BY name').all() as JumpHostRow[];
    return { jumpHosts: rows.map(view) };
  });

  app.post('/api/admin/jump-hosts', async (req) => {
    const base = auditBase(req);
    const body = parse(createBody, req.body);
    assertNameFree(body.name);
    const pair = await generateKeyPair('ed25519');
    const { fingerprint } = inspectPrivateKey(pair.private);
    const id = randomUUID();
    const now = Date.now();
    db.prepare(
      `INSERT INTO jump_hosts (id, name, host, port, username, public_key, fingerprint, private_key_enc, enabled, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
    ).run(
      id, body.name, body.host, body.port, body.username, pair.public.trim(), fingerprint,
      box.seal(JSON.stringify({ privateKey: pair.private } satisfies StoredPrivateKey), jumpHostContext(id)),
      base.actorId, now, now,
    );
    audit.record({ ...base, action: 'jump_host.create', targetId: id, details: { name: body.name, host: body.host, port: body.port, username: body.username, keyFingerprint: fingerprint } });
    return { jumpHost: view(find(id)) };
  });

  app.patch('/api/admin/jump-hosts/:id', async (req) => {
    const base = auditBase(req);
    const { id } = parse(idParam, req.params);
    const body = parse(updateBody, req.body);
    const j = find(id);
    if (body.name) assertNameFree(body.name, id);
    const host = body.host ?? j.host;
    const port = body.port ?? j.port;
    // A different endpoint is a different machine: its host key must be verified afresh.
    const endpointChanged = host !== j.host || port !== j.port;
    const enabled = body.enabled ?? j.enabled === 1;
    db.prepare('UPDATE jump_hosts SET name = ?, host = ?, port = ?, username = ?, enabled = ?, host_key_fingerprint = ?, updated_at = ? WHERE id = ?').run(
      body.name ?? j.name, host, port, body.username ?? j.username, enabled ? 1 : 0,
      endpointChanged ? null : j.host_key_fingerprint, Date.now(), id,
    );
    forgetLatency(id);
    if (!enabled || endpointChanged || (body.username && body.username !== j.username)) {
      terminals.closeForJumpHost(id, 'The jump host this terminal used was changed or disabled.');
    }
    audit.record({ ...base, action: 'jump_host.update', targetId: id, details: { ...body, hostKeyCleared: endpointChanged && !!j.host_key_fingerprint } });
    return { jumpHost: view(find(id)) };
  });

  app.delete('/api/admin/jump-hosts/:id', async (req) => {
    const base = auditBase(req);
    const { id } = parse(idParam, req.params);
    const j = find(id);
    terminals.closeForJumpHost(id, 'The jump host this terminal used was removed.');
    // Servers fixed to it keep jump_mode 'fixed' with no host, so they fail closed instead of going direct.
    db.prepare('DELETE FROM jump_hosts WHERE id = ?').run(id);
    forgetLatency(id);
    audit.record({ ...base, action: 'jump_host.delete', targetId: id, details: { name: j.name, host: j.host, serversAffected: view(j).serverCount } });
    return { ok: true };
  });

  // Connects to the jump host without using it for anyone. With no pinned host key it stops at the
  // handshake and reports the fingerprint for the admin to check.
  app.post('/api/admin/jump-hosts/:id/test', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req) => {
    const base = auditBase(req);
    const { id } = parse(idParam, req.params);
    const result = await testJumpHost(ctx, find(id));
    audit.record({ ...base, action: 'jump_host.test', targetId: id, outcome: result.authenticated ? 'success' : 'failure', details: { hostKey: result.hostKey, fingerprint: result.fingerprint, latencyMs: result.latencyMs, error: result.error } });
    return result;
  });

  // Pins the host key the admin has checked. The jump host is probed again and must still present
  // exactly that fingerprint, so a key swapped in between is not pinned by accident.
  app.post('/api/admin/jump-hosts/:id/pin', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req) => {
    const base = auditBase(req);
    const { id } = parse(idParam, req.params);
    const { fingerprint } = parse(pinBody, req.body);
    const j = find(id);
    if (j.host_key_fingerprint) throw badRequest('A host key is already verified. Remove it first to verify a different one.');
    const probe = await testJumpHost(ctx, j);
    if (!probe.fingerprint) throw badRequest(probe.error ?? 'Could not reach the jump host.');
    if (probe.fingerprint !== fingerprint) {
      audit.record({ ...base, action: 'jump_host.pin', targetId: id, outcome: 'failure', details: { expected: fingerprint, presented: probe.fingerprint } });
      throw badRequest('The jump host now presents a different host key from the one you checked. Nothing was saved.');
    }
    db.prepare('UPDATE jump_hosts SET host_key_fingerprint = ?, updated_at = ? WHERE id = ? AND host_key_fingerprint IS NULL').run(fingerprint, Date.now(), id);
    audit.record({ ...base, action: 'jump_host.pin', targetId: id, details: { name: j.name, fingerprint } });
    return { jumpHost: view(find(id)) };
  });

  app.post('/api/admin/jump-hosts/:id/forget-host-key', async (req) => {
    const base = auditBase(req);
    const { id } = parse(idParam, req.params);
    const j = find(id);
    db.prepare('UPDATE jump_hosts SET host_key_fingerprint = NULL, updated_at = ? WHERE id = ?').run(Date.now(), id);
    terminals.closeForJumpHost(id, 'The jump host’s pinned host key was cleared.');
    audit.record({ ...base, action: 'jump_host.host_key_forget', targetId: id, details: { name: j.name, previous: j.host_key_fingerprint } });
    return { jumpHost: view(find(id)) };
  });
}
