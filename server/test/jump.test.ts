import net, { type AddressInfo } from 'node:net';
import ssh2 from 'ssh2';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import type { BuiltApp } from '../src/app.js';
import { sshFingerprint } from '../src/ssh/fingerprint.js';
import { createUser, makeApp, setupAdmin, type Client } from './helpers.js';

const { Server, utils } = ssh2;
type Msg = { type: string; [k: string]: unknown };
type Listening = { port: number; close(): void };

const listen = (server: net.Server | ssh2.Server): Promise<Listening> =>
  new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ port: (server.address() as AddressInfo).port, close: () => server.close() })));

function parsePublic(k: string) {
  const parsed = utils.parseKey(k);
  if (parsed instanceof Error || Array.isArray(parsed)) throw new Error('bad key');
  return parsed;
}

/** SSH server that accepts one public key and answers shells by upper-casing input. Optionally also relays tcpip channels (a jump host). */
function fakeSshd(allowed: string[], hostKey: string, opts: { relay?: { forwarded: number[] } } = {}) {
  const keys = allowed.map(parsePublic);
  const server = new Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => {
      const match = ctx.method === 'publickey' && keys.find((k) => ctx.key.algo === k.type && ctx.key.data.equals(k.getPublicSSH()));
      if (match) {
        if (!ctx.signature) return ctx.accept();
        return match.verify(ctx.blob!, ctx.signature, ctx.hashAlgo) ? ctx.accept() : ctx.reject();
      }
      ctx.reject(['publickey']);
    });
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept();
        session.on('pty', (acceptPty) => acceptPty?.());
        session.on('shell', (acceptShell) => {
          const stream = acceptShell();
          stream.write('welcome\r\n');
          stream.on('data', (d: Buffer) => stream.write(d.toString().toUpperCase()));
        });
      });
    });
    if (opts.relay) {
      client.on('tcpip', (accept, _reject, info) => {
        opts.relay!.forwarded.push(info.destPort);
        const upstream = net.connect(info.destPort, info.destIP, () => {
          const channel = accept();
          channel.pipe(upstream).pipe(channel);
          channel.on('close', () => upstream.destroy());
          upstream.on('close', () => channel.close());
        });
        upstream.on('error', () => _reject());
      });
    }
    client.on('error', () => {});
  });
  return listen(server as unknown as net.Server);
}

let built: BuiltApp;
let origin: string;
let admin: Client;
let user: Client;
let userId: string;
let userPassword: string;
let other: Client;
let targetHostKey: string;
let target: Listening;
let jumpHostKey: string;
let jump: Listening;
const forwarded: number[] = [];
let jumpId: string;
let jumpPublicKey: string;
let targetKeyId: string;
let adminServerId: string;

const fp = (privateKey: string) => sshFingerprint((utils.parseKey(privateKey) as ssh2.ParsedKey).getPublicSSH());

beforeAll(async () => {
  built = await makeApp({ allowLoopbackTargets: true });
  await built.app.listen({ host: '127.0.0.1', port: 0 });
  origin = `http://127.0.0.1:${(built.app.server.address() as AddressInfo).port}`;
  built.ctx.config.allowedOrigins = [origin];
  admin = await setupAdmin(built);
  const u = await createUser(built, admin, 'alice');
  user = u.client;
  userId = u.id;
  userPassword = u.password;
  other = (await createUser(built, admin, 'bob')).client;

  const key = (await admin.post('/api/keys/generate', { name: 'target-key' })).body.key;
  targetKeyId = key.id;
  targetHostKey = utils.generateKeyPairSync('ed25519').private;
  target = await fakeSshd([key.publicKey], targetHostKey);

  const created = (await admin.post('/api/admin/jump-hosts', { name: 'bastion', host: '127.0.0.1', port: 1, username: 'jump' })).body.jumpHost;
  jumpId = created.id;
  jumpPublicKey = created.publicKey;
  jumpHostKey = utils.generateKeyPairSync('ed25519').private;
  jump = await fakeSshd([jumpPublicKey], jumpHostKey, { relay: { forwarded } });
  await admin.patch(`/api/admin/jump-hosts/${jumpId}`, { port: jump.port });

  adminServerId = (
    await admin.post('/api/servers', { name: 'behind', host: '127.0.0.1', port: target.port, username: 'me', authMethod: 'key', keyId: key.id })
  ).body.server.id;
  // The target's own host key is pinned as usual (the jump host never decides that).
  built.ctx.db.prepare('UPDATE servers SET host_key_fingerprint = ? WHERE id = ?').run(fp(targetHostKey), adminServerId);
});

afterAll(async () => {
  target?.close();
  jump?.close();
  await built?.app.close();
});

async function openTerminal(client: Client, serverId: string, body: Record<string, unknown> = {}) {
  const res = await client.post(`/api/servers/${serverId}/connect`, body);
  if (res.status !== 200) return { failed: res };
  const ws = new WebSocket(`${origin.replace('http', 'ws')}/api/terminal?ticket=${res.body.ticket}&cols=80&rows=24`, {
    headers: { origin, cookie: client.cookie },
  });
  const messages: Msg[] = [];
  const waiters: { pred: (m: Msg) => boolean; resolve: (m: Msg) => void }[] = [];
  ws.on('message', (raw) => {
    const m = JSON.parse(raw.toString()) as Msg;
    messages.push(m);
    for (const w of [...waiters]) if (w.pred(m)) (waiters.splice(waiters.indexOf(w), 1), w.resolve(m));
  });
  const next = (pred: (m: Msg) => boolean) =>
    new Promise<Msg>((resolve, reject) => {
      const hit = messages.find(pred);
      if (hit) return resolve(hit);
      waiters.push({ pred, resolve });
      setTimeout(() => reject(new Error(`timeout; got ${JSON.stringify(messages)}`)), 5000);
    });
  return { ws, next, messages, send: (m: Msg) => ws.send(JSON.stringify(m)), failed: null };
}

const useJump = (id = jumpId) => admin.patch(`/api/servers/${adminServerId}`, { jumpMode: 'fixed', jumpHostId: id });

describe('jump hosts', () => {
  it('are an admin-only resource', async () => {
    expect((await user.get('/api/admin/jump-hosts')).status).toBe(403);
    expect((await user.post('/api/admin/jump-hosts', { name: 'x', host: 'h.example', username: 'u' })).status).toBe(403);
    const list = (await admin.get('/api/admin/jump-hosts')).body.jumpHosts;
    expect(list[0].publicKey).toMatch(/^ssh-ed25519 /);
    expect(JSON.stringify(list)).not.toContain('PRIVATE KEY');
  });

  it('cannot be used until an admin has verified the host key', async () => {
    expect((await useJump()).status).toBe(200);
    const t = await openTerminal(admin, adminServerId);
    const err = await t.next!((m) => m.type === 'error');
    expect(err.code).toBe('jump_host_key_unverified');
    expect(forwarded).toHaveLength(0);
  });

  it('pins only the fingerprint the admin checked', async () => {
    const test = (await admin.post(`/api/admin/jump-hosts/${jumpId}/test`)).body;
    expect(test.hostKey).toBe('unpinned');
    expect(test.fingerprint).toBe(fp(jumpHostKey));
    expect(test.authenticated).toBe(false);

    const wrong = await admin.post(`/api/admin/jump-hosts/${jumpId}/pin`, { fingerprint: 'SHA256:' + 'A'.repeat(43) });
    expect(wrong.status).toBe(400);
    const ok = await admin.post(`/api/admin/jump-hosts/${jumpId}/pin`, { fingerprint: test.fingerprint });
    expect(ok.body.jumpHost.hostKeyFingerprint).toBe(test.fingerprint);

    const after = (await admin.post(`/api/admin/jump-hosts/${jumpId}/test`)).body;
    expect(after).toMatchObject({ hostKey: 'match', authenticated: true });
  });

  it('carry a session through to the target, which still verifies its own host key', async () => {
    const t = await openTerminal(admin, adminServerId);
    await t.next!((m) => m.type === 'ready');
    t.send!({ type: 'input', data: 'via jump' });
    await t.next!((m) => m.type === 'data' && String(m.data).includes('VIA JUMP'));
    expect(forwarded).toContain(target.port);
    const start = (built.ctx.db.prepare("SELECT details FROM audit_log WHERE action = 'ssh.session_start' ORDER BY seq DESC").get() as { details: string }).details;
    expect(JSON.parse(start)).toMatchObject({ jumpHost: 'bastion', jumpMode: 'fixed' });
    t.ws!.close();

    // A changed target key is refused even through a jump host.
    built.ctx.db.prepare("UPDATE servers SET host_key_fingerprint = 'SHA256:not-the-real-one' WHERE id = ?").run(adminServerId);
    const bad = await openTerminal(admin, adminServerId);
    expect((await bad.next!((m) => m.type === 'error')).code).toBe('host_key_mismatch');
    built.ctx.db.prepare('UPDATE servers SET host_key_fingerprint = ? WHERE id = ?').run(fp(targetHostKey), adminServerId);
  });

  it('refuse a jump host whose host key changed', async () => {
    built.ctx.db.prepare("UPDATE jump_hosts SET host_key_fingerprint = 'SHA256:somethingelse' WHERE id = ?").run(jumpId);
    const t = await openTerminal(admin, adminServerId);
    expect((await t.next!((m) => m.type === 'error')).code).toBe('jump_host_key_mismatch');
    const actions = (built.ctx.db.prepare('SELECT action FROM audit_log').all() as { action: string }[]).map((r) => r.action);
    expect(actions).toContain('ssh.jump_host_key_mismatch');
    built.ctx.db.prepare('UPDATE jump_hosts SET host_key_fingerprint = ? WHERE id = ?').run(fp(jumpHostKey), jumpId);
  });

  it('only let an admin choose a specific jump host, but let owners opt in to the closest one', async () => {
    const mine = (await user.post('/api/servers', { name: 'mine', host: '127.0.0.1', port: target.port, username: 'me', authMethod: 'prompt' })).body.server.id;
    expect((await user.patch(`/api/servers/${mine}`, { jumpMode: 'fixed', jumpHostId: jumpId })).status).toBe(403);
    expect((await user.post('/api/servers', { name: 'n', host: 'h.example', username: 'me', authMethod: 'prompt', jumpMode: 'fixed', jumpHostId: jumpId })).status).toBe(403);
    const auto = await user.patch(`/api/servers/${mine}`, { jumpMode: 'auto' });
    expect(auto.body.server.jump).toMatchObject({ mode: 'auto' });

    // A manager cannot touch the route of someone else's server.
    await admin.put(`/api/servers/${adminServerId}/shares/${userId}`, { permission: 'manage' });
    expect((await user.patch(`/api/servers/${adminServerId}`, { jumpMode: 'none' })).status).toBe(403);
  });

  it('send "closest" servers through the lowest-latency reachable jump host and skip unreachable ones', async () => {
    // A second jump host that nothing listens on is skipped rather than failing the connection.
    const dead = (await admin.post('/api/admin/jump-hosts', { name: 'dead', host: '127.0.0.1', port: 9, username: 'jump' })).body.jumpHost;
    built.ctx.db.prepare("UPDATE jump_hosts SET host_key_fingerprint = 'SHA256:x' WHERE id = ?").run(dead.id);
    await admin.patch(`/api/servers/${adminServerId}`, { jumpMode: 'auto' });
    forwarded.length = 0;
    const t = await openTerminal(admin, adminServerId);
    await t.next!((m) => m.type === 'ready');
    expect(forwarded).toContain(target.port);
    t.ws!.close();
    await admin.del(`/api/admin/jump-hosts/${dead.id}`);
  });

  it('close live terminals when the jump host is disabled, and fail closed when it is gone', async () => {
    await useJump();
    const live = await openTerminal(admin, adminServerId);
    await live.next!((m) => m.type === 'ready');
    await admin.patch(`/api/admin/jump-hosts/${jumpId}`, { enabled: false });
    expect(String((await live.next!((m) => m.type === 'exit')).reason)).toMatch(/jump host/i);

    const blocked = await openTerminal(admin, adminServerId);
    expect((await blocked.next!((m) => m.type === 'error')).code).toBe('jump_unavailable');

    await admin.del(`/api/admin/jump-hosts/${jumpId}`);
    const gone = await openTerminal(admin, adminServerId);
    expect((await gone.next!((m) => m.type === 'error')).code).toBe('jump_unavailable');
    // Never quietly connected directly.
    expect(built.ctx.db.prepare('SELECT jump_mode FROM servers WHERE id = ?').get(adminServerId)).toMatchObject({ jump_mode: 'fixed' });
  });
});

describe('reconnectable sessions', () => {
  let serverId: string;
  beforeAll(async () => {
    await admin.patch(`/api/servers/${adminServerId}`, { jumpMode: 'none' }).catch(() => {});
    built.ctx.db.prepare("UPDATE servers SET jump_mode = 'none', jump_host_id = NULL WHERE id = ?").run(adminServerId);
    serverId = adminServerId;
  });

  it('keeps a terminal alive after the browser drops, replays missed output and accepts input again', async () => {
    const t = await openTerminal(admin, serverId);
    const ready = await t.next!((m) => m.type === 'ready');
    t.send!({ type: 'input', data: 'before' });
    await t.next!((m) => m.type === 'data' && String(m.data).includes('BEFORE'));
    t.ws!.terminate();
    await new Promise((r) => setTimeout(r, 150));

    const again = await openTerminal(admin, serverId, { resume: ready.session });
    const replay = await again.next!((m) => m.type === 'replay');
    expect(String(replay.data)).toContain('welcome');
    expect(String(replay.data)).toContain('BEFORE');
    await again.next!((m) => m.type === 'ready');
    again.send!({ type: 'input', data: 'after' });
    await again.next!((m) => m.type === 'data' && String(m.data).includes('AFTER'));
    const actions = (built.ctx.db.prepare('SELECT action FROM audit_log').all() as { action: string }[]).map((r) => r.action);
    expect(actions).toEqual(expect.arrayContaining(['ssh.session_detach', 'ssh.session_resume']));
    again.ws!.close();
  });

  it('cannot be resumed by anyone else, or twice from a live connection that is not detached', async () => {
    const t = await openTerminal(admin, serverId);
    const ready = await t.next!((m) => m.type === 'ready');
    // Still attached: nothing to resume yet.
    expect((await admin.post(`/api/servers/${serverId}/connect`, { resume: ready.session })).status).toBe(404);
    t.ws!.terminate();
    await new Promise((r) => setTimeout(r, 150));
    expect((await other.post(`/api/servers/${serverId}/connect`, { resume: ready.session })).status).toBe(404);
    expect((await admin.post(`/api/servers/${serverId}/connect`, { resume: 'x'.repeat(43) })).status).toBe(404);
    const again = await openTerminal(admin, serverId, { resume: ready.session });
    await again.next!((m) => m.type === 'ready');
    again.ws!.close();
  });

  it('closes at once when keeping sessions is turned off', async () => {
    const limits = (await admin.get('/api/admin/settings')).body.limits;
    expect((await admin.put('/api/admin/settings/limits', { maxTerminalsPerUser: limits.maxTerminalsPerUser, detachMinutes: 0 })).status).toBe(200);
    const t = await openTerminal(admin, serverId);
    const ready = await t.next!((m) => m.type === 'ready');
    t.ws!.terminate();
    await new Promise((r) => setTimeout(r, 150));
    expect((await admin.post(`/api/servers/${serverId}/connect`, { resume: ready.session })).status).toBe(404);
    await admin.put('/api/admin/settings/limits', { maxTerminalsPerUser: limits.maxTerminalsPerUser, detachMinutes: 5 });
  });

  it('does not resume into a locked session, and ends a detached terminal when its web session ends', async () => {
    await admin.put(`/api/servers/${serverId}/shares/${userId}`, { permission: 'use' });
    const t = await openTerminal(user, serverId);
    const ready = await t.next!((m) => m.type === 'ready');
    t.ws!.terminate();
    await new Promise((r) => setTimeout(r, 150));

    await user.post('/api/auth/lock');
    const locked = await user.post(`/api/servers/${serverId}/connect`, { resume: ready.session });
    expect(locked.status).toBe(401);
    expect(locked.body.code).toBe('session_locked');
    expect((await user.post('/api/auth/unlock', { password: userPassword })).status).toBe(200);

    await user.post('/api/auth/logout');
    await user.post('/api/auth/login', { username: 'alice', password: userPassword });
    expect((await user.post(`/api/servers/${serverId}/connect`, { resume: ready.session })).status).toBe(404);
  });
});
