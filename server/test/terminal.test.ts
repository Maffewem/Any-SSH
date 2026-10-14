import type { AddressInfo } from 'node:net';
import ssh2 from 'ssh2';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import type { BuiltApp } from '../src/app.js';
import { createUser, makeApp, setupAdmin, type Client } from './helpers.js';

const { Server, utils } = ssh2;

/** A tiny SSH server that accepts the given public keys and echoes the shell back, upper-cased. */
function startFakeSshd(allowedPublicKeys: string[], hostKey: string): Promise<{ port: number; close(): void }> {
  const allowed = allowedPublicKeys.map((k) => {
    const parsed = utils.parseKey(k);
    if (parsed instanceof Error || Array.isArray(parsed)) throw new Error('bad key');
    return parsed;
  });
  const server = new Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => {
      const match = ctx.method === 'publickey' && allowed.find((k) => ctx.key.algo === k.type && ctx.key.data.equals(k.getPublicSSH()));
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
    client.on('error', () => {});
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ port: (server.address() as AddressInfo).port, close: () => server.close() });
    });
  });
}

let built: BuiltApp;
let origin: string;
let owner: Client;
let sharee: Client;
let shareePassword: string;
let serverId: string;
let sshd: { port: number; close(): void };
/** A key the fake sshd accepts but Any-SSH has never stored. */
let oneOffKey: string;

beforeAll(async () => {
  built = await makeApp({ allowLoopbackTargets: true });
  await built.app.listen({ host: '127.0.0.1', port: 0 });
  origin = `http://127.0.0.1:${(built.app.server.address() as AddressInfo).port}`;
  built.ctx.config.allowedOrigins = [origin];

  const admin = await setupAdmin(built);
  const o = await createUser(built, admin, 'owner');
  const s = await createUser(built, admin, 'sharee');
  owner = o.client;
  sharee = s.client;
  shareePassword = s.password;

  const key = (await owner.post('/api/keys/generate', { name: 'k' })).body.key;
  const oneOff = utils.generateKeyPairSync('ed25519');
  oneOffKey = oneOff.private;
  sshd = await startFakeSshd([key.publicKey, oneOff.public], utils.generateKeyPairSync('ed25519').private);
  serverId = (
    await owner.post('/api/servers', { name: 'box', host: '127.0.0.1', port: sshd.port, username: 'me', authMethod: 'key', keyId: key.id })
  ).body.server.id;
  await owner.put(`/api/servers/${serverId}/shares/${s.id}`, { permission: 'use' });
});

afterAll(async () => {
  sshd?.close();
  await built?.app.close();
});

type Msg = { type: string; [k: string]: unknown };

async function openTerminal(client: Client, opts: { origin?: string; connect?: Record<string, unknown> } = {}) {
  const { ticket } = (await client.post(`/api/servers/${serverId}/connect`, opts.connect ?? {})).body;
  const ws = new WebSocket(`${origin.replace('http', 'ws')}/api/terminal?ticket=${ticket}&cols=80&rows=24`, {
    headers: { origin: opts.origin ?? origin, cookie: client.cookie },
  });
  const messages: Msg[] = [];
  const waiters: { pred: (m: Msg) => boolean; resolve: (m: Msg) => void }[] = [];
  ws.on('message', (raw) => {
    const m = JSON.parse(raw.toString()) as Msg;
    messages.push(m);
    for (const w of [...waiters]) if (w.pred(m)) {
      waiters.splice(waiters.indexOf(w), 1);
      w.resolve(m);
    }
  });
  const next = (pred: (m: Msg) => boolean) =>
    new Promise<Msg>((resolve, reject) => {
      const hit = messages.find(pred);
      if (hit) return resolve(hit);
      waiters.push({ pred, resolve });
      setTimeout(() => reject(new Error(`timeout; got ${JSON.stringify(messages)}`)), 5000);
    });
  const send = (m: Msg) => ws.send(JSON.stringify(m));
  return { ws, next, send, messages, ticket: ticket as string };
}

describe('terminal over WebSocket', () => {
  it('refuses a sharee until the owner has verified the host key', async () => {
    const t = await openTerminal(sharee);
    const err = await t.next((m) => m.type === 'error');
    expect(err.code).toBe('host_key_unverified');
    t.ws.close();
  });

  it('asks the owner to trust an unknown host key, then runs a shell', async () => {
    const t = await openTerminal(owner);
    const prompt = await t.next((m) => m.type === 'hostkey');
    expect(prompt.fingerprint).toMatch(/^SHA256:/);
    t.send({ type: 'hostkey', accept: true });
    await t.next((m) => m.type === 'ready');
    await t.next((m) => m.type === 'data' && String(m.data).includes('welcome'));
    t.send({ type: 'input', data: 'hello' });
    await t.next((m) => m.type === 'data' && String(m.data).includes('HELLO'));
    t.ws.close();
  });

  it('lets the sharee connect with the owner’s key once the host key is pinned', async () => {
    const t = await openTerminal(sharee);
    await t.next((m) => m.type === 'ready');
    t.send({ type: 'input', data: 'shared' });
    await t.next((m) => m.type === 'data' && String(m.data).includes('SHARED'));
    expect(t.messages.some((m) => m.type === 'hostkey')).toBe(false);
    t.ws.close();
  });

  it('pauses a live terminal while the session is locked and resumes it on unlock', async () => {
    const t = await openTerminal(sharee);
    await t.next((m) => m.type === 'ready');
    await sharee.post('/api/auth/lock');
    await t.next((m) => m.type === 'locked');
    // Keystrokes from a locked browser never reach the server.
    t.send({ type: 'input', data: 'sneaky' });
    await new Promise((r) => setTimeout(r, 200));
    expect(t.messages.some((m) => m.type === 'data' && String(m.data).includes('SNEAKY'))).toBe(false);

    const unlocked = await sharee.post('/api/auth/unlock', { password: shareePassword });
    expect(unlocked.status).toBe(200);
    await t.next((m) => m.type === 'unlocked');
    t.send({ type: 'input', data: 'back' });
    await t.next((m) => m.type === 'data' && String(m.data).includes('BACK'));
    t.ws.close();
  });

  it('closes the sharee’s live terminal the moment access is revoked', async () => {
    const t = await openTerminal(sharee);
    await t.next((m) => m.type === 'ready');
    const shareeId = (await sharee.get('/api/auth/me')).body.user.id;
    await owner.del(`/api/servers/${serverId}/shares/${shareeId}`);
    const exit = await t.next((m) => m.type === 'exit');
    expect(String(exit.reason)).toMatch(/access/);
    await owner.put(`/api/servers/${serverId}/shares/${shareeId}`, { permission: 'use' });
  });

  it('connects with a one-off key that is never stored, and refuses one the server does not know', async () => {
    const accepted = utils.generateKeyPairSync('ed25519');
    const keys = () => (built.ctx.db.prepare('SELECT COUNT(*) AS n FROM ssh_keys').get() as { n: number }).n;
    const before = keys();

    // A key the fake sshd does not accept fails authentication rather than being quietly ignored.
    const stranger = await openTerminal(sharee, { connect: { credential: { type: 'oneoff', privateKey: accepted.private } } });
    expect((await stranger.next((m) => m.type === 'error')).code).toBe('ssh_error');
    stranger.ws.close();
    expect(keys()).toBe(before);

    // The key the sshd does accept gets a shell, and still leaves nothing behind.
    const t = await openTerminal(sharee, { connect: { credential: { type: 'oneoff', privateKey: oneOffKey } } });
    await t.next((m) => m.type === 'ready');
    t.send({ type: 'input', data: 'oneoff' });
    await t.next((m) => m.type === 'data' && String(m.data).includes('ONEOFF'));
    t.ws.close();
    expect(keys()).toBe(before);
    const stored = JSON.stringify(built.ctx.db.prepare('SELECT * FROM audit_log').all());
    expect(stored).not.toContain('PRIVATE KEY');
    expect(stored).toContain('one_off_key');
  });

  it('stops a sharee using the owner’s credentials once the owner requires their own', async () => {
    const shareeId = (await sharee.get('/api/auth/me')).body.user.id;
    const live = await openTerminal(sharee);
    await live.next((m) => m.type === 'ready');

    await owner.put(`/api/servers/${serverId}/shares/${shareeId}`, { permission: 'use', credentials: 'own' });
    expect(String((await live.next((m) => m.type === 'exit')).reason)).toMatch(/own credentials/i);
    expect((await sharee.post(`/api/servers/${serverId}/connect`)).body.code).toBe('own_credentials_required');

    // A one-off key of their own still works.
    const t = await openTerminal(sharee, { connect: { credential: { type: 'oneoff', privateKey: oneOffKey } } });
    await t.next((m) => m.type === 'ready');
    t.ws.close();

    await owner.put(`/api/servers/${serverId}/shares/${shareeId}`, { permission: 'use', credentials: 'owner' });
  });

  it('refuses a changed host key', async () => {
    built.ctx.db.prepare("UPDATE servers SET host_key_fingerprint = 'SHA256:not-the-real-one' WHERE id = ?").run(serverId);
    const t = await openTerminal(owner);
    const err = await t.next((m) => m.type === 'error');
    expect(err.code).toBe('host_key_mismatch');
    const actions = (built.ctx.db.prepare('SELECT action FROM audit_log').all() as { action: string }[]).map((r) => r.action);
    expect(actions).toContain('ssh.host_key_mismatch');
  });

  it('rejects reused tickets and foreign origins', async () => {
    const t = await openTerminal(owner, { origin: 'https://evil.example' });
    expect((await t.next((m) => m.type === 'error')).code).toBe('bad_origin');

    const reuse = new WebSocket(`${origin.replace('http', 'ws')}/api/terminal?ticket=${t.ticket}`, {
      headers: { origin, cookie: owner.cookie },
    });
    const msg = await new Promise<Msg>((resolve) => reuse.on('message', (raw) => resolve(JSON.parse(raw.toString()))));
    expect(msg.code).toBe('unauthorized');
  });
});
