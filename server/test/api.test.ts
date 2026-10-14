import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { BuiltApp } from '../src/app.js';
import { hotp, totpCounter } from '../src/totp.js';
import ssh2 from 'ssh2';
import { ADMIN_PASSWORD, Client, createUser, makeApp, setupAdmin } from './helpers.js';

let built: BuiltApp;
beforeEach(async () => {
  built = await makeApp();
});
afterEach(async () => {
  await built.app.close();
});

describe('first-run setup', () => {
  it('needs the one-time token and only works once', async () => {
    const c = new Client(built);
    expect((await c.get('/api/setup')).body).toEqual({ needed: true });
    expect((await c.post('/api/setup', { setupToken: 'nope', username: 'admin', password: ADMIN_PASSWORD })).status).toBe(403);
    expect((await c.post('/api/setup', { setupToken: built.setup.token, username: 'admin', password: 'short' })).status).toBe(400);
    const ok = await c.post('/api/setup', { setupToken: built.setup.token, username: 'admin', password: ADMIN_PASSWORD });
    expect(ok.status).toBe(200);
    expect(ok.body.user.role).toBe('admin');
    expect((await c.get('/api/setup')).body).toEqual({ needed: false });
    expect((await c.post('/api/setup', { setupToken: 'x', username: 'evil', password: ADMIN_PASSWORD })).status).toBe(403);
  });
});

describe('authentication', () => {
  it('requires the CSRF header on writes', async () => {
    await setupAdmin(built);
    const res = await built.app.inject({ method: 'POST', url: '/api/auth/login', payload: { username: 'admin', password: ADMIN_PASSWORD } });
    expect(res.statusCode).toBe(403);
  });

  it('rejects foreign origins', async () => {
    const admin = await setupAdmin(built);
    const res = await admin.req('POST', '/api/auth/logout', {}, { origin: 'https://evil.example' });
    expect(res.status).toBe(403);
  });

  it('sets a hardened session cookie and stores only its hash', async () => {
    await setupAdmin(built);
    const res = await built.app.inject({
      method: 'POST', url: '/api/auth/login', headers: { 'x-any-ssh': '1' }, payload: { username: 'admin', password: ADMIN_PASSWORD },
    });
    const cookie = res.cookies[0]!;
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.sameSite).toBe('Strict');
    const rows = built.ctx.db.prepare('SELECT id_hash FROM sessions').all() as { id_hash: string }[];
    expect(rows.some((r) => r.id_hash === cookie.value)).toBe(false);
  });

  it('gives the same error for unknown users and bad passwords, and locks out after 5 failures', async () => {
    await setupAdmin(built);
    const c = new Client(built);
    const unknown = await c.post('/api/auth/login', { username: 'ghost', password: 'whatever-password' });
    const bad = await c.post('/api/auth/login', { username: 'admin', password: 'wrong-password' });
    expect(unknown.status).toBe(401);
    expect(bad.body.error).toBe(unknown.body.error);
    for (let i = 0; i < 4; i++) await c.post('/api/auth/login', { username: 'admin', password: 'wrong-password' });
    const locked = await c.post('/api/auth/login', { username: 'admin', password: ADMIN_PASSWORD });
    expect(locked.status).toBe(401);
  });

  it('logout kills the session', async () => {
    const admin = await setupAdmin(built);
    const cookie = admin.cookie;
    await admin.post('/api/auth/logout');
    const replay = new Client(built);
    replay.cookie = cookie;
    expect((await replay.get('/api/auth/me')).status).toBe(401);
  });
});

describe('user administration', () => {
  it('admin creates a user who must change the temporary password', async () => {
    const admin = await setupAdmin(built);
    const created = await admin.post('/api/admin/users', { username: 'alice' });
    expect(created.status).toBe(200);
    expect(created.body.temporaryPassword).toHaveLength(20);

    const alice = new Client(built);
    await alice.post('/api/auth/login', { username: 'alice', password: created.body.temporaryPassword });
    expect((await alice.get('/api/servers')).body.code).toBe('password_change_required');
    const changed = await alice.post('/api/auth/password', {
      currentPassword: created.body.temporaryPassword, newPassword: 'tangerine-river-blueprint',
    });
    expect(changed.status).toBe(200);
    expect((await alice.get('/api/servers')).status).toBe(200);
  });

  it('non-admins cannot reach admin endpoints', async () => {
    const admin = await setupAdmin(built);
    const { client } = await createUser(built, admin, 'bob');
    expect((await client.get('/api/admin/users')).status).toBe(403);
    expect((await client.post('/api/admin/users', { username: 'mallory', role: 'admin' })).status).toBe(403);
  });

  it('disabling a user ends their sessions; last admin is protected', async () => {
    const admin = await setupAdmin(built);
    const { client, id } = await createUser(built, admin, 'carol');
    await admin.patch(`/api/admin/users/${id}`, { status: 'disabled' });
    expect((await client.get('/api/auth/me')).status).toBe(401);

    const me = (await admin.get('/api/auth/me')).body.user.id;
    expect((await admin.patch(`/api/admin/users/${me}`, { role: 'user' })).status).toBe(400);
    expect((await admin.del(`/api/admin/users/${me}`)).status).toBe(400);
  });
});

describe('MFA', () => {
  it('enrols TOTP, then requires it at login, with single-use recovery codes', async () => {
    const admin = await setupAdmin(built);
    const setup = await admin.post('/api/auth/mfa/setup', { password: ADMIN_PASSWORD });
    expect(setup.body.uri).toMatch(/^otpauth:\/\/totp\//);
    const secret = setup.body.secret as string;
    const enable = await admin.post('/api/auth/mfa/enable', { code: hotp(secret, totpCounter()) });
    expect(enable.status).toBe(200);
    const recovery = enable.body.recoveryCodes as string[];
    expect(recovery).toHaveLength(10);

    const c = new Client(built);
    const step1 = await c.post('/api/auth/login', { username: 'admin', password: ADMIN_PASSWORD });
    expect(step1.body).toEqual({ mfaRequired: true });
    // Half-logged-in sessions cannot use the API.
    expect((await c.get('/api/servers')).status).toBe(401);
    expect((await c.post('/api/auth/mfa', { code: '000000' })).status).toBe(401);
    const step2 = await c.post('/api/auth/mfa', { recoveryCode: recovery[0] });
    expect(step2.status).toBe(200);
    expect((await c.get('/api/servers')).status).toBe(200);

    const again = new Client(built);
    await again.post('/api/auth/login', { username: 'admin', password: ADMIN_PASSWORD });
    expect((await again.post('/api/auth/mfa', { recoveryCode: recovery[0] })).status).toBe(401);
  });

  it('stores the TOTP secret encrypted', async () => {
    const admin = await setupAdmin(built);
    const setup = await admin.post('/api/auth/mfa/setup', { password: ADMIN_PASSWORD });
    const row = built.ctx.db.prepare("SELECT totp_secret_enc FROM users WHERE username = 'admin'").get() as { totp_secret_enc: string };
    expect(row.totp_secret_enc).not.toContain(setup.body.secret);
  });
});

describe('SSH keys', () => {
  it('generates and imports keys without ever returning or storing plaintext private keys', async () => {
    const admin = await setupAdmin(built);
    const gen = await admin.post('/api/keys/generate', { name: 'laptop' });
    expect(gen.status).toBe(200);
    expect(gen.body.key.publicKey).toMatch(/^ssh-ed25519 /);
    expect(gen.body.key.fingerprint).toMatch(/^SHA256:/);
    expect(JSON.stringify(gen.body)).not.toMatch(/PRIVATE KEY/);

    const row = built.ctx.db.prepare('SELECT private_key_enc FROM ssh_keys').get() as { private_key_enc: string };
    expect(row.private_key_enc).not.toMatch(/PRIVATE KEY/);

    const list = await admin.get('/api/keys');
    expect(JSON.stringify(list.body)).not.toMatch(/PRIVATE KEY|private_key_enc/);

    expect((await admin.post('/api/keys/import', { name: 'bad', privateKey: 'not a key' })).status).toBe(400);
    const pub = gen.body.key.publicKey as string;
    expect((await admin.post('/api/keys/import', { name: 'pub', privateKey: pub })).status).toBe(400);
  });

  it("users cannot see or use each other's keys", async () => {
    const admin = await setupAdmin(built);
    const key = (await admin.post('/api/keys/generate', { name: 'admin-key' })).body.key;
    const { client: dave } = await createUser(built, admin, 'dave');
    expect((await dave.get('/api/keys')).body.keys).toEqual([]);
    expect((await dave.del(`/api/keys/${key.id}`)).status).toBe(404);
    const res = await dave.post('/api/servers', { name: 's', host: 'example.com', username: 'root', authMethod: 'key', keyId: key.id });
    expect(res.status).toBe(400);
  });
});

describe('servers and sharing', () => {
  async function scenario() {
    const admin = await setupAdmin(built);
    const owner = await createUser(built, admin, 'owner');
    const user = await createUser(built, admin, 'user1');
    const manager = await createUser(built, admin, 'manager');
    const outsider = await createUser(built, admin, 'outsider');
    const key = (await owner.client.post('/api/keys/generate', { name: 'k' })).body.key;
    const server = (
      await owner.client.post('/api/servers', { name: 'prod', host: 'prod.example.com', username: 'deploy', authMethod: 'key', keyId: key.id })
    ).body.server;
    return { admin, owner, user, manager, outsider, key, server };
  }

  it('shares with multiple users at different permission levels', async () => {
    const { owner, user, manager, outsider, server } = await scenario();
    expect((await owner.client.put(`/api/servers/${server.id}/shares/${user.id}`, { permission: 'use' })).status).toBe(200);
    expect((await owner.client.put(`/api/servers/${server.id}/shares/${manager.id}`, { permission: 'manage' })).status).toBe(200);

    const seen = (await user.client.get('/api/servers')).body.servers;
    expect(seen).toHaveLength(1);
    expect(seen[0].access).toBe('use');
    expect(seen[0].key).toBeNull(); // sharees never learn which key is used

    // Outsiders get 404, not 403: the server's existence is not disclosed.
    expect((await outsider.client.get(`/api/servers/${server.id}`)).status).toBe(404);
    expect((await outsider.client.post(`/api/servers/${server.id}/connect`)).status).toBe(404);

    // "use" can connect but not edit.
    expect((await user.client.post(`/api/servers/${server.id}/connect`)).body.ticket).toBeTruthy();
    expect((await user.client.patch(`/api/servers/${server.id}`, { name: 'x' })).status).toBe(403);

    // "manage" can rename, but cannot repoint the server, delete it, or re-share it by default.
    expect((await manager.client.patch(`/api/servers/${server.id}`, { name: 'production' })).status).toBe(200);
    expect((await manager.client.patch(`/api/servers/${server.id}`, { host: 'attacker.example' })).status).toBe(403);
    expect((await manager.client.put(`/api/servers/${server.id}/shares/${outsider.id}`, { permission: 'use' })).status).toBe(403);
    expect((await manager.client.del(`/api/servers/${server.id}`)).status).toBe(403);

    // Once the owner allows re-sharing, the manager can hand out "use" but still not "manage".
    await owner.client.put(`/api/servers/${server.id}/shares/${manager.id}`, { permission: 'manage', canReshare: true });
    expect((await manager.client.put(`/api/servers/${server.id}/shares/${outsider.id}`, { permission: 'manage' })).status).toBe(403);
    expect((await manager.client.put(`/api/servers/${server.id}/shares/${outsider.id}`, { permission: 'use' })).status).toBe(200);

    const shares = (await owner.client.get(`/api/servers/${server.id}/shares`)).body.shares;
    expect(shares.map((s: { username: string }) => s.username).sort()).toEqual(['manager', 'outsider', 'user1']);

    // Revocation is immediate.
    await owner.client.del(`/api/servers/${server.id}/shares/${user.id}`);
    expect((await user.client.post(`/api/servers/${server.id}/connect`)).status).toBe(404);
  });

  it('only lets a manager re-share when the owner allowed it, and never beyond their own grant', async () => {
    const { owner, manager, outsider, server } = await scenario();
    await owner.client.put(`/api/servers/${server.id}/shares/${manager.id}`, { permission: 'manage' });

    // Default is no re-sharing, and a manager cannot grant themselves the right.
    expect((await owner.client.get(`/api/servers/${server.id}/shares`)).body.shares[0].canReshare).toBe(false);
    const blocked = await manager.client.put(`/api/servers/${server.id}/shares/${outsider.id}`, { permission: 'use' });
    expect(blocked.status).toBe(403);
    expect(blocked.body.error).toMatch(/not allowed you to share/i);
    expect(
      (await manager.client.put(`/api/servers/${server.id}/shares/${manager.id}`, { permission: 'manage', canReshare: true })).status,
    ).toBe(400);

    // A manager who must bring their own credentials cannot pass the owner's on to anyone else.
    await owner.client.put(`/api/servers/${server.id}/shares/${manager.id}`, { permission: 'manage', canReshare: true, credentials: 'own' });
    expect((await manager.client.put(`/api/servers/${server.id}/shares/${outsider.id}`, { permission: 'use' })).status).toBe(403);
    expect(
      (await manager.client.put(`/api/servers/${server.id}/shares/${outsider.id}`, { permission: 'use', credentials: 'own' })).status,
    ).toBe(200);
    const outsiderShare = (await owner.client.get(`/api/servers/${server.id}/shares`)).body.shares.find(
      (s: { username: string }) => s.username === 'outsider',
    );
    expect(outsiderShare).toMatchObject({ credentials: 'own', canReshare: false, sharedBy: 'manager' });

    // Withdrawing re-sharing takes effect at once.
    await owner.client.put(`/api/servers/${server.id}/shares/${manager.id}`, { permission: 'manage', canReshare: false });
    expect((await manager.client.put(`/api/servers/${server.id}/shares/${outsider.id}`, { permission: 'use' })).status).toBe(403);
  });

  it('lets the owner say whose credentials a share connects with', async () => {
    const { owner, user, server, key } = await scenario();
    await owner.client.put(`/api/servers/${server.id}/shares/${user.id}`, { permission: 'use', credentials: 'own' });
    const seen = (await user.client.get('/api/servers')).body.servers[0];
    expect(seen.credentials).toBe('own');
    expect(seen.canShare).toBe(false);

    // The owner's saved key is off limits; their own key, a one-off key or a password prompt are not.
    const saved = await user.client.post(`/api/servers/${server.id}/connect`);
    expect(saved.status).toBe(400);
    expect(saved.body.code).toBe('own_credentials_required');
    expect((await user.client.post(`/api/servers/${server.id}/connect`, { credential: { type: 'password' } })).body.ticket).toBeTruthy();

    const ownKey = (await user.client.post('/api/keys/generate', { name: 'mine' })).body.key;
    expect(
      (await user.client.post(`/api/servers/${server.id}/connect`, { credential: { type: 'key', keyId: ownKey.id } })).body.ticket,
    ).toBeTruthy();
    // Someone else's stored key is not a credential you may pick.
    expect((await user.client.post(`/api/servers/${server.id}/connect`, { credential: { type: 'key', keyId: key.id } })).status).toBe(400);

    // Switching back to the owner's credentials restores the plain connect.
    await owner.client.put(`/api/servers/${server.id}/shares/${user.id}`, { permission: 'use', credentials: 'owner' });
    expect((await user.client.post(`/api/servers/${server.id}/connect`)).body.ticket).toBeTruthy();
  });

  it('takes a one-off private key without ever storing it', async () => {
    const { owner, server } = await scenario();
    const before = (built.ctx.db.prepare('SELECT COUNT(*) AS n FROM ssh_keys').get() as { n: number }).n;
    const pair = ssh2.utils.generateKeyPairSync('ed25519');

    expect((await owner.client.post(`/api/servers/${server.id}/connect`, { credential: { type: 'oneoff', privateKey: 'not a key' } })).status).toBe(400);
    const res = await owner.client.post(`/api/servers/${server.id}/connect`, {
      credential: { type: 'oneoff', privateKey: pair.private },
      username: 'someone-else',
    });
    expect(res.body.ticket).toBeTruthy();
    expect((built.ctx.db.prepare('SELECT COUNT(*) AS n FROM ssh_keys').get() as { n: number }).n).toBe(before);
    const rows = JSON.stringify(built.ctx.db.prepare('SELECT * FROM servers').all());
    expect(rows).not.toContain('PRIVATE KEY');
  });

  it('exports a private key only to its owner, and only with the password', async () => {
    const { admin, owner, user } = await scenario();
    const key = (await owner.client.post('/api/keys/generate', { name: 'work servers', type: 'ed25519' })).body.key;

    expect((await owner.client.post(`/api/keys/${key.id}/export`, { password: 'wrong-password-here' })).status).toBe(400);
    expect((await user.client.post(`/api/keys/${key.id}/export`, { password: user.password })).status).toBe(404);

    const res = await owner.client.post(`/api/keys/${key.id}/export`, { password: owner.password });
    expect(res.status).toBe(200);
    expect(res.body.privateKey).toContain('PRIVATE KEY');
    expect(res.body.filename).toBe('id_ed25519_work-servers');
    expect(res.body.passphraseProtected).toBe(false);
    // The export is recorded, without the key material.
    const log = JSON.stringify((await admin.get('/api/admin/audit?limit=500')).body);
    expect(log).toContain('key.export');
    expect(log).not.toContain('PRIVATE KEY');
  });

  it('stores passwords encrypted and resets host key pin when the endpoint changes', async () => {
    const { owner } = await scenario();
    const s = (
      await owner.client.post('/api/servers', { name: 'pw', host: '10.0.0.5', username: 'root', authMethod: 'password', password: 'hunter2-hunter2' })
    ).body.server;
    expect(s.hasStoredPassword).toBe(true);
    const row = built.ctx.db.prepare('SELECT password_enc FROM servers WHERE id = ?').get(s.id) as { password_enc: string };
    expect(row.password_enc).not.toContain('hunter2');

    built.ctx.db.prepare("UPDATE servers SET host_key_fingerprint = 'SHA256:abc' WHERE id = ?").run(s.id);
    await owner.client.patch(`/api/servers/${s.id}`, { notes: 'hi' });
    expect((await owner.client.get(`/api/servers/${s.id}`)).body.server.hostKeyFingerprint).toBe('SHA256:abc');
    await owner.client.patch(`/api/servers/${s.id}`, { host: '10.0.0.6' });
    expect((await owner.client.get(`/api/servers/${s.id}`)).body.server.hostKeyFingerprint).toBeNull();
  });

  it('admins do not get implicit access to other people’s servers', async () => {
    const { admin, server } = await scenario();
    expect((await admin.get(`/api/servers/${server.id}`)).status).toBe(404);
  });

  it('writes an intact audit trail without secrets', async () => {
    const { admin, owner, user, server } = await scenario();
    await owner.client.put(`/api/servers/${server.id}/shares/${user.id}`, { permission: 'use' });
    const log = await admin.get('/api/admin/audit?limit=500');
    const actions = log.body.entries.map((e: { action: string }) => e.action);
    expect(actions).toContain('share.grant');
    expect(actions).toContain('key.generate');
    expect(actions).toContain('admin.user_create');
    expect(JSON.stringify(log.body)).not.toMatch(/PRIVATE KEY|Str0ng-passphrase|temporaryPassword/);
    expect((await admin.get('/api/admin/audit/verify')).body.ok).toBe(true);
  });
});

describe('version and update check', () => {
  it('is admin only and reports no update when checks are off', async () => {
    const off = await makeApp({ updateCheck: false });
    try {
      const admin = await setupAdmin(off);
      const { client } = await createUser(off, admin, 'bob');
      expect((await client.get('/api/admin/version')).status).toBe(403);
      const v = await admin.post('/api/admin/version/check');
      expect(v.status).toBe(200);
      expect(v.body).toMatchObject({ checkEnabled: false, updateAvailable: null, checkedAt: null });
      expect(v.body.current.version).toBe('dev');
    } finally {
      await off.app.close();
    }
  });

  it('flags a newer published build', async () => {
    const registry = async (url: any) => {
      const u = String(url);
      const json = (o: unknown) => new Response(JSON.stringify(o), { status: 200 });
      if (u.endsWith('/manifests/latest')) return json({ config: { digest: 'sha256:c' } });
      if (u.endsWith('/blobs/sha256:c'))
        return json({ config: { Labels: { 'org.opencontainers.image.revision': 'bbb', 'org.opencontainers.image.created': '2026-02-01T00:00:00Z' } } });
      return new Response('no', { status: 404 });
    };
    const mine = { version: 'dev', commit: 'aaa', builtAt: '2026-01-01T00:00:00Z' };
    const b = await makeApp({ updateCheck: true }, { build: mine, fetch: registry as typeof fetch });
    try {
      const admin = await setupAdmin(b);
      const v = await admin.post('/api/admin/version/check');
      expect(v.body.updateAvailable).toBe(true);
      expect(v.body.latest.commit).toBe('bbb');
    } finally {
      await b.app.close();
    }
  });
});
