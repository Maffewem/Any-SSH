import { randomBytes } from 'node:crypto';
import ssh2 from 'ssh2';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SecretBox } from '../src/crypto.js';
import { rotateSecrets } from '../src/rotate.js';
import { hotp, totpCounter } from '../src/totp.js';
import { ADMIN_PASSWORD, Client, createUser, lastLinkToken, makeApp, setupAdmin } from './helpers.js';

let built: Awaited<ReturnType<typeof makeApp>>;
beforeEach(async () => {
  built = await makeApp();
});
afterEach(async () => {
  await built.app.close();
});

describe('invites', () => {
  it('admin invites by email; the link sets a password once', async () => {
    const admin = await setupAdmin(built);
    const res = await admin.post('/api/admin/users', { username: 'erin', email: 'erin@example.com' });
    expect(res.status).toBe(200);
    expect(res.body.temporaryPassword).toBeUndefined();
    expect(res.body.invite).toEqual({ purpose: 'invite', sent: true });

    const token = lastLinkToken(built.mail, 'erin@example.com');
    expect(built.mail.sent.at(-1)!.text).toContain('/#/welcome?token=');
    const anon = new Client(built);
    expect((await anon.post('/api/auth/token/check', { token })).body).toMatchObject({ purpose: 'invite', username: 'erin' });
    expect((await anon.post('/api/auth/token/complete', { token, newPassword: 'short' })).status).toBe(400);
    expect((await anon.post('/api/auth/token/complete', { token, newPassword: 'lantern-meadow-quartz-7' })).status).toBe(200);
    expect((await anon.post('/api/auth/token/complete', { token, newPassword: 'another-good-passphrase' })).status).toBe(400);

    const erin = new Client(built);
    const login = await erin.post('/api/auth/login', { username: 'erin', password: 'lantern-meadow-quartz-7' });
    expect(login.body.user.mustChangePassword).toBe(false);
  });

  it('rejects duplicate email addresses', async () => {
    const admin = await setupAdmin(built);
    await admin.post('/api/admin/users', { username: 'a1', email: 'same@example.com' });
    expect((await admin.post('/api/admin/users', { username: 'a2', email: 'SAME@example.com' })).status).toBe(409);
  });
});

describe('password reset', () => {
  async function userWithEmail() {
    const admin = await setupAdmin(built);
    const u = await createUser(built, admin, 'frank');
    expect((await u.client.patch('/api/auth/profile', { email: 'frank@example.com', password: u.password })).status).toBe(200);
    return { admin, ...u };
  }

  it('answers identically for unknown and known accounts', async () => {
    await userWithEmail();
    const anon = new Client(built);
    const before = built.mail.sent.length;
    const unknown = await anon.post('/api/auth/forgot', { identifier: 'nobody' });
    const known = await anon.post('/api/auth/forgot', { identifier: 'frank@example.com' });
    expect(unknown).toEqual(known);
    await new Promise((r) => setTimeout(r, 10));
    expect(built.mail.sent.length).toBe(before + 1);
  });

  it('resets via the emailed link, signs out everywhere and notifies', async () => {
    const { client } = await userWithEmail();
    await new Client(built).post('/api/auth/forgot', { identifier: 'frank' });
    await new Promise((r) => setTimeout(r, 10));
    const token = lastLinkToken(built.mail, 'frank@example.com');

    const done = await new Client(built).post('/api/auth/token/complete', { token, newPassword: 'harbor-violet-engine-42' });
    expect(done.status).toBe(200);
    expect((await client.get('/api/auth/me')).status).toBe(401);
    await new Promise((r) => setTimeout(r, 10));
    expect(built.mail.sent.at(-1)!.subject).toMatch(/security notice/);

    const again = new Client(built);
    expect((await again.post('/api/auth/login', { username: 'frank', password: 'harbor-violet-engine-42' })).status).toBe(200);
  });

  it('throttles repeat requests and only the newest link works', async () => {
    await userWithEmail();
    const anon = new Client(built);
    await anon.post('/api/auth/forgot', { identifier: 'frank' });
    await new Promise((r) => setTimeout(r, 10));
    const first = lastLinkToken(built.mail, 'frank@example.com');
    const count = built.mail.sent.length;
    await anon.post('/api/auth/forgot', { identifier: 'frank' });
    expect(built.mail.sent.length).toBe(count);

    // Admin-triggered link replaces the earlier one.
    const id = (built.ctx.db.prepare("SELECT id FROM users WHERE username = 'frank'").get() as { id: string }).id;
    const admin = new Client(built);
    await admin.post('/api/auth/login', { username: 'admin', password: ADMIN_PASSWORD });
    expect((await admin.post(`/api/admin/users/${id}/send-link`)).body).toMatchObject({ purpose: 'reset', sent: true });
    expect((await anon.post('/api/auth/token/check', { token: first })).status).toBe(400);
  });

  it('expired links do not work', async () => {
    await userWithEmail();
    await new Client(built).post('/api/auth/forgot', { identifier: 'frank' });
    await new Promise((r) => setTimeout(r, 10));
    const token = lastLinkToken(built.mail, 'frank@example.com');
    built.ctx.db.prepare('UPDATE auth_tokens SET expires_at = 0').run();
    expect((await new Client(built).post('/api/auth/token/complete', { token, newPassword: 'harbor-violet-engine-42' })).status).toBe(400);
  });

  it('does not bypass two-factor', async () => {
    const admin = await setupAdmin(built);
    await admin.patch('/api/auth/profile', { email: 'admin@example.com', password: ADMIN_PASSWORD });
    const { secret } = (await admin.post('/api/auth/mfa/setup', { password: ADMIN_PASSWORD })).body;
    await admin.post('/api/auth/mfa/enable', { code: hotp(secret, totpCounter()) });

    await new Client(built).post('/api/auth/forgot', { identifier: 'admin' });
    await new Promise((r) => setTimeout(r, 10));
    const token = lastLinkToken(built.mail, 'admin@example.com');
    await new Client(built).post('/api/auth/token/complete', { token, newPassword: 'harbor-violet-engine-42' });
    const c = new Client(built);
    expect((await c.post('/api/auth/login', { username: 'admin', password: 'harbor-violet-engine-42' })).body).toEqual({ mfaRequired: true });
  });

  it('changing email needs the password and warns the old address', async () => {
    const { client, password } = await userWithEmail();
    expect((await client.patch('/api/auth/profile', { email: 'evil@example.com' })).status).toBe(400);
    expect((await client.patch('/api/auth/profile', { email: 'evil@example.com', password: 'wrong' })).status).toBe(400);
    expect((await client.patch('/api/auth/profile', { email: 'new@example.com', password })).status).toBe(200);
    await new Promise((r) => setTimeout(r, 10));
    const notice = built.mail.sent.at(-1)!;
    expect(notice.to).toBe('frank@example.com');
    expect(notice.text).toContain('new@example.com');
  });
});

describe('SSH key storage', () => {
  it('re-seals every secret under a new master key', async () => {
    const admin = await setupAdmin(built);
    const key = (await admin.post('/api/keys/generate', { name: 'k' })).body.key;
    await admin.post('/api/servers', { name: 'pw', host: '10.0.0.9', username: 'root', authMethod: 'password', password: 'pw-123456789' });
    await admin.post('/api/auth/mfa/setup', { password: ADMIN_PASSWORD });

    const oldBox = built.ctx.box;
    const newKey = randomBytes(32);
    const result = rotateSecrets(built.ctx.db, new SecretBox(newKey, [built.ctx.config.masterKey]));
    expect(result).toEqual({ resealed: 3, remainingStale: 0 });

    const row = built.ctx.db.prepare('SELECT private_key_enc FROM ssh_keys WHERE id = ?').get(key.id) as { private_key_enc: string };
    expect(() => oldBox.open(row.private_key_enc, `ssh_key:${key.id}:private`)).toThrow();
    const pem = new SecretBox(newKey).openString(row.private_key_enc, `ssh_key:${key.id}:private`);
    expect(pem).toContain('OPENSSH PRIVATE KEY');
  });

  it('refuses weak imported keys', async () => {
    const admin = await setupAdmin(built);
    const weak = ssh2.utils.generateKeyPairSync('rsa', { bits: 1024 });
    const res = await admin.post('/api/keys/import', { name: 'old', privateKey: weak.private });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/1024 bits/);
    const ok = ssh2.utils.generateKeyPairSync('rsa', { bits: 2048 });
    expect((await admin.post('/api/keys/import', { name: 'ok', privateKey: ok.private })).status).toBe(200);
  });
});
