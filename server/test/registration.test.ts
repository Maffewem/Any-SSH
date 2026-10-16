import { afterEach, describe, expect, it } from 'vitest';
import { buildApp } from '../src/app.js';
import { openDatabase } from '../src/db.js';
import { MemoryMailer } from '../src/mail.js';
import { checkSecrets, rotateSecrets } from '../src/rotate.js';
import { Client, lastLinkToken, makeApp, setupAdmin, testConfig } from './helpers.js';

const smtp = { enabled: true, host: 'smtp.example.com', port: 587, security: 'starttls', username: 'm', password: 'smtp-secret-1', from: 'Any-SSH <a@example.com>' };
const PASSWORD = 'violet-lantern-orchard-77';
const signup = { displayName: 'Ada Lovelace', email: 'ada@example.com', password: PASSWORD };

let built: Awaited<ReturnType<typeof makeApp>>;
afterEach(async () => {
  await built.app.close();
});

async function adminWithMail() {
  built = await makeApp();
  const admin = await setupAdmin(built);
  expect((await admin.put('/api/admin/settings/mail', smtp)).status).toBe(200);
  return admin;
}

describe('registration modes', () => {
  it('is invite-only by default', async () => {
    built = await makeApp();
    const res = await new Client(built).post('/api/auth/register', signup);
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('registration_closed');
    expect((await new Client(built).get('/api/auth/config')).body).toEqual({ registration: 'invite', turnstile: null });
  });

  it('needs working email before registration can be opened', async () => {
    built = await makeApp();
    const admin = await setupAdmin(built);
    const res = await admin.put('/api/admin/settings/registration', { mode: 'open' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/email/i);
  });

  it('open mode: register, confirm the email, sign in with the email address', async () => {
    const admin = await adminWithMail();
    expect((await admin.put('/api/admin/settings/registration', { mode: 'open' })).status).toBe(200);
    const anon = new Client(built);
    expect((await anon.post('/api/auth/register', signup)).body).toEqual({ ok: true });

    // Cannot sign in before confirming.
    expect((await new Client(built).post('/api/auth/login', { username: 'ada@example.com', password: PASSWORD })).status).toBe(401);

    const token = lastLinkToken(built.mail, 'ada@example.com');
    expect((await anon.post('/api/auth/verify', { token })).body).toEqual({ status: 'active' });
    // The link works once.
    expect((await anon.post('/api/auth/verify', { token })).status).toBe(400);

    const me = new Client(built);
    const login = await me.post('/api/auth/login', { username: 'Ada@Example.com', password: PASSWORD });
    expect(login.status).toBe(200);
    expect(login.body.user).toMatchObject({ role: 'user', displayName: 'Ada Lovelace', username: 'ada' });
    // Standard user with no servers and no admin access.
    expect((await me.get('/api/servers')).body).toMatchObject({ servers: [] });
    expect((await me.get('/api/admin/users')).status).toBe(403);
  });

  it('approval mode holds the account until an administrator approves it', async () => {
    const admin = await adminWithMail();
    await admin.patch('/api/auth/profile', { email: 'root@example.com', password: 'correct horse battery staple' });
    await admin.put('/api/admin/settings/registration', { mode: 'approval' });
    const anon = new Client(built);
    await anon.post('/api/auth/register', signup);
    expect((await anon.post('/api/auth/verify', { token: lastLinkToken(built.mail, 'ada@example.com') })).body).toEqual({ status: 'pending_approval' });
    expect(built.mail.sent.some((m) => m.to === 'root@example.com' && /waiting for approval/.test(m.subject))).toBe(true);

    expect((await new Client(built).post('/api/auth/login', { username: 'ada', password: PASSWORD })).status).toBe(401);
    const list = (await admin.get('/api/admin/users')).body.users as { id: string; username: string; registrationState: string }[];
    const pending = list.find((u) => u.username === 'ada')!;
    expect(pending.registrationState).toBe('pending_approval');
    // The generic status switch can't bypass the queue.
    expect((await admin.patch(`/api/admin/users/${pending.id}`, { status: 'active' })).status).toBe(400);

    expect((await admin.post(`/api/admin/users/${pending.id}/approve`)).status).toBe(200);
    expect(built.mail.sent.some((m) => m.to === 'ada@example.com' && /ready/.test(m.subject))).toBe(true);
    expect((await new Client(built).post('/api/auth/login', { username: 'ada', password: PASSWORD })).status).toBe(200);
  });

  it('administrators can decline a registration', async () => {
    const admin = await adminWithMail();
    await admin.put('/api/admin/settings/registration', { mode: 'approval' });
    const anon = new Client(built);
    await anon.post('/api/auth/register', signup);
    await anon.post('/api/auth/verify', { token: lastLinkToken(built.mail, 'ada@example.com') });
    const id = ((await admin.get('/api/admin/users')).body.users as { id: string; username: string }[]).find((u) => u.username === 'ada')!.id;
    expect((await admin.post(`/api/admin/users/${id}/reject`)).status).toBe(200);
    expect(((await admin.get('/api/admin/users')).body.users as { username: string }[]).some((u) => u.username === 'ada')).toBe(false);
    // Ordinary accounts can't be declined this way.
    const adminId = ((await admin.get('/api/admin/users')).body.users as { id: string }[])[0]!.id;
    expect((await admin.post(`/api/admin/users/${adminId}/reject`)).status).toBe(400);
  });

  it('does not reveal whether an email address is already registered', async () => {
    const admin = await adminWithMail();
    await admin.put('/api/admin/settings/registration', { mode: 'open' });
    const first = new Client(built);
    await first.post('/api/auth/register', signup);
    await first.post('/api/auth/verify', { token: lastLinkToken(built.mail, 'ada@example.com') });
    const sentBefore = built.mail.sent.length;
    const again = await new Client(built).post('/api/auth/register', { ...signup, displayName: 'Someone Else', password: 'another-long-passphrase-99' });
    expect(again).toMatchObject({ status: 200, body: { ok: true } });
    await new Promise((r) => setTimeout(r, 10));
    expect(built.mail.sent.length).toBe(sentBefore + 1);
    expect(built.mail.sent.at(-1)!.subject).toMatch(/already have/);
    // The original account is untouched.
    expect((await new Client(built).post('/api/auth/login', { username: 'ada', password: PASSWORD })).status).toBe(200);
  });

  it('enforces the password rules', async () => {
    const admin = await adminWithMail();
    await admin.put('/api/admin/settings/registration', { mode: 'open' });
    const weak = await new Client(built).post('/api/auth/register', { ...signup, password: 'short' });
    expect(weak.status).toBe(400);
    expect(weak.body.error).toMatch(/at least/);
    const common = await new Client(built).post('/api/auth/register', { ...signup, password: 'password1234' });
    expect(common.status).toBe(400);
  });

  it('allows registering again before confirming, replacing the earlier attempt', async () => {
    const admin = await adminWithMail();
    await admin.put('/api/admin/settings/registration', { mode: 'open' });
    const c = new Client(built);
    await c.post('/api/auth/register', signup);
    const first = lastLinkToken(built.mail, 'ada@example.com');
    await c.post('/api/auth/register', { ...signup, password: 'second-long-passphrase-42' });
    expect((await c.post('/api/auth/verify', { token: first })).status).toBe(400);
    expect((await c.post('/api/auth/verify', { token: lastLinkToken(built.mail, 'ada@example.com') })).status).toBe(200);
    expect((await new Client(built).post('/api/auth/login', { username: 'ada', password: 'second-long-passphrase-42' })).status).toBe(200);
  });

  it('counts bad verification links against the address', async () => {
    await adminWithMail();
    const c = new Client(built);
    c.ip = '203.0.113.9';
    for (let i = 0; i < 5; i++) expect((await c.post('/api/auth/verify', { token: `bad${i}` })).status).toBe(400);
    expect(built.ctx.db.prepare("SELECT COUNT(*) AS n FROM auth_failures WHERE kind = 'register'").get()).toEqual({ n: 5 });
  });
});

describe('Cloudflare Turnstile', () => {
  const calls: { url: string; body: URLSearchParams }[] = [];
  let outcome: 'pass' | 'fail' | 'down' | 'error' = 'pass';
  const fakeFetch = (async (url: string, init: { body: URLSearchParams }) => {
    calls.push({ url, body: init.body });
    if (outcome === 'down') throw new Error('network down');
    if (outcome === 'error') return new Response('nope', { status: 500 });
    return new Response(JSON.stringify({ success: outcome === 'pass' }), { status: 200 });
  }) as unknown as typeof fetch;

  async function adminWithTurnstile(flags: { signup?: boolean; reset?: boolean; login?: boolean }) {
    calls.length = 0;
    outcome = 'pass';
    const mail = new MemoryMailer();
    built = { ...(await buildApp(testConfig(), { db: openDatabase(':memory:'), logger: false, mailer: mail, fetch: fakeFetch })), mail };
    const admin = await setupAdmin(built);
    await admin.put('/api/admin/settings/mail', smtp);
    await admin.put('/api/admin/settings/registration', { mode: 'open' });
    const res = await admin.put('/api/admin/settings/turnstile', { siteKey: '0xSITE', secretKey: '0xSECRET', signup: false, reset: false, login: false, ...flags });
    expect(res.status).toBe(200);
    return admin;
  }

  it('never returns the secret key, only whether one is saved', async () => {
    const admin = await adminWithTurnstile({ signup: true });
    const view = (await admin.get('/api/admin/settings')).body.turnstile;
    expect(view).toMatchObject({ siteKey: '0xSITE', hasSecretKey: true, signup: true });
    expect(JSON.stringify(view)).not.toContain('0xSECRET');
    const pub = (await new Client(built).get('/api/auth/config')).body;
    expect(pub.turnstile).toEqual({ siteKey: '0xSITE', signup: true, reset: false, login: false });
    expect(JSON.stringify(pub)).not.toContain('0xSECRET');
    // Sealed at rest and covered by key rotation.
    const row = built.ctx.db.prepare("SELECT value, value_enc FROM settings WHERE id = 'turnstile'").get() as { value: string; value_enc: string };
    expect(row.value + row.value_enc).not.toContain('0xSECRET');
    expect(checkSecrets(built.ctx.db, built.ctx.box)).toMatchObject({ failed: 0 });
    expect(rotateSecrets(built.ctx.db, built.ctx.box).remainingStale).toBe(0);
  });

  it('requires both keys before the check can be turned on, and drops the secret if the site key changes', async () => {
    built = await makeApp();
    const admin = await setupAdmin(built);
    expect((await admin.put('/api/admin/settings/turnstile', { siteKey: '0xSITE', signup: true, reset: false, login: false })).status).toBe(400);
    await admin.put('/api/admin/settings/turnstile', { siteKey: '0xSITE', secretKey: '0xSECRET', signup: true, reset: false, login: false });
    expect((await admin.put('/api/admin/settings/turnstile', { siteKey: '0xOTHER', signup: true, reset: false, login: false })).status).toBe(400);
    expect((await admin.put('/api/admin/settings/turnstile', { siteKey: '0xSITE', signup: true, reset: true, login: false })).status).toBe(200);
  });

  it('sign-up requires a passing check, verified with Cloudflare along with the client IP', async () => {
    await adminWithTurnstile({ signup: true });
    const c = new Client(built);
    c.ip = '198.51.100.7';
    expect((await c.post('/api/auth/register', signup)).body.code).toBe('browser_check_failed');
    expect(calls).toHaveLength(0);

    const ok = await c.post('/api/auth/register', { ...signup, captchaToken: 'good-token' });
    expect(ok.status).toBe(200);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    expect(Object.fromEntries(calls[0]!.body)).toEqual({ secret: '0xSECRET', response: 'good-token', remoteip: '198.51.100.7' });

    outcome = 'fail';
    const bad = await c.post('/api/auth/register', { ...signup, email: 'b@example.com', captchaToken: 'bad-token' });
    expect(bad.status).toBe(400);
    expect(bad.body.code).toBe('browser_check_failed');
    expect(built.ctx.db.prepare("SELECT 1 FROM users WHERE email = 'b@example.com'").get()).toBeUndefined();
  });

  it('fails closed when Cloudflare cannot be reached or answers with an error', async () => {
    await adminWithTurnstile({ signup: true });
    for (const o of ['down', 'error'] as const) {
      outcome = o;
      const res = await new Client(built).post('/api/auth/register', { ...signup, captchaToken: 'x' });
      expect(res.status).toBe(400);
    }
    expect(built.ctx.db.prepare("SELECT COUNT(*) AS n FROM users WHERE email = 'ada@example.com'").get()).toEqual({ n: 0 });
  });

  it('password reset requests require the check when enforced', async () => {
    await adminWithTurnstile({ reset: true });
    const c = new Client(built);
    expect((await c.post('/api/auth/forgot', { identifier: 'admin' })).status).toBe(400);
    expect((await c.post('/api/auth/forgot', { identifier: 'admin', captchaToken: 't' })).status).toBe(200);
    // Not enforced elsewhere.
    expect((await new Client(built).post('/api/auth/login', { username: 'nobody', password: 'x' })).body.code).toBe('invalid_credentials');
  });

  it('sign-in requires the check only when that option is on', async () => {
    await adminWithTurnstile({ login: true });
    const c = new Client(built);
    expect((await c.post('/api/auth/login', { username: 'admin', password: 'correct horse battery staple' })).body.code).toBe('browser_check_failed');
    expect((await c.post('/api/auth/login', { username: 'admin', password: 'correct horse battery staple', captchaToken: 't' })).status).toBe(200);
  });

  it('repeated failed checks lock the address out', async () => {
    await adminWithTurnstile({ signup: true });
    const c = new Client(built);
    c.ip = '203.0.113.50';
    for (let i = 0; i < 30; i++) built.ctx.bruteForce.recordFailure({ kind: 'captcha', ip: c.ip });
    expect((await c.post('/api/auth/register', { ...signup, captchaToken: 't' })).body.code).toBe('ip_locked');
  });

  it('allows Cloudflare in the content security policy only while the check is configured', async () => {
    built = await makeApp();
    const admin = await setupAdmin(built);
    const csp = async () => String((await built.app.inject({ method: 'GET', url: '/api/health' })).headers['content-security-policy']);
    expect(await csp()).not.toContain('challenges.cloudflare.com');
    await admin.put('/api/admin/settings/turnstile', { siteKey: '0xSITE', secretKey: '0xSECRET', signup: true, reset: false, login: false });
    const on = await csp();
    expect(on).toMatch(/script-src [^;]*https:\/\/challenges\.cloudflare\.com/);
    expect(on).toMatch(/frame-src [^;]*https:\/\/challenges\.cloudflare\.com/);
    await admin.del('/api/admin/settings/turnstile');
    expect(await csp()).not.toContain('challenges.cloudflare.com');
  });
});

