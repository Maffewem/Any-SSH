import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ADMIN_PASSWORD, Client, createUser, makeApp, setupAdmin } from './helpers.js';

let built: Awaited<ReturnType<typeof makeApp>>;
beforeEach(async () => {
  built = await makeApp();
});
afterEach(async () => {
  await built.app.close();
});

const audit = (action: string) =>
  (built.ctx.db.prepare('SELECT * FROM audit_log WHERE action = ? ORDER BY seq').all(action) as { details: string; actor_username: string | null }[]).map((r) => ({
    ...r,
    details: JSON.parse(r.details),
  }));
const guess = (c: Client, username: string, n: number) => Promise.all(Array.from({ length: n }, () => c.post('/api/auth/login', { username, password: 'wrong-password-1' })));

describe('brute-force protection', () => {
  it('locks an account after the configured number of failures, emails the owner and lets an admin unlock', async () => {
    const admin = await setupAdmin(built);
    await admin.patch(`/api/admin/users/${(built.ctx.db.prepare("SELECT id FROM users WHERE username='admin'").get() as { id: string }).id}`, { email: 'admin@example.com' });
    const { client: bob, password } = await createUser(built, admin, 'bob');
    const bobRow = built.ctx.db.prepare("SELECT id FROM users WHERE username='bob'").get() as { id: string };
    await admin.patch(`/api/admin/users/${bobRow.id}`, { email: 'bob@example.com' });

    const attacker = new Client(built);
    attacker.ip = '203.0.113.9';
    for (let i = 0; i < 5; i++) await attacker.post('/api/auth/login', { username: 'bob', password: 'wrong-password-1' });
    expect(audit('auth.lockout')).toHaveLength(1);
    expect(audit('auth.lockout')[0]!.details).toMatchObject({ scope: 'account', failures: 5 });
    await new Promise((r) => setTimeout(r, 20));
    expect(built.mail.sent.some((m) => m.to === 'bob@example.com' && /locked/.test(m.subject))).toBe(true);

    // The right password no longer works while locked.
    expect((await attacker.post('/api/auth/login', { username: 'bob', password })).status).toBe(401);
    expect((await admin.post(`/api/admin/users/${bobRow.id}/unlock`)).status).toBe(200);
    expect((await attacker.post('/api/auth/login', { username: 'bob', password })).status).toBe(200);
    expect(bob).toBeDefined();
  });

  it('uses admin-configured thresholds and records the change old → new', async () => {
    const admin = await setupAdmin(built);
    const res = await admin.put('/api/admin/settings/security', { accountThreshold: 3, ipThreshold: 50, windowMinutes: 10, lockoutMinutes: 30, notifyOwner: false });
    expect(res.status).toBe(200);
    expect(res.body.security).toMatchObject({ source: 'web', accountThreshold: 3, lockoutMinutes: 30 });
    expect(audit('admin.settings_change').at(-1)!.details.changes).toEqual({
      accountThreshold: { from: 5, to: 3 }, ipThreshold: { from: 30, to: 50 }, windowMinutes: { from: 15, to: 10 }, lockoutMinutes: { from: 15, to: 30 }, notifyOwner: { from: true, to: false },
    });
    const c = new Client(built);
    await guess(c, 'admin', 3);
    expect(audit('auth.lockout')).toHaveLength(1);
    expect((await admin.put('/api/admin/settings/security', { accountThreshold: 1, ipThreshold: 50, windowMinutes: 10, lockoutMinutes: 30, notifyOwner: true })).status).toBe(400);
  });

  it('blocks an address that fails against many accounts, until an admin unlocks it', async () => {
    const admin = await setupAdmin(built);
    await admin.put('/api/admin/settings/security', { accountThreshold: 100, ipThreshold: 6, windowMinutes: 15, lockoutMinutes: 15, notifyOwner: true });
    const attacker = new Client(built);
    attacker.ip = '198.51.100.7';
    for (let i = 0; i < 6; i++) await attacker.post('/api/auth/login', { username: `ghost${i}`, password: 'wrong-password-1' });
    const blocked = await attacker.post('/api/auth/login', { username: 'admin', password: ADMIN_PASSWORD });
    expect(blocked.status).toBe(429);
    expect(blocked.body.code).toBe('ip_locked');
    expect((await attacker.post('/api/auth/forgot', { identifier: 'admin' })).status).toBe(429);
    // Other addresses are unaffected.
    const other = new Client(built);
    expect((await other.post('/api/auth/login', { username: 'admin', password: ADMIN_PASSWORD })).status).toBe(200);

    expect((await admin.get('/api/admin/lockouts')).body.ips).toMatchObject([{ ip: '198.51.100.7' }]);
    expect((await admin.del('/api/admin/lockouts/ip/198.51.100.7')).status).toBe(200);
    expect(audit('admin.ip_unlock')).toHaveLength(1);
    expect((await attacker.post('/api/auth/login', { username: 'admin', password: ADMIN_PASSWORD })).status).toBe(200);
  });

  it('counts wrong passwords on signed-in actions and ends the sessions when that locks the account', async () => {
    const admin = await setupAdmin(built);
    const { client: bob } = await createUser(built, admin, 'bob');
    for (let i = 0; i < 4; i++) expect((await bob.post('/api/auth/mfa/setup', { password: 'nope-nope' })).status).toBe(400);
    expect((await bob.post('/api/auth/mfa/setup', { password: 'nope-nope' })).status).toBe(400);
    expect((await bob.get('/api/servers')).status).toBe(401);
    expect(audit('auth.lockout').at(-1)!.details).toMatchObject({ scope: 'account', kind: 'reauth' });
  });

  it('counts bad reset tokens against the address', async () => {
    const admin = await setupAdmin(built);
    await admin.put('/api/admin/settings/security', { accountThreshold: 100, ipThreshold: 3, windowMinutes: 15, lockoutMinutes: 15, notifyOwner: true });
    const c = new Client(built);
    c.ip = '192.0.2.44';
    for (let i = 0; i < 3; i++) expect((await c.post('/api/auth/token/check', { token: 'bogus' })).status).toBe(400);
    expect((await c.post('/api/auth/token/check', { token: 'bogus' })).status).toBe(429);
  });
});

describe('settings audit trail', () => {
  it('records old and new values for session settings, resets and user changes', async () => {
    const admin = await setupAdmin(built);
    await admin.put('/api/admin/settings/sessions', { lockMinutes: 5, idleMinutes: 60, maxHours: 8 });
    expect(audit('admin.settings_change').at(-1)!.details.changes).toEqual({ lockMinutes: { from: 15, to: 5 }, idleMinutes: { from: 120, to: 60 }, maxHours: { from: 12, to: 8 } });
    await admin.del('/api/admin/settings/sessions');
    expect(audit('admin.settings_reset').at(-1)!.details.changes.lockMinutes).toEqual({ from: 5, to: 15 });

    await admin.put('/api/admin/settings/mail', { enabled: true, host: 'smtp.example.com', port: 587, security: 'starttls', password: 'smtp-secret-1', from: 'a@example.com' });
    const mail = audit('admin.settings_change').at(-1)!;
    expect(mail.details.changes.host).toEqual({ from: '', to: 'smtp.example.com' });
    expect(JSON.stringify(mail.details)).not.toContain('smtp-secret-1');

    const { client } = await createUser(built, admin, 'bob');
    const id = (built.ctx.db.prepare("SELECT id FROM users WHERE username='bob'").get() as { id: string }).id;
    await admin.patch(`/api/admin/users/${id}`, { role: 'admin' });
    expect(audit('admin.user_update').at(-1)!.details.changes).toEqual({ role: { from: 'user', to: 'admin' } });
    expect(client).toBeDefined();
  });

  it('records trusted-IP setting changes old → new', async () => {
    const admin = await setupAdmin(built);
    await admin.post('/api/account/trusted-ips', { password: ADMIN_PASSWORD, current: true });
    await admin.put('/api/account/trusted-ips/settings', { password: ADMIN_PASSWORD, enabled: true, policy: 'notify' });
    expect(audit('user.trusted_ip_settings').at(-1)!.details.changes).toEqual({ enabled: { from: false, to: true } });
  });
});
