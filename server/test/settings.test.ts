import { randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SecretBox } from '../src/crypto.js';
import { openDatabase } from '../src/db.js';
import { ConfigurableMailer } from '../src/mail.js';
import { rotateSecrets } from '../src/rotate.js';
import { Settings } from '../src/settings.js';
import { ADMIN_PASSWORD, Client, createUser, makeApp, setupAdmin, testConfig } from './helpers.js';

let built: Awaited<ReturnType<typeof makeApp>>;
beforeEach(async () => {
  built = await makeApp();
});
afterEach(async () => {
  await built.app.close();
});

const smtp = { enabled: true, host: 'smtp.example.com', port: 587, security: 'starttls', username: 'mailer', password: 'smtp-secret-1', from: 'Any-SSH <a@example.com>' };

describe('admin settings', () => {
  it('only admins can read or change settings', async () => {
    const admin = await setupAdmin(built);
    const { client } = await createUser(built, admin, 'bob');
    expect((await client.get('/api/admin/settings')).status).toBe(403);
    expect((await client.put('/api/admin/settings/mail', smtp)).status).toBe(403);
    expect((await client.post('/api/admin/settings/mail/test', {})).status).toBe(403);
  });

  it('starts from the environment and falls back to it on reset', async () => {
    const admin = await setupAdmin(built);
    const res = await admin.get('/api/admin/settings');
    expect(res.body.mail).toMatchObject({ source: 'environment', enabled: false });
    expect(res.body.sessions).toEqual({ source: 'environment', lockMinutes: 15, idleMinutes: 120, maxHours: 12 });

    expect((await admin.put('/api/admin/settings/sessions', { lockMinutes: 5, idleMinutes: 60, maxHours: 8 })).status).toBe(200);
    expect(built.ctx.settings.sessionLockMinutes).toBe(5);
    expect((await admin.del('/api/admin/settings/sessions')).body.sessions).toMatchObject({ source: 'environment', lockMinutes: 15 });
  });

  it('rejects a lock that comes after the idle sign-out', async () => {
    const admin = await setupAdmin(built);
    const res = await admin.put('/api/admin/settings/sessions', { lockMinutes: 60, idleMinutes: 30, maxHours: 12 });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/lock must come before/);
  });

  it('stores the SMTP password sealed and never returns it', async () => {
    const admin = await setupAdmin(built);
    const res = await admin.put('/api/admin/settings/mail', smtp);
    expect(res.status).toBe(200);
    expect(res.body.mail).toMatchObject({ source: 'web', enabled: true, host: 'smtp.example.com', username: 'mailer', hasPassword: true });
    expect(JSON.stringify(res.body)).not.toContain('smtp-secret-1');
    expect(JSON.stringify((await admin.get('/api/admin/settings')).body)).not.toContain('smtp-secret-1');

    const row = built.ctx.db.prepare("SELECT * FROM settings WHERE id = 'mail'").get() as { value: string; value_enc: string };
    expect(row.value).not.toContain('smtp-secret-1');
    expect(row.value_enc).toMatch(/^v1\./);
    expect(built.ctx.settings.mail.smtp?.pass).toBe('smtp-secret-1');

    // Saving without a password keeps the stored one.
    await admin.put('/api/admin/settings/mail', { ...smtp, password: undefined, port: 465, security: 'tls' });
    expect(built.ctx.settings.mail.smtp).toMatchObject({ port: 465, secure: true, pass: 'smtp-secret-1' });

    const audit = built.ctx.db.prepare("SELECT details FROM audit_log WHERE action = 'admin.settings_change'").all() as { details: string }[];
    expect(audit.map((a) => JSON.parse(a.details).changed)).toEqual([
      ['enabled', 'host', 'username', 'from', 'password'],
      ['port', 'security'],
    ]);
    expect(audit.map((a) => a.details).join()).not.toContain('smtp-secret-1');
  });

  it('drops the stored password when the SMTP server or username changes', async () => {
    const admin = await setupAdmin(built);
    await admin.put('/api/admin/settings/mail', smtp);
    const res = await admin.put('/api/admin/settings/mail', { ...smtp, password: undefined, host: 'evil.example.net' });
    expect(res.body.mail.hasPassword).toBe(false);
    expect(built.ctx.settings.mail.smtp?.pass).toBeUndefined();
  });

  it('sends a test email', async () => {
    const admin = await setupAdmin(built);
    expect((await admin.post('/api/admin/settings/mail/test', {})).status).toBe(400); // admin has no email yet
    const res = await admin.post('/api/admin/settings/mail/test', { to: 'ops@example.com' });
    expect(res.status).toBe(200);
    expect(built.mail.sent.at(-1)).toMatchObject({ to: 'ops@example.com', subject: 'Any-SSH test email' });
  });

  it('master key rotation re-seals the SMTP password', async () => {
    const admin = await setupAdmin(built);
    await admin.put('/api/admin/settings/mail', smtp);
    const newKey = randomBytes(32);
    const box = new SecretBox(newKey, [built.ctx.config.masterKey]);
    expect(rotateSecrets(built.ctx.db, box).remainingStale).toBe(0);
    const row = built.ctx.db.prepare("SELECT value_enc FROM settings WHERE id = 'mail'").get() as { value_enc: string };
    expect(new SecretBox(newKey).openString(row.value_enc, 'setting:mail')).toBe('smtp-secret-1');
  });

  it('the mailer follows settings changes without a restart', () => {
    const config = testConfig();
    const db = openDatabase(':memory:');
    const settings = new Settings(db, new SecretBox(config.masterKey), config);
    const mailer = new ConfigurableMailer(() => ({ smtp: settings.mail.smtp, mailFrom: settings.mail.from }), { info() {} });
    settings.onChange(() => mailer.reload());
    expect(mailer.delivery).toBe('log');
    settings.setMail({ ...smtp, security: 'starttls' }, 'admin');
    expect(mailer.delivery).toBe('smtp');
    settings.reset('mail');
    expect(mailer.delivery).toBe('log');
    db.close();
  });
});

describe('idle lock', () => {
  /** Pretends the session has been idle for `minutes`. */
  const idle = (minutes: number) =>
    built.ctx.db.prepare('UPDATE sessions SET last_seen_at = ?').run(Date.now() - minutes * 60_000);

  it('locks after the idle period and unlocks with the password, without 2FA', async () => {
    const admin = await setupAdmin(built);
    expect((await admin.get('/api/auth/state')).body.msUntilLock).toBeGreaterThan(14 * 60_000);
    idle(16);

    const blocked = await admin.get('/api/servers');
    expect(blocked.status).toBe(401);
    expect(blocked.body.code).toBe('session_locked');
    expect((await admin.get('/api/auth/me')).body).toEqual({ locked: true, username: 'admin', displayName: 'admin' });
    expect((await admin.get('/api/auth/state')).body).toEqual({ locked: true });
    // Activity does not unlock it.
    expect((await admin.post('/api/auth/heartbeat')).status).toBe(401);
    expect((await admin.get('/api/servers')).status).toBe(401);

    expect((await admin.post('/api/auth/unlock', { password: 'wrong' })).body.code).toBe('invalid_credentials');
    const ok = await admin.post('/api/auth/unlock', { password: ADMIN_PASSWORD });
    expect(ok.status).toBe(200);
    expect(ok.body.user.username).toBe('admin');
    expect((await admin.get('/api/servers')).status).toBe(200);
  });

  it('still signs out after the longer idle timeout', async () => {
    const admin = await setupAdmin(built);
    idle(121);
    expect((await admin.get('/api/auth/me')).status).toBe(401);
    expect((await admin.post('/api/auth/unlock', { password: ADMIN_PASSWORD })).status).toBe(401);
  });

  it('ends the session after repeated wrong passwords', async () => {
    const admin = await setupAdmin(built);
    await admin.post('/api/auth/lock');
    for (let i = 0; i < 4; i++) expect((await admin.post('/api/auth/unlock', { password: 'nope' })).body.code).toBe('invalid_credentials');
    const last = await admin.post('/api/auth/unlock', { password: 'nope' });
    expect(last.body.code).toBe('unauthenticated');
    expect((await admin.post('/api/auth/unlock', { password: ADMIN_PASSWORD })).status).toBe(401);
    // A full sign-in still works.
    expect((await admin.post('/api/auth/login', { username: 'admin', password: ADMIN_PASSWORD })).status).toBe(200);
  });

  it('the state check is not activity, a heartbeat is', async () => {
    const admin = await setupAdmin(built);
    idle(10);
    const before = (await admin.get('/api/auth/state')).body.msUntilLock as number;
    expect(before).toBeLessThanOrEqual(5 * 60_000);
    expect((await admin.get('/api/auth/state')).body.msUntilLock).toBeLessThanOrEqual(before);
    await admin.post('/api/auth/heartbeat');
    expect((await admin.get('/api/auth/state')).body.msUntilLock).toBeGreaterThan(14 * 60_000);
  });

  it('a lock period of 0 turns locking off', async () => {
    const admin = await setupAdmin(built);
    await admin.put('/api/admin/settings/sessions', { lockMinutes: 0, idleMinutes: 120, maxHours: 12 });
    idle(60);
    expect((await admin.get('/api/servers')).status).toBe(200);
    expect((await admin.get('/api/auth/state')).body).toEqual({ locked: false, msUntilLock: null });
  });

  it('a locked session cannot get a terminal ticket', async () => {
    const admin = await setupAdmin(built);
    const other = new Client(built);
    await other.post('/api/auth/login', { username: 'admin', password: ADMIN_PASSWORD });
    await admin.post('/api/auth/lock');
    expect((await admin.post('/api/servers/00000000-0000-4000-8000-000000000000/connect', {})).body.code).toBe('session_locked');
    // Other devices are unaffected.
    expect((await other.get('/api/servers')).status).toBe(200);
  });
});
