import { afterEach, describe, expect, it } from 'vitest';
import { isTrustedIp, normaliseIp, parseTrustedEntry } from '../src/ipTrust.js';
import { hotp, totpCounter } from '../src/totp.js';
import { ADMIN_PASSWORD, Client, createUser, makeApp, setupAdmin } from './helpers.js';

let built: Awaited<ReturnType<typeof makeApp>>;
afterEach(async () => {
  await built?.app.close();
});

describe('address matching', () => {
  it('accepts and canonicalises addresses and ranges', () => {
    expect(parseTrustedEntry('203.0.113.7')).toEqual({ value: '203.0.113.7' });
    expect(parseTrustedEntry('::ffff:203.0.113.7')).toEqual({ value: '203.0.113.7' });
    expect(parseTrustedEntry('203.0.113.7/32')).toEqual({ value: '203.0.113.7' });
    expect(parseTrustedEntry('203.0.113.0/24')).toEqual({ value: '203.0.113.0/24' });
    expect(parseTrustedEntry('2001:DB8::/48')).toEqual({ value: '2001:db8::/48' });
  });
  it('rejects junk and ranges that trust (nearly) everything', () => {
    for (const bad of ['', 'nope', '1.2.3.4/33', '1.2.3.4/x', '0.0.0.0/0', '10.0.0.0/7', '::/0', '2001:db8::/16', '1.2.3.4/24/1', '999.1.1.1']) {
      expect('error' in parseTrustedEntry(bad), bad).toBe(true);
    }
  });
  it('matches IPv4, IPv6 and IPv4-mapped clients', () => {
    const list = ['203.0.113.0/24', '2001:db8:1::/48', '198.51.100.9'];
    expect(isTrustedIp(list, '203.0.113.200')).toBe(true);
    expect(isTrustedIp(list, '::ffff:203.0.113.200')).toBe(true);
    expect(isTrustedIp(list, '203.0.114.1')).toBe(false);
    expect(isTrustedIp(list, '2001:db8:1:ffff::1')).toBe(true);
    expect(isTrustedIp(list, '2001:db8:2::1')).toBe(false);
    expect(isTrustedIp(list, '198.51.100.9')).toBe(true);
    expect(isTrustedIp(list, '198.51.100.10')).toBe(false);
    expect(isTrustedIp(list, null)).toBe(false);
    expect(isTrustedIp([], '1.2.3.4')).toBe(false);
    expect(normaliseIp('fe80::1%eth0')).toBe('fe80::1');
  });
});

async function userAt(ip: string, name = 'gina') {
  const admin = await setupAdmin(built);
  const u = await createUser(built, admin, name);
  u.client.ip = ip;
  return { admin, ...u };
}
const enable = (c: Client, password: string, policy: 'notify' | 'challenge') =>
  c.put('/api/account/trusted-ips/settings', { password, enabled: true, policy });

describe('trusted IP list', () => {
  it('is off by default and changes nothing', async () => {
    built = await makeApp();
    const { client } = await userAt('198.51.100.1');
    const res = await client.get('/api/account/trusted-ips');
    expect(res.body).toMatchObject({ enabled: false, currentIp: '198.51.100.1', currentIpTrusted: false });
    expect((await client.get('/api/servers')).status).toBe(200);
  });

  it('refuses to turn on while the current address is not listed, and needs the password', async () => {
    built = await makeApp();
    const { client, password } = await userAt('198.51.100.1');
    expect((await enable(client, password, 'notify')).status).toBe(400);
    expect((await client.post('/api/account/trusted-ips', { current: true, password: 'wrong' })).status).toBe(400);
    const added = await client.post('/api/account/trusted-ips', { current: true, label: 'Home', password });
    expect(added.body.entries).toMatchObject([{ cidr: '198.51.100.1', label: 'Home' }]);
    expect((await client.post('/api/account/trusted-ips', { current: true, password })).status).toBe(409);
    expect((await enable(client, password, 'notify')).body).toMatchObject({ enabled: true, currentIpTrusted: true });
  });

  it('cannot remove the entry covering the current address while enforced', async () => {
    built = await makeApp();
    const { client, password } = await userAt('198.51.100.1');
    const added = await client.post('/api/account/trusted-ips', { cidr: '198.51.100.0/24', password });
    await enable(client, password, 'notify');
    expect((await client.del(`/api/account/trusted-ips/${added.body.entries[0].id}`)).status).toBe(400);
  });

  it('notify policy: lets an unlisted address in, audits and emails once', async () => {
    built = await makeApp();
    const { client, password } = await userAt('198.51.100.1');
    await client.patch('/api/auth/profile', { email: 'gina@example.com', password });
    await client.post('/api/account/trusted-ips', { current: true, password });
    await enable(client, password, 'notify');

    const away = new Client(built);
    away.ip = '192.0.2.50';
    away.cookie = client.cookie;
    const before = built.mail.sent.length;
    expect((await away.get('/api/servers')).status).toBe(200);
    expect((await away.get('/api/servers')).status).toBe(200);
    await new Promise((r) => setTimeout(r, 10));
    const notices = built.mail.sent.slice(before).filter((m) => m.subject.includes('192.0.2.50'));
    expect(notices).toHaveLength(1);
    const admin = new Client(built);
    await admin.post('/api/auth/login', { username: 'admin', password: ADMIN_PASSWORD });
    const audit = await admin.get('/api/admin/audit?limit=20');
    expect(JSON.stringify(audit.body)).toContain('auth.untrusted_ip');
  });

  it('challenge policy: an unlisted address is held, then released by an emailed code', async () => {
    built = await makeApp();
    const { client, password } = await userAt('198.51.100.1');
    await client.patch('/api/auth/profile', { email: 'gina@example.com', password });
    await client.post('/api/account/trusted-ips', { current: true, password });
    await enable(client, password, 'challenge');

    // Same account, new network: password login works but nothing else does.
    const away = new Client(built);
    away.ip = '192.0.2.50';
    const login = await away.post('/api/auth/login', { username: 'gina', password });
    expect(login.status).toBe(200);
    expect(login.body.ipChallenge).toBe(true);
    expect((await away.get('/api/servers')).body).toMatchObject({ code: 'ip_challenge' });
    expect((await away.post('/api/servers/x/connect', {})).status).toBe(403);
    expect((await away.get('/api/auth/me')).body.ipChallenge).toBe(true);
    expect((await away.get('/api/auth/ip-challenge')).body).toMatchObject({ ip: '192.0.2.50', methods: ['email'] });

    expect((await away.post('/api/auth/ip-challenge/send')).body.sent).toBe(true);
    expect((await away.post('/api/auth/ip-challenge/send')).body.sent).toBe(false); // throttled
    const mail = [...built.mail.sent].reverse().find((m) => m.subject.includes('verification'))!;
    const code = /\n(\d{8})\n/.exec(mail.text)![1]!;
    expect((await away.post('/api/auth/ip-challenge/verify', { code: '00000000' })).status).toBe(400);
    expect((await away.post('/api/auth/ip-challenge/verify', { code })).status).toBe(200);
    expect((await away.get('/api/servers')).status).toBe(200);
    // The code is single use.
    expect((await away.post('/api/auth/ip-challenge/verify', { code })).status).toBe(400);
  });

  it('challenge policy: too many wrong codes ends the session', async () => {
    built = await makeApp();
    const { client, password } = await userAt('198.51.100.1');
    await client.patch('/api/auth/profile', { email: 'gina@example.com', password });
    await client.post('/api/account/trusted-ips', { current: true, password });
    await enable(client, password, 'challenge');
    const away = new Client(built);
    away.ip = '192.0.2.50';
    await away.post('/api/auth/login', { username: 'gina', password });
    await away.post('/api/auth/ip-challenge/send');
    let last = 0;
    for (let i = 0; i < 5; i++) last = (await away.post('/api/auth/ip-challenge/verify', { code: '11111111' })).status;
    expect(last).toBe(401);
    expect((await away.get('/api/auth/me')).status).toBe(401);
  });

  it('challenge policy: an existing session that moves address is held mid-session', async () => {
    built = await makeApp();
    const { client, password } = await userAt('198.51.100.1');
    await client.patch('/api/auth/profile', { email: 'gina@example.com', password });
    await client.post('/api/account/trusted-ips', { current: true, password });
    await enable(client, password, 'challenge');
    expect((await client.get('/api/servers')).status).toBe(200);
    const thief = new Client(built);
    thief.ip = '203.0.113.99';
    thief.cookie = client.cookie; // stolen cookie
    expect((await thief.get('/api/servers')).body).toMatchObject({ code: 'ip_challenge' });
    // The legitimate holder's session is flagged too: it must be verified again, not silently trusted.
    client.ip = '198.51.100.1';
    expect((await client.get('/api/servers')).body).toMatchObject({ code: 'ip_challenge' });
  });

  it('two-factor users release a held session with a code; MFA at login counts as verification', async () => {
    built = await makeApp();
    const { client, password } = await userAt('198.51.100.1');
    const setup = await client.post('/api/auth/mfa/setup', { password });
    const secret = setup.body.secret as string;
    const codeNow = (offset = 0) => hotp(secret, totpCounter(Date.now()) + offset);
    const recovery = (await client.post('/api/auth/mfa/enable', { code: codeNow() })).body.recoveryCodes as string[];
    await client.post('/api/account/trusted-ips', { current: true, password });
    await enable(client, password, 'challenge');

    // Login from elsewhere: password then TOTP. The TOTP code is the proof, so no hold.
    const away = new Client(built);
    away.ip = '192.0.2.50';
    await away.post('/api/auth/login', { username: 'gina', password });
    const mfa = await away.post('/api/auth/mfa', { code: codeNow(1) });
    expect(mfa.status).toBe(200);
    expect((await away.get('/api/servers')).status).toBe(200);

    // A stolen cookie from yet another address is held and needs a fresh proof.
    const thief = new Client(built);
    thief.ip = '203.0.113.99';
    thief.cookie = away.cookie;
    expect((await thief.get('/api/servers')).body).toMatchObject({ code: 'ip_challenge' });
    expect((await thief.get('/api/auth/ip-challenge')).body.methods).toEqual(['totp']);
    expect((await thief.post('/api/auth/ip-challenge/verify', { code: '000000' })).status).toBe(400);
    // (The authenticator window is spent by now, so use a recovery code.)
    expect((await thief.post('/api/auth/ip-challenge/verify', { recoveryCode: recovery[0] })).status).toBe(200);
  });

  it('challenge needs an email or 2FA so nobody is locked out by design', async () => {
    built = await makeApp();
    const { client, password } = await userAt('198.51.100.1');
    await client.post('/api/account/trusted-ips', { current: true, password });
    expect((await enable(client, password, 'challenge')).status).toBe(400);
    expect((await enable(client, password, 'notify')).status).toBe(200);
  });

  it('admin can switch the list off for a locked-out user', async () => {
    built = await makeApp();
    const { admin, client, password, id } = await userAt('198.51.100.1');
    await client.patch('/api/auth/profile', { email: 'gina@example.com', password });
    await client.post('/api/account/trusted-ips', { current: true, password });
    await enable(client, password, 'challenge');
    const away = new Client(built);
    away.ip = '192.0.2.50';
    await away.post('/api/auth/login', { username: 'gina', password });
    expect((await away.get('/api/servers')).status).toBe(403);
    expect((await admin.post(`/api/admin/users/${id}/reset-trusted-ips`)).status).toBe(200);
    expect((await away.get('/api/servers')).status).toBe(200);
    expect((await away.get('/api/account/trusted-ips')).body.enabled).toBe(false);
  });

  it('ignores X-Forwarded-For unless the proxy is trusted', async () => {
    built = await makeApp({ trustProxy: false });
    const { client, password } = await userAt('198.51.100.1');
    await client.post('/api/account/trusted-ips', { current: true, password });
    await enable(client, password, 'notify');
    const res = await client.req('GET', '/api/account/trusted-ips', undefined, { 'x-forwarded-for': '192.0.2.99' });
    expect(res.body.currentIp).toBe('198.51.100.1');
  });
});
