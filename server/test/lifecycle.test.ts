import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Client, createUser, makeApp, setupAdmin } from './helpers.js';

let built: Awaited<ReturnType<typeof makeApp>>;
beforeEach(async () => {
  built = await makeApp();
});
afterEach(async () => {
  await built.app.close();
});

const server = (name: string) => ({ name, host: 'example.com', port: 22, username: 'root', authMethod: 'prompt' });

async function ownerWithSharedServer() {
  const admin = await setupAdmin(built);
  const alice = await createUser(built, admin, 'alice');
  const bob = await createUser(built, admin, 'bobby');
  const shared = (await alice.client.post('/api/servers', server('Shared box'))).body.server.id as string;
  await alice.client.post('/api/servers', server('Private box'));
  expect((await alice.client.put(`/api/servers/${shared}/shares/${bob.id}`, { permission: 'use' })).status).toBe(200);
  return { admin, alice, bob, shared };
}

describe('sign out everywhere', () => {
  it('ends every session of the user, including the current one', async () => {
    const admin = await setupAdmin(built);
    const u = await createUser(built, admin, 'carol');
    const other = new Client(built);
    await other.post('/api/auth/login', { username: 'carol', password: u.password });
    expect((await u.client.post('/api/auth/sessions/revoke-all')).body.ok).toBe(true);
    expect((await other.get('/api/auth/me')).status).toBe(401);
    expect((await u.client.get('/api/auth/me')).status).toBe(401);
  });

  it('lets an administrator sign a user out', async () => {
    const admin = await setupAdmin(built);
    const u = await createUser(built, admin, 'dave');
    expect((await admin.post(`/api/admin/users/${u.id}/sign-out`)).status).toBe(200);
    expect((await u.client.get('/api/auth/me')).status).toBe(401);
    expect((await u.client.post('/api/admin/users/x/sign-out')).status).not.toBe(200);
  });
});

describe('password changes sign out other devices', () => {
  it('keeps the current session on a self-service change and ends the others', async () => {
    const admin = await setupAdmin(built);
    const u = await createUser(built, admin, 'erin');
    const other = new Client(built);
    await other.post('/api/auth/login', { username: 'erin', password: u.password });
    const res = await u.client.post('/api/auth/password', { currentPassword: u.password, newPassword: 'harbor-violet-engine-42' });
    expect(res.status).toBe(200);
    expect(res.body.signedOutSessions).toBeGreaterThanOrEqual(1);
    expect((await other.get('/api/auth/me')).status).toBe(401);
    expect((await u.client.get('/api/auth/me')).status).toBe(200);
    const log = (await admin.get('/api/admin/audit?limit=50')).body;
    expect(JSON.stringify(log)).toContain('signedOutSessions');
  });

  it('signs the user out everywhere when an administrator resets the password', async () => {
    const admin = await setupAdmin(built);
    const u = await createUser(built, admin, 'frank');
    expect((await admin.post(`/api/admin/users/${u.id}/reset-password`)).status).toBe(200);
    expect((await u.client.get('/api/auth/me')).status).toBe(401);
  });
});

describe('deleting an account', () => {
  it('needs the password', async () => {
    const { alice } = await ownerWithSharedServer();
    expect((await alice.client.post('/api/account/delete', { password: 'wrong-password-here', confirm: 'delete' })).status).toBe(400);
  });

  it('requires typing "delete" when servers are shared, and then removes them', async () => {
    const { alice, bob, shared } = await ownerWithSharedServer();
    const preview = (await alice.client.get('/api/account/deletion-preview')).body;
    expect(preview.servers.find((s: any) => s.id === shared).sharedWith).toHaveLength(1);

    expect((await alice.client.post('/api/account/delete', { password: alice.password })).status).toBe(400);
    expect((await alice.client.post('/api/account/delete', { password: alice.password, confirm: 'delete' })).status).toBe(200);
    expect((await alice.client.get('/api/auth/me')).status).toBe(401);
    expect((await bob.client.get('/api/servers')).body.servers).toHaveLength(0);
  });

  it('transfers shared servers to another user instead, deleting the rest', async () => {
    const { alice, bob, shared } = await ownerWithSharedServer();
    expect((await alice.client.post('/api/account/delete', { password: alice.password, transferTo: bob.id })).status).toBe(200);
    const servers = (await bob.client.get('/api/servers')).body.servers;
    expect(servers.map((s: any) => s.name)).toEqual(['Shared box']);
    expect(servers[0].id).toBe(shared);
    expect(servers[0].access).toBe('owner');
  });

  it('does not require confirmation when nothing is shared', async () => {
    const admin = await setupAdmin(built);
    const u = await createUser(built, admin, 'erin2');
    await u.client.post('/api/servers', server('Mine'));
    expect((await u.client.post('/api/account/delete', { password: u.password })).status).toBe(200);
  });

  it('refuses to delete the only administrator', async () => {
    const admin = await setupAdmin(built);
    const res = await admin.post('/api/account/delete', { password: 'correct horse battery staple' });
    expect(res.status).toBe(400);
  });

  it('lets an administrator transfer then delete', async () => {
    const { admin, alice, bob, shared } = await ownerWithSharedServer();
    expect((await admin.del(`/api/admin/users/${alice.id}`)).status).toBe(400);
    expect((await admin.post(`/api/admin/users/${alice.id}/transfer-servers`, { to: bob.id })).body.moved).toHaveLength(1);
    expect((await admin.del(`/api/admin/users/${alice.id}`)).status).toBe(200);
    expect((await bob.client.get('/api/servers')).body.servers.map((s: any) => s.id)).toEqual([shared]);
  });
});

describe('usage limits by account type', () => {
  it('uses a separate terminal limit for administrators', async () => {
    const admin = await setupAdmin(built);
    expect(built.ctx.settings.terminalLimit('admin')).toBe(built.ctx.settings.terminalLimit('user'));
    const res = await admin.put('/api/admin/settings/limits', { maxTerminalsPerUser: 2, maxTerminalsPerAdmin: 20, detachMinutes: 5 });
    expect(res.status).toBe(200);
    expect(res.body.limits).toMatchObject({ maxTerminalsPerUser: 2, maxTerminalsPerAdmin: 20 });
    expect(built.ctx.settings.terminalLimit('user')).toBe(2);
    expect(built.ctx.settings.terminalLimit('admin')).toBe(20);
    const same = await admin.put('/api/admin/settings/limits', { maxTerminalsPerUser: 3, maxTerminalsPerAdmin: null, detachMinutes: 5 });
    expect(same.body.limits.maxTerminalsPerAdmin).toBeNull();
    expect(built.ctx.settings.terminalLimit('admin')).toBe(3);
  });

  it('reports the defaults alongside saved limits', async () => {
    const admin = await setupAdmin(built);
    await admin.put('/api/admin/settings/limits', { maxTerminalsPerUser: 4, maxTerminalsPerAdmin: 9, detachMinutes: 1 });
    const { limits } = (await admin.get('/api/admin/settings')).body;
    expect(limits.defaults).toEqual({ maxTerminalsPerUser: 8, maxTerminalsPerAdmin: null, detachMinutes: 5 });
    expect(limits).toMatchObject({ maxTerminalsPerUser: 4, maxTerminalsPerAdmin: 9, detachMinutes: 1 });
  });
});
