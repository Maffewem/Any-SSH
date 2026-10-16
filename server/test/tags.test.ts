import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { BuiltApp } from '../src/app.js';
import { createUser, makeApp, setupAdmin, type Client } from './helpers.js';

describe('server tags', () => {
  let built: BuiltApp;
  let admin: Client;
  let serverId: string;

  beforeAll(async () => {
    built = await makeApp();
    admin = await setupAdmin(built);
  });
  afterAll(() => built.app.close());

  const base = { name: 'web-1', host: 'web1.example.com', username: 'deploy', authMethod: 'prompt' };

  it('stores tags in the order given and drops repeats ignoring case', async () => {
    const res = await admin.post('/api/servers', { ...base, tags: ['Prod', 'web', 'prod', ' eu-west '] });
    expect(res.status).toBe(200);
    expect(res.body.server.tags).toEqual(['Prod', 'web', 'eu-west']);
    serverId = res.body.server.id;
  });

  it('defaults to no tags and keeps tags when other fields change', async () => {
    const plain = await admin.post('/api/servers', { ...base, name: 'plain' });
    expect(plain.body.server.tags).toEqual([]);
    const renamed = await admin.patch(`/api/servers/${serverId}`, { name: 'web-one' });
    expect(renamed.body.server.tags).toEqual(['Prod', 'web', 'eu-west']);
  });

  it('replaces and clears tags', async () => {
    expect((await admin.patch(`/api/servers/${serverId}`, { tags: ['db'] })).body.server.tags).toEqual(['db']);
    expect((await admin.patch(`/api/servers/${serverId}`, { tags: [] })).body.server.tags).toEqual([]);
  });

  it('rejects too many, too long and odd-looking tags', async () => {
    const many = await admin.patch(`/api/servers/${serverId}`, { tags: Array.from({ length: 11 }, (_, i) => `t${i}`) });
    expect(many.status).toBe(400);
    expect((await admin.patch(`/api/servers/${serverId}`, { tags: ['x'.repeat(33)] })).status).toBe(400);
    expect((await admin.patch(`/api/servers/${serverId}`, { tags: ['<script>'] })).status).toBe(400);
    expect((await admin.patch(`/api/servers/${serverId}`, { tags: ['  '] })).status).toBe(400);
  });

  it('lets a manager retag but not a user with use-only access', async () => {
    await admin.patch(`/api/servers/${serverId}`, { tags: ['shared'] });
    const manager = await createUser(built, admin, 'mgr');
    const user = await createUser(built, admin, 'usr');
    await admin.put(`/api/servers/${serverId}/shares/${manager.id}`, { permission: 'manage' });
    await admin.put(`/api/servers/${serverId}/shares/${user.id}`, { permission: 'use' });

    const seen = await user.client.get(`/api/servers/${serverId}`);
    expect(seen.body.server.tags).toEqual(['shared']);
    expect((await user.client.patch(`/api/servers/${serverId}`, { tags: ['nope'] })).status).toBe(403);
    expect((await manager.client.patch(`/api/servers/${serverId}`, { tags: ['ops'] })).body.server.tags).toEqual(['ops']);
  });
});
