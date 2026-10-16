import net, { type AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { BuiltApp } from '../src/app.js';
import { createUser, makeApp, setupAdmin, type Client } from './helpers.js';

describe('health and status', () => {
  let built: BuiltApp;
  let admin: Client;
  let listener: net.Server;
  let port: number;
  let closedPort: number;

  beforeAll(async () => {
    built = await makeApp({ allowLoopbackTargets: true });
    admin = await setupAdmin(built);
    listener = net.createServer((s) => s.end());
    await new Promise<void>((r) => listener.listen(0, '127.0.0.1', r));
    port = (listener.address() as AddressInfo).port;
    const spare = net.createServer();
    await new Promise<void>((r) => spare.listen(0, '127.0.0.1', r));
    closedPort = (spare.address() as AddressInfo).port;
    await new Promise<void>((r) => spare.close(() => r()));
  });
  afterAll(async () => {
    listener.close();
    await built.app.close();
  });

  const server = (name: string, p: number, extra: Record<string, unknown> = {}) =>
    admin.post('/api/servers', { name, host: '127.0.0.1', port: p, username: 'u', authMethod: 'prompt', ...extra });

  it('is admin only', async () => {
    const user = await createUser(built, admin, 'plain');
    expect((await user.client.get('/api/admin/health')).status).toBe(403);
    expect((await user.client.post('/api/admin/health/check')).status).toBe(403);
  });

  it('reports the app, storage and counts without probing until asked', async () => {
    const res = await admin.get('/api/admin/health');
    expect(res.status).toBe(200);
    expect(res.body.app.version).toBe('dev');
    expect(res.body.app.uptimeSeconds).toBeGreaterThanOrEqual(0);
    expect(res.body.backups.configured).toBe(false);
    expect(res.body.summary.servers).toBe(0);
  });

  it('measures reachable and unreachable hosts and reports host key status', async () => {
    await server('up', port);
    await server('down', closedPort);
    const res = await admin.post('/api/admin/health/check');
    expect(res.status).toBe(200);
    const byName = Object.fromEntries(res.body.servers.map((s: any) => [s.name, s]));
    expect(byName.up.probe.reachable).toBe(true);
    expect(byName.up.probe.latencyMs).toBeGreaterThanOrEqual(0);
    expect(byName.down.probe.reachable).toBe(false);
    expect(byName.down.probe.error).toBeTruthy();
    expect(byName.up.hostKey).toBe('unverified');
    expect(res.body.summary).toMatchObject({ servers: 2, reachable: 1, unreachable: 1, hostKeyUnverified: 2 });
    // The stored result is served without probing again.
    expect((await admin.get('/api/admin/health')).body.servers.find((s: any) => s.name === 'up').probe.reachable).toBe(true);
  });

  it('tests jump hosts directly and reports servers behind them through the jump host', async () => {
    const jh = await admin.post('/api/admin/jump-hosts', { name: 'bastion', host: '127.0.0.1', port, username: 'jump' });
    expect(jh.status).toBe(200);
    await server('behind', closedPort, { jumpMode: 'fixed', jumpHostId: jh.body.jumpHost.id });
    const res = await admin.post('/api/admin/health/check');
    const behind = res.body.servers.find((s: any) => s.name === 'behind');
    expect(behind.route).toMatchObject({ mode: 'fixed', jumpHost: 'bastion', testable: false });
    expect(behind.probe).toBeNull();
    expect(res.body.jumpHosts[0]).toMatchObject({ name: 'bastion', hostKey: 'unverified', serverCount: 1 });
    expect(res.body.jumpHosts[0].probe.reachable).toBe(true);
    expect(res.body.summary.viaJumpHost).toBe(1);
  });
});
