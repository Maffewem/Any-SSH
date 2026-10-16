import { describe, expect, it } from 'vitest';
import { windowState } from '../src/maintenance.js';
import { UpdateRequests, WARNING_MINUTES } from '../src/updateRequests.js';
import { openDatabase } from '../src/db.js';
import { createUser, makeApp, setupAdmin } from './helpers.js';

const win = { enabled: true, days: [0], start: '04:00', durationMinutes: 120, timezone: 'Europe/London' };

describe('maintenance window', () => {
  it('opens at local time and follows daylight saving', () => {
    // Sunday 2026-03-29 is when the UK moved to summer time: 04:00 local = 03:00 UTC.
    expect(windowState(win, Date.parse('2026-03-29T02:59:00Z')).open).toBe(false);
    expect(windowState(win, Date.parse('2026-03-29T03:00:00Z')).open).toBe(true);
    expect(windowState(win, Date.parse('2026-03-29T04:59:00Z')).open).toBe(true);
    expect(windowState(win, Date.parse('2026-03-29T05:00:00Z')).open).toBe(false);
    // Winter Sunday 2026-01-04: 04:00 local = 04:00 UTC.
    expect(windowState(win, Date.parse('2026-01-04T04:00:00Z')).open).toBe(true);
    expect(windowState(win, Date.parse('2026-01-03T04:30:00Z')).open).toBe(false);
  });

  it('reports the next opening and handles windows past midnight', () => {
    const s = windowState(win, Date.parse('2026-01-05T12:00:00Z'));
    expect(s.open).toBe(false);
    expect(s.nextStart).toBe(Date.parse('2026-01-11T04:00:00Z'));
    const late = { ...win, start: '23:00', durationMinutes: 180, timezone: 'UTC' };
    expect(windowState(late, Date.parse('2026-01-05T00:30:00Z')).open).toBe(true); // Sunday 23:00 + 3h
    expect(windowState(late, Date.parse('2026-01-05T02:30:00Z')).open).toBe(false);
  });

  it('is always open when disabled', () => {
    expect(windowState({ ...win, enabled: false }).open).toBe(true);
  });
});

describe('update requests', () => {
  it('gates the automatic check on the window and runs it once per window', () => {
    const r = new UpdateRequests(openDatabase(':memory:'));
    const sunday = Date.parse('2026-01-04T04:10:00Z');
    expect(r.shouldCheckAuto(false, win, sunday)).toBe(false); // auto-update off
    expect(r.shouldCheckAuto(true, win, Date.parse('2026-01-05T04:10:00Z'))).toBe(false); // Monday: closed
    expect(r.shouldCheckAuto(true, win, sunday)).toBe(true);
    expect(r.shouldCheckAuto(true, win, sunday + 30 * 60_000)).toBe(false); // already looked this window
    expect(r.shouldCheckAuto(true, win, sunday + 7 * 86_400_000)).toBe(true); // next week's window
  });

  it('does not schedule an automatic update that the window would cut off', () => {
    const r = new UpdateRequests(openDatabase(':memory:'));
    expect(r.scheduleAuto(win, Date.parse('2026-01-04T05:59:00Z'))).toBeNull();
    expect(r.scheduleAuto(win, Date.parse('2026-01-04T05:00:00Z'))).not.toBeNull();
  });

  it('claims a request only after the warning period, and only once', () => {
    const r = new UpdateRequests(openDatabase(':memory:'));
    const now = Date.now();
    r.create('alice', 'manual', now);
    expect(r.create('bob', 'manual', now)).toBeNull();
    expect(r.claimDue(now + 1000)).toBeNull();
    expect(r.claimDue(now + WARNING_MINUTES * 60_000)?.requestedBy).toBe('alice');
    expect(r.claimDue(now + 10 * 60_000)).toBeNull();
  });
});

describe('Update now API', () => {
  it('needs the host agent, warns terminals, can be cancelled, and is admin only', async () => {
    const b = await makeApp({ updateCheck: false });
    try {
      const admin = await setupAdmin(b);
      const { client } = await createUser(b, admin, 'bob');
      expect((await client.post('/api/admin/version/update-now')).status).toBe(403);

      b.ctx.updateRequests.heartbeat();
      // "Update now" forces a registry check, so replace it: the test must not depend on the network.
      const known = (updateAvailable: boolean | null) => {
        const status = { checkedAt: Date.now(), latest: null, updateAvailable, error: null };
        (b.ctx.updates as any).status = status;
        (b.ctx.updates as any).check = async () => status;
      };
      known(false);
      // Checks are off in this test, so the server can't tell; with a check run it must refuse unless newer is known.
      (b.ctx.config as any).updateCheck = true;
      expect((await admin.post('/api/admin/version/update-now')).status).toBe(400); // up to date
      known(null);
      expect((await admin.post('/api/admin/version/update-now')).status).toBe(400); // never confirmed
      known(true);
      const warned: string[] = [];
      b.ctx.terminals.add({ id: 't', userId: 'x', serverId: 's', sessionIdHash: 'h', jumpHostId: null, detached: false, close() {}, setLocked() {}, notify: (m) => warned.push(m) });
      const res = await admin.post('/api/admin/version/update-now');
      expect(res.status).toBe(200);
      expect(res.body.pending.requestedBy).toBe('admin');
      expect(warned[0]).toMatch(/restart for an update/);
      expect((await client.get('/api/update-notice')).body.scheduledFor).toBe(res.body.pending.scheduledFor);
      expect((await admin.post('/api/admin/version/update-now')).status).toBe(400); // already scheduled

      const cancelled = await admin.req('DELETE', '/api/admin/version/update-now');
      expect(cancelled.body.pending).toBeNull();
      expect(warned[1]).toMatch(/cancelled/);
    } finally {
      await b.app.close();
    }
  });

  it('saves and validates the maintenance window', async () => {
    const b = await makeApp({ updateCheck: false });
    try {
      const admin = await setupAdmin(b);
      const ok = { enabled: true, days: [6, 0], start: '03:30', durationMinutes: 90, timezone: 'America/New_York' };
      const res = await admin.put('/api/admin/settings/maintenance', ok);
      expect(res.status).toBe(200);
      expect(res.body.maintenance).toMatchObject({ source: 'web', days: [0, 6], start: '03:30' });
      expect((await admin.put('/api/admin/settings/maintenance', { ...ok, timezone: 'Mars/Base' })).status).toBe(400);
      expect((await admin.put('/api/admin/settings/maintenance', { ...ok, start: '25:00' })).status).toBe(400);
      expect((await admin.put('/api/admin/settings/maintenance', { ...ok, days: [] })).status).toBe(400);
      expect((await admin.get('/api/admin/version')).body.maintenance).toMatchObject({ enabled: true, timezone: 'America/New_York' });
      expect((await admin.req('DELETE', '/api/admin/settings/maintenance')).body.maintenance.source).toBe('environment');
    } finally {
      await b.app.close();
    }
  });
});
