import type { FastifyInstance } from 'fastify';
import { requireAdmin, requireUser } from '../http.js';
import type { AppContext } from '../types.js';
import { windowState } from '../maintenance.js';
import { WARNING_MINUTES } from '../updateRequests.js';
import { clientIp, badRequest } from '../http.js';

/** The line shown in open terminals (and the banner) when an update is about to restart the server. */
export function updateNoticeText(scheduledFor: number): string {
  const mins = Math.max(1, Math.round((scheduledFor - Date.now()) / 60_000));
  return `[Any-SSH will restart for an update in about ${mins} minute${mins === 1 ? '' : 's'}. Terminals disconnect and reconnect on their own; save your work.]`;
}

export function registerVersionRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { config, updates } = ctx;
  const view = () => ({
    current: updates.build,
    checkEnabled: config.updateCheck,
    autoUpdate: config.autoUpdate,
    image: `${config.updateImage}:${config.updateTag}`,
    ...updates.current,
    maintenance: { ...ctx.settings.maintenance, ...windowState(ctx.settings.maintenance) },
    /** Update-now needs the host agent (any-ssh web-update on, or auto-update on) to be polling. */
    agentActive: ctx.updateRequests.agentActive(),
    pending: ctx.updateRequests.pending(),
    warningMinutes: WARNING_MINUTES,
  });

  app.get('/api/admin/version', async (req) => {
    requireAdmin(req);
    return view();
  });

  // Update history, recorded by the host's `any-ssh update` (see cli/record-update.ts) in the audit log.
  app.get('/api/admin/version/history', async (req) => {
    requireAdmin(req);
    const rows = ctx.audit.list({ limit: 50, action: 'system.update' });
    return {
      updates: rows.map((r) => {
        const d = JSON.parse(r.details) as Record<string, unknown>;
        return { id: r.seq, ts: r.ts, result: d.result, trigger: d.trigger, from: d.from, to: d.to, note: d.note ?? null };
      }),
    };
  });

  // Manual "check now". Refused when the operator turned checks off, so the server never calls out unasked.
  app.post('/api/admin/version/check', { config: { rateLimit: { max: 6, timeWindow: '1 minute' } } }, async (req) => {
    requireAdmin(req);
    if (config.updateCheck) await updates.check();
    return view();
  });

  // Update now: records a request that the host agent starts after the warning period (backup first, rollback if
  // the new version doesn't start). Allowed at any time once a newer version is known: the maintenance window only limits automatic updates.
  app.post('/api/admin/version/update-now', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req) => {
    const { user } = requireAdmin(req);
    if (!ctx.updateRequests.agentActive()) {
      throw badRequest('The update agent is not running on the server. Run “sudo any-ssh web-update on” on the server once, then try again.');
    }
    // Only when a newer version is known. Re-checks first (reusing a result under 30 seconds old). With update checks
    // turned off the server can't tell, so the host agent's own check ("update-if-newer") is the guard.
    if (config.updateCheck) {
      const status = await updates.check();
      if (status.updateAvailable === false) throw badRequest('This server is already up to date.');
      if (status.updateAvailable !== true) throw badRequest('Couldn’t confirm that a newer version is available. Use “Check for updates” first.');
    }
    const request = ctx.updateRequests.create(user.username, 'manual');
    if (!request) throw badRequest('An update is already scheduled.');
    ctx.audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.update_requested', targetType: 'system', ip: clientIp(req), details: { scheduledFor: request.scheduledFor } });
    ctx.terminals.notifyAll(updateNoticeText(request.scheduledFor));
    ctx.updateRequests.markAnnounced(request.id);
    return view();
  });

  app.delete('/api/admin/version/update-now', async (req) => {
    const { user } = requireAdmin(req);
    const pending = ctx.updateRequests.pending();
    if (pending && ctx.updateRequests.cancel(pending.id)) {
      ctx.audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.update_cancelled', targetType: 'system', ip: clientIp(req) });
      ctx.terminals.notifyAll('[The scheduled Any-SSH update was cancelled.]');
    }
    return view();
  });

  // Any signed-in user: is a restart coming? Drives the banner.
  app.get('/api/update-notice', async (req) => {
    requireUser(req);
    const pending = ctx.updateRequests.pending();
    return { scheduledFor: pending?.scheduledFor ?? null };
  });
}
