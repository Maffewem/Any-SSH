import type { FastifyInstance } from 'fastify';
import { requireAdmin } from '../http.js';
import type { AppContext } from '../types.js';

export function registerVersionRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { config, updates } = ctx;
  const view = () => ({
    current: updates.build,
    checkEnabled: config.updateCheck,
    autoUpdate: config.autoUpdate,
    image: `${config.updateImage}:${config.updateTag}`,
    ...updates.current,
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
}
