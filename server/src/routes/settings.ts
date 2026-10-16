import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { notify } from '../accountTokens.js';
import { emailSchema } from './account.js';
import { badRequest, clientIp, parse, requireAdmin } from '../http.js';
import { emails } from '../mail.js';
import { changes } from '../audit.js';
import { limitSettingsSchema, maintenanceSettingsSchema, mailSettingsSchema, securitySettingsSchema, sessionSettingsSchema, type SettingsGroup } from '../settings.js';
import type { AppContext } from '../types.js';

const groupParam = z.object({ group: z.enum(['mail', 'sessions', 'limits', 'security', 'backup', 'maintenance']) });

/** Admin-only runtime settings. Every change is audited; secrets are write-only. */
export function registerSettingsRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { audit, settings } = ctx;

  app.get('/api/admin/settings', async (req) => {
    requireAdmin(req);
    return settings.describe();
  });

  app.put('/api/admin/settings/mail', async (req) => {
    const { user } = requireAdmin(req);
    const body = parse(mailSettingsSchema, req.body);
    let changed: string[];
    let diff: Record<string, { from: unknown; to: unknown }>;
    try {
      ({ changed, changes: diff } = settings.setMail(body, user.id));
    } catch (err) {
      throw badRequest(err instanceof Error ? err.message : String(err));
    }
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.settings_change', targetType: 'settings', targetId: 'mail', ip: clientIp(req), details: { changed, changes: diff } });
    if (changed.length) notify(ctx, req.log, user, `email settings were changed (${changed.join(', ')})`);
    return settings.describe();
  });

  app.put('/api/admin/settings/sessions', async (req) => {
    const { user } = requireAdmin(req);
    const body = parse(sessionSettingsSchema, req.body);
    const before = settings.sessions;
    settings.setSessions(body, user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.settings_change', targetType: 'settings', targetId: 'sessions', ip: clientIp(req), details: { changes: changes(before, body) } });
    return settings.describe();
  });

  app.put('/api/admin/settings/limits', async (req) => {
    const { user } = requireAdmin(req);
    const body = parse(limitSettingsSchema, req.body);
    const before = settings.limits;
    settings.setLimits(body, user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.settings_change', targetType: 'settings', targetId: 'limits', ip: clientIp(req), details: { changes: changes(before, body) } });
    return settings.describe();
  });

  app.put('/api/admin/settings/security', async (req) => {
    const { user } = requireAdmin(req);
    const body = parse(securitySettingsSchema, req.body);
    const before = settings.security;
    settings.setSecurity(body, user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.settings_change', targetType: 'settings', targetId: 'security', ip: clientIp(req), details: { changes: changes(before, body) } });
    return settings.describe();
  });

  app.put('/api/admin/settings/maintenance', async (req) => {
    const { user } = requireAdmin(req);
    const body = parse(maintenanceSettingsSchema, req.body);
    const before = settings.maintenance;
    settings.setMaintenance(body, user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.settings_change', targetType: 'settings', targetId: 'maintenance', ip: clientIp(req), details: { changes: changes({ ...before, days: before.days.join(',') }, { ...body, days: body.days.join(',') }) } });
    return settings.describe();
  });

  app.delete('/api/admin/settings/:group', async (req) => {
    const { user } = requireAdmin(req);
    const { group } = parse(groupParam, req.params);
    const g = group as SettingsGroup;
    const snapshot = (): Record<string, unknown> => {
      if (g === 'mail') { const m = settings.describe().mail; return { enabled: m.enabled, host: m.host, port: m.port, security: m.security, username: m.username, from: m.from }; }
      return { ...settings[g] };
    };
    const before = snapshot();
    settings.reset(g);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.settings_reset', targetType: 'settings', targetId: group, ip: clientIp(req), details: { changes: changes(before, snapshot()) } });
    if (group === 'mail') notify(ctx, req.log, user, 'email settings were reset to the server defaults');
    return settings.describe();
  });

  // Sends a test message with the saved settings, to the admin's own address unless another is given.
  app.post('/api/admin/settings/mail/test', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req) => {
    const { user } = requireAdmin(req);
    const { to } = parse(z.object({ to: emailSchema.optional() }), req.body ?? {});
    const address = to ?? user.email;
    if (!address) throw badRequest('Add an email address to your account, or enter one to send the test email to.');
    const auditBase = { actorId: user.id, actorUsername: user.username, action: 'admin.settings_mail_test', ip: clientIp(req) };
    try {
      await ctx.mailer.send(emails.test({ to: address, displayName: user.display_name, sentBy: user.username }));
    } catch (err) {
      const message = (err instanceof Error ? err.message : String(err)).slice(0, 300);
      audit.record({ ...auditBase, outcome: 'failure', details: { to: address, error: message } });
      throw badRequest(`Sending failed: ${message}`);
    }
    audit.record({ ...auditBase, details: { to: address, delivery: ctx.mailer.delivery } });
    return { sent: ctx.mailer.delivery === 'smtp', delivery: ctx.mailer.delivery, to: address };
  });
}
