import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { notify } from '../accountTokens.js';
import { emailSchema } from './account.js';
import { badRequest, clientIp, parse, requireAdmin } from '../http.js';
import { emails } from '../mail.js';
import { limitSettingsSchema, mailSettingsSchema, sessionSettingsSchema, type SettingsGroup } from '../settings.js';
import type { AppContext } from '../types.js';

const groupParam = z.object({ group: z.enum(['mail', 'sessions', 'limits', 'backup']) });

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
    try {
      changed = settings.setMail(body, user.id);
    } catch (err) {
      throw badRequest(err instanceof Error ? err.message : String(err));
    }
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.settings_change', targetType: 'settings', targetId: 'mail', ip: clientIp(req), details: { changed } });
    if (changed.length) notify(ctx, req.log, user, `email settings were changed (${changed.join(', ')})`);
    return settings.describe();
  });

  app.put('/api/admin/settings/sessions', async (req) => {
    const { user } = requireAdmin(req);
    const body = parse(sessionSettingsSchema, req.body);
    settings.setSessions(body, user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.settings_change', targetType: 'settings', targetId: 'sessions', ip: clientIp(req), details: body });
    return settings.describe();
  });

  app.put('/api/admin/settings/limits', async (req) => {
    const { user } = requireAdmin(req);
    const body = parse(limitSettingsSchema, req.body);
    settings.setLimits(body, user.id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.settings_change', targetType: 'settings', targetId: 'limits', ip: clientIp(req), details: body });
    return settings.describe();
  });

  app.delete('/api/admin/settings/:group', async (req) => {
    const { user } = requireAdmin(req);
    const { group } = parse(groupParam, req.params);
    settings.reset(group as SettingsGroup);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.settings_reset', targetType: 'settings', targetId: group, ip: clientIp(req) });
    if (group === 'mail') notify(ctx, req.log, user, 'email settings were reset to the server defaults');
    return settings.describe();
  });

  // Sends a test message with the saved settings, to the admin's own address unless another is given.
  app.post('/api/admin/settings/mail/test', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req) => {
    const { user } = requireAdmin(req);
    const { to } = parse(z.object({ to: emailSchema.optional() }), req.body ?? {});
    const address = to ?? user.email;
    if (!address) throw badRequest('Add an email address to your account, or enter one to send the test to.');
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
