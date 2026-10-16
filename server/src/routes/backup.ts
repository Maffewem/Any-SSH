import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { notify } from '../accountTokens.js';
import { recordReauthFailure } from '../bruteForce.js';
import { BackupConfigError } from '../backup/service.js';
import { generateBackupKeyPair } from '../backup/format.js';
import { badRequest, clientIp, parse, requireAdmin } from '../http.js';
import { verifyPassword } from '../passwords.js';
import { backupSettingsSchema } from '../settings.js';
import type { AppContext } from '../types.js';

/** Admin-only backup settings, status and actions. Restoring is deliberately not offered over the web (see docs). */
export function registerBackupRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { audit, settings, backups } = ctx;
  const who = (req: Parameters<typeof requireAdmin>[0]) => {
    const { user } = requireAdmin(req);
    return { user, actor: { id: user.id, username: user.username, ip: clientIp(req) } };
  };

  // Where backups go and which key they are encrypted to decide who can read them, so changing either needs the
  // password again: a hijacked admin session must not be able to redirect copies of the database.
  app.put('/api/admin/settings/backup', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req) => {
    const { user } = requireAdmin(req);
    const { currentPassword, ...body } = parse(backupSettingsSchema.and(z.object({ currentPassword: z.string().min(1).max(1024) })), req.body);
    const auditBase = { actorId: user.id, actorUsername: user.username, action: 'admin.settings_change', targetType: 'settings', targetId: 'backup', ip: clientIp(req) };
    if (!(await verifyPassword(user.password_hash, currentPassword))) {
      recordReauthFailure(ctx, req.log, clientIp(req), user);
      audit.record({ ...auditBase, outcome: 'failure', details: { reason: 'bad_password' } });
      throw badRequest('The password isn’t correct.');
    }
    const { changed, changes } = settings.setBackup(body, user.id);
    audit.record({ ...auditBase, details: { changed, changes } });
    if (changed.length) notify(ctx, req.log, user, `backup settings were changed (${changed.join(', ')})`);
    return settings.describe();
  });

  app.get('/api/admin/backup', async (req) => {
    requireAdmin(req);
    return { status: backups.status(), runs: backups.recent() };
  });

  // Makes a recovery key pair for the admin to keep. The server stores nothing: only the public half comes back
  // in a later settings save.
  app.post('/api/admin/backup/keypair', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req) => {
    const { user } = requireAdmin(req);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'admin.backup_keypair', ip: clientIp(req) });
    return generateBackupKeyPair();
  });

  app.post('/api/admin/backup/test', { config: { rateLimit: { max: 6, timeWindow: '1 minute' } } }, async (req) => {
    const { user } = requireAdmin(req);
    const auditBase = { actorId: user.id, actorUsername: user.username, action: 'admin.backup_test', ip: clientIp(req) };
    try {
      const result = await backups.test();
      audit.record({ ...auditBase, details: result });
      return result;
    } catch (err) {
      const message = (err instanceof Error ? err.message : String(err)).slice(0, 300);
      audit.record({ ...auditBase, outcome: 'failure', details: { error: message } });
      throw badRequest(message);
    }
  });

  app.post('/api/admin/backup/run', { config: { rateLimit: { max: 3, timeWindow: '1 minute' } } }, async (req) => {
    const { actor } = who(req);
    try {
      return { run: await backups.run('manual', actor), status: backups.status() };
    } catch (err) {
      if (err instanceof BackupConfigError) throw badRequest(err.message);
      throw err;
    }
  });
}
