import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { TOKEN_TTL_MS, consumeToken, findToken, issueToken, notify, tokenUrl } from '../accountTokens.js';
import { HttpError, badRequest, clientIp, parse, requireUser } from '../http.js';
import { emails } from '../mail.js';
import { checkPasswordPolicy, hashPassword, verifyPassword } from '../passwords.js';
import { publicUser, type AppContext, type UserRow } from '../types.js';

export const emailSchema = z.email('Enter a valid email address').max(254);

/** A second reset request within this window is silently ignored (stops inbox flooding). */
const RESET_RESEND_MS = 2 * 60_000;

const tokenBody = z.object({ token: z.string().min(1).max(100) });

export function registerAccountRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { db, audit, sessions, terminals } = ctx;
  const strict = { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } };

  // ---- Forgotten password ----
  // Always answers the same way, whether or not the account exists or has an email address.

  app.post('/api/auth/forgot', strict, async (req) => {
    const { identifier } = parse(z.object({ identifier: z.string().trim().min(1).max(254) }), req.body);
    const user = db
      .prepare("SELECT * FROM users WHERE (username = ? OR email = ? COLLATE NOCASE) AND status = 'active'")
      .get(identifier, identifier) as UserRow | undefined;

    const recent = user
      ? (db
          .prepare("SELECT 1 FROM auth_tokens WHERE user_id = ? AND purpose = 'reset' AND used_at IS NULL AND created_at > ?")
          .get(user.id, Date.now() - RESET_RESEND_MS) as unknown)
      : undefined;

    if (user?.email && !recent) {
      const token = issueToken(ctx, user.id, 'reset');
      const msg = emails.passwordReset({
        to: user.email,
        displayName: user.display_name,
        username: user.username,
        url: tokenUrl(ctx, 'reset', token),
        minutes: TOKEN_TTL_MS.reset / 60_000,
      });
      // Not awaited: response time must not reveal whether an email was sent.
      ctx.mailer.send(msg).catch((err: unknown) => req.log.warn({ err }, 'Failed to send password reset email'));
    }
    audit.record({
      actorId: user?.id ?? null, actorUsername: user?.username ?? null, action: 'auth.password_reset_request', ip: clientIp(req),
      outcome: user?.email ? 'success' : 'failure',
      details: user ? (user.email ? (recent ? { throttled: true } : {}) : { reason: 'no_email' }) : { identifier: identifier.slice(0, 64), reason: 'unknown_user' },
    });
    return { ok: true };
  });

  // ---- Completing an emailed link (invite or reset) ----

  app.post('/api/auth/token/check', strict, async (req) => {
    const { token } = parse(tokenBody, req.body);
    const found = findToken(ctx, token);
    if (!found) throw new HttpError(400, 'This link is invalid or has expired. Ask for a new one.', 'invalid_token');
    return { purpose: found.row.purpose, username: found.user.username, displayName: found.user.display_name };
  });

  app.post('/api/auth/token/complete', strict, async (req) => {
    const body = parse(tokenBody.extend({ newPassword: z.string().max(1024) }), req.body);
    const found = findToken(ctx, body.token);
    if (!found) throw new HttpError(400, 'This link is invalid or has expired. Ask for a new one.', 'invalid_token');
    const { row, user } = found;
    const problem = checkPasswordPolicy(body.newPassword, user.username);
    if (problem) throw badRequest(problem);
    const hash = await hashPassword(body.newPassword);
    if (!consumeToken(ctx, row.token_hash)) throw new HttpError(400, 'This link has already been used.', 'invalid_token');

    const now = Date.now();
    db.prepare(
      `UPDATE users SET password_hash = ?, must_change_password = 0, failed_logins = 0, locked_until = NULL,
         password_changed_at = ?, updated_at = ? WHERE id = ?`,
    ).run(hash, now, now, user.id);
    // Any other outstanding links die with this one; every existing session is signed out.
    db.prepare('DELETE FROM auth_tokens WHERE user_id = ? AND used_at IS NULL').run(user.id);
    sessions.destroyAllForUser(user.id);
    terminals.closeForUser(user.id, 'Your password was changed.');

    audit.record({
      actorId: user.id, actorUsername: user.username, ip: clientIp(req),
      action: row.purpose === 'invite' ? 'auth.invite_accept' : 'auth.password_reset',
    });
    if (row.purpose === 'reset') notify(ctx, req.log, user, 'your password was reset using an emailed link');
    // Two-factor is untouched: if it is on, the next sign-in still asks for a code.
    return { ok: true, username: user.username };
  });

  // ---- Profile ----

  app.patch('/api/auth/profile', async (req) => {
    const { user } = requireUser(req);
    const body = parse(
      z
        .object({
          displayName: z.string().trim().min(1).max(100).optional(),
          email: emailSchema.nullable().optional(),
          password: z.string().max(1024).optional(),
        })
        .refine((b) => b.displayName !== undefined || b.email !== undefined, 'Nothing to update'),
      req.body,
    );
    const emailChanging = body.email !== undefined && (body.email ?? null)?.toLowerCase() !== user.email?.toLowerCase();
    if (emailChanging) {
      // Changing where reset links go is as sensitive as changing the password.
      if (!body.password) throw badRequest('Enter your password to change your email address.');
      if (!(await verifyPassword(user.password_hash, body.password))) {
        audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.email_change', outcome: 'failure', ip: clientIp(req) });
        throw badRequest('Password is incorrect.');
      }
      if (body.email && db.prepare('SELECT 1 FROM users WHERE email = ? COLLATE NOCASE AND id != ?').get(body.email, user.id)) {
        throw new HttpError(409, 'That email address is already in use.', 'conflict');
      }
    }

    db.prepare('UPDATE users SET display_name = COALESCE(?, display_name), email = ?, updated_at = ? WHERE id = ?').run(
      body.displayName ?? null,
      emailChanging ? (body.email ?? null) : user.email,
      Date.now(),
      user.id,
    );
    if (emailChanging) {
      // Pending reset links were addressed to the old mailbox.
      db.prepare("DELETE FROM auth_tokens WHERE user_id = ? AND purpose = 'reset' AND used_at IS NULL").run(user.id);
      audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.email_change', ip: clientIp(req), details: { email: body.email ?? null } });
      if (user.email) notify(ctx, req.log, user, `your email address was changed to ${body.email ?? '(none)'}`, user.email);
    }
    return { user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(user.id) as UserRow) };
  });
}
