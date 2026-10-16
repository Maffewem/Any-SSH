import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { ResolvedSession } from './sessions.js';
import type { AppContext } from './types.js';

declare module 'fastify' {
  interface FastifyRequest {
    auth: ResolvedSession | null;
  }
}

export class HttpError extends Error {
  constructor(
    readonly statusCode: number,
    message: string,
    readonly code?: string,
  ) {
    super(message);
  }
}

export const badRequest = (msg: string) => new HttpError(400, msg, 'bad_request');
export const notFound = (msg = 'Not found.') => new HttpError(404, msg, 'not_found');
export const forbidden = (msg = 'Forbidden') => new HttpError(403, msg, 'forbidden');

export function parse<T extends z.ZodType>(schema: T, data: unknown): z.infer<T> {
  const result = schema.safeParse(data);
  if (!result.success) {
    const issue = result.error.issues[0];
    const where = issue?.path.length ? `${issue.path.join('.')}: ` : '';
    throw badRequest(`${where}${issue?.message ?? 'Invalid input'}`);
  }
  return result.data;
}

export function clientIp(req: FastifyRequest): string {
  return req.ip;
}

export function cookieName(ctx: AppContext): string {
  // The __Host- prefix makes browsers refuse the cookie unless it is Secure, host-only and Path=/.
  return ctx.config.cookieSecure ? '__Host-anyssh_sid' : 'anyssh_sid';
}

export function setSessionCookie(ctx: AppContext, reply: FastifyReply, token: string): void {
  reply.setCookie(cookieName(ctx), token, {
    httpOnly: true,
    secure: ctx.config.cookieSecure,
    sameSite: 'strict',
    path: '/',
  });
}

export function clearSessionCookie(ctx: AppContext, reply: FastifyReply): void {
  reply.clearCookie(cookieName(ctx), { path: '/', secure: ctx.config.cookieSecure, sameSite: 'strict', httpOnly: true });
}

export function sessionToken(ctx: AppContext, req: FastifyRequest): string | undefined {
  return req.cookies[cookieName(ctx)];
}

interface GuardOptions {
  /** Allow users who still have to replace an admin-issued temporary password. */
  allowPendingPasswordChange?: boolean;
  admin?: boolean;
  /** Let a session through that is held by the trusted-IP challenge (only the challenge routes). */
  allowIpChallenge?: boolean;
}

/** Returns the authenticated, fully-logged-in user or throws 401/403. */
export function requireUser(req: FastifyRequest, opts: GuardOptions = {}): ResolvedSession {
  const auth = req.auth;
  if (!auth || auth.session.stage !== 'full') throw new HttpError(401, 'You are not signed in.', 'unauthenticated');
  if (auth.session.ip_challenge === 1 && !opts.allowIpChallenge) {
    throw new HttpError(403, 'Verify this sign-in to continue.', 'ip_challenge');
  }
  if (auth.session.locked_at !== null) throw new HttpError(401, 'This session is locked. Enter your password to unlock it.', 'session_locked');
  if (auth.user.must_change_password && !opts.allowPendingPasswordChange) {
    throw new HttpError(403, 'You must change your password before continuing.', 'password_change_required');
  }
  if (opts.admin && auth.user.role !== 'admin') throw forbidden('Administrator access is required.');
  return auth;
}

export function requireAdmin(req: FastifyRequest): ResolvedSession {
  return requireUser(req, { admin: true });
}

export const idParam = z.object({ id: z.uuid() });
