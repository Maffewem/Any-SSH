import type { FastifyRequest } from 'fastify';
import { recordAuthFailure } from './bruteForce.js';
import { HttpError, clientIp } from './http.js';
import type { AppContext } from './types.js';

export const TURNSTILE_ORIGIN = 'https://challenges.cloudflare.com';
const SITEVERIFY_URL = `${TURNSTILE_ORIGIN}/turnstile/v0/siteverify`;
const TIMEOUT_MS = 5000;

export type TurnstileAction = 'signup' | 'reset' | 'login';

type Fetch = typeof fetch;

/** Checks a Cloudflare Turnstile response token with Cloudflare. Any failure to get a clear "yes" is a "no". */
export class Turnstile {
  constructor(private readonly fetchImpl: Fetch = fetch) {}

  async verify(secret: string, token: string, ip: string | null): Promise<boolean> {
    // Tokens are short (well under 2048 characters); refuse anything else without calling Cloudflare.
    if (!token || token.length > 2048) return false;
    const form = new URLSearchParams({ secret, response: token });
    if (ip) form.set('remoteip', ip);
    try {
      const res = await this.fetchImpl(SITEVERIFY_URL, {
        method: 'POST',
        body: form,
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) return false;
      const body = (await res.json()) as { success?: unknown };
      return body.success === true;
    } catch {
      return false;
    }
  }
}

/**
 * Enforces the Cloudflare browser check for an action when the administrator has turned it on. Does nothing when it
 * is off. When it is on, a missing token, a rejected token, an unreachable Cloudflare or a missing secret key all
 * refuse the request (fail closed), and the attempt counts against the caller's address.
 */
export async function requireHuman(ctx: AppContext, req: FastifyRequest, action: TurnstileAction, token: string | undefined): Promise<void> {
  if (!ctx.settings.turnstileRequired(action)) return;
  const ip = clientIp(req);
  const secret = ctx.settings.turnstileSecret();
  const ok = !!secret && !!token && (await ctx.turnstile.verify(secret, token, ip));
  if (ok) return;
  recordAuthFailure(ctx, req.log, ip, 'captcha');
  ctx.audit.record({ action: 'auth.browser_check', outcome: 'failure', ip, details: { for: action, reason: !token ? 'missing' : !secret ? 'not_configured' : 'rejected' } });
  throw new HttpError(400, 'We couldn’t confirm that you’re a person. Reload the page and try again.', 'browser_check_failed');
}
