import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { notify } from '../accountTokens.js';
import { HttpError, badRequest, clientIp, idParam, parse, requireUser } from '../http.js';
import { isTrustedIp, newTrustedId, normaliseIp, parseTrustedEntry, trustedEntries } from '../ipTrust.js';
import { verifyPassword } from '../passwords.js';
import type { AppContext, UserRow } from '../types.js';

const MAX_ENTRIES = 50;
const passwordField = z.string().min(1).max(1024);

/**
 * The user's own trusted IP list (Account → Trusted IP addresses). Changes that could weaken the
 * protection need the account password, so a stolen session cannot trust the thief's address.
 */
export function registerTrustedIpRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { db, audit } = ctx;
  const getUser = (id: string) => db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow;
  const strict = { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } };

  const entryRows = (userId: string) =>
    db.prepare('SELECT id, cidr, label, created_at FROM trusted_ips WHERE user_id = ? ORDER BY created_at').all(userId) as {
      id: string;
      cidr: string;
      label: string;
      created_at: number;
    }[];

  function view(user: UserRow, ip: string | null) {
    const fresh = getUser(user.id);
    return {
      enabled: fresh.trusted_ip_enabled === 1,
      policy: fresh.trusted_ip_policy,
      currentIp: normaliseIp(ip),
      currentIpTrusted: isTrustedIp(trustedEntries(ctx, user.id), ip),
      /** Challenge needs a way to prove identity from a new address. */
      canChallenge: !!fresh.email || fresh.totp_enabled === 1,
      entries: entryRows(user.id).map((e) => ({ id: e.id, cidr: e.cidr, label: e.label, createdAt: e.created_at })),
    };
  }

  async function confirmPassword(req: Parameters<typeof clientIp>[0], user: UserRow, password: string, action: string): Promise<void> {
    if (await verifyPassword(user.password_hash, password)) return;
    audit.record({ actorId: user.id, actorUsername: user.username, action, outcome: 'failure', ip: clientIp(req) });
    throw badRequest('Password is incorrect.');
  }

  app.get('/api/account/trusted-ips', async (req) => {
    const { user } = requireUser(req);
    return view(user, clientIp(req));
  });

  app.post('/api/account/trusted-ips', strict, async (req) => {
    const { user } = requireUser(req);
    const body = parse(
      z.object({
        password: passwordField,
        /** Trust the address this request came from. */
        current: z.boolean().optional(),
        cidr: z.string().trim().max(64).optional(),
        label: z.string().trim().max(60).default(''),
      }),
      req.body,
    );
    await confirmPassword(req, user, body.password, 'user.trusted_ip_add');
    let value: string;
    if (body.current) {
      const ip = normaliseIp(clientIp(req));
      if (!ip) throw badRequest('Could not work out your current IP address.');
      value = ip;
    } else {
      const parsed = parseTrustedEntry(body.cidr ?? '');
      if ('error' in parsed) throw badRequest(parsed.error);
      value = parsed.value;
    }
    if (entryRows(user.id).length >= MAX_ENTRIES) throw badRequest(`You can list at most ${MAX_ENTRIES} addresses.`);
    if (db.prepare('SELECT 1 FROM trusted_ips WHERE user_id = ? AND cidr = ?').get(user.id, value)) {
      throw new HttpError(409, 'That address is already on the list.', 'conflict');
    }
    db.prepare('INSERT INTO trusted_ips (id, user_id, cidr, label, created_at) VALUES (?, ?, ?, ?, ?)').run(
      newTrustedId(), user.id, value, body.label, Date.now(),
    );
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.trusted_ip_add', ip: clientIp(req), details: { entry: value } });
    notify(ctx, req.log, user, `${value} was added to your trusted IP list`);
    return view(user, clientIp(req));
  });

  app.delete('/api/account/trusted-ips/:id', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    const row = db.prepare('SELECT cidr FROM trusted_ips WHERE id = ? AND user_id = ?').get(id, user.id) as { cidr: string } | undefined;
    if (!row) throw new HttpError(404, 'Not found', 'not_found');
    // Do not let someone delete the entry that covers the address they are using while the list is enforced.
    const fresh = getUser(user.id);
    if (fresh.trusted_ip_enabled) {
      const rest = trustedEntries(ctx, user.id).filter((e) => e !== row.cidr);
      if (!isTrustedIp(rest, clientIp(req))) {
        throw badRequest('That entry covers the address you are using now. Turn the feature off first, or add another entry that covers this address.');
      }
    }
    db.prepare('DELETE FROM trusted_ips WHERE id = ?').run(id);
    audit.record({ actorId: user.id, actorUsername: user.username, action: 'user.trusted_ip_remove', ip: clientIp(req), details: { entry: row.cidr } });
    return view(user, clientIp(req));
  });

  app.put('/api/account/trusted-ips/settings', strict, async (req) => {
    const { user } = requireUser(req);
    const body = parse(
      z.object({ password: passwordField, enabled: z.boolean(), policy: z.enum(['notify', 'challenge']) }),
      req.body,
    );
    await confirmPassword(req, user, body.password, 'user.trusted_ip_settings');
    if (body.enabled) {
      if (!isTrustedIp(trustedEntries(ctx, user.id), clientIp(req))) {
        throw badRequest('Add the address you are using now to the list first, or you would be locked out of this session.');
      }
      if (body.policy === 'challenge' && !user.email && !user.totp_enabled) {
        throw badRequest('Holding sign-ins from new addresses needs a way to verify you. Add an email address or turn on two-factor first.');
      }
    }
    db.prepare('UPDATE users SET trusted_ip_enabled = ?, trusted_ip_policy = ?, updated_at = ? WHERE id = ?').run(
      body.enabled ? 1 : 0, body.policy, Date.now(), user.id,
    );
    // Turning the feature off releases any session it was holding.
    if (!body.enabled) db.prepare('UPDATE sessions SET ip_challenge = 0 WHERE user_id = ?').run(user.id);
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'user.trusted_ip_settings', ip: clientIp(req),
      details: { enabled: body.enabled, policy: body.policy },
    });
    notify(ctx, req.log, user, body.enabled ? `the trusted IP list was turned on (${body.policy === 'challenge' ? 'unlisted addresses are held until verified' : 'unlisted addresses are reported'})` : 'the trusted IP list was turned off');
    return view(user, clientIp(req));
  });
}
