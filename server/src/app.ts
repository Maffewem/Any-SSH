import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';
import websocket from '@fastify/websocket';
import Fastify, { type FastifyInstance } from 'fastify';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { AuditLog } from './audit.js';
import { BackupService } from './backup/service.js';
import { BruteForce } from './bruteForce.js';
import { registerBackupRoutes } from './routes/backup.js';
import type { Config } from './config.js';
import { SecretBox, randomToken } from './crypto.js';
import { openDatabase, type DB } from './db.js';
import { HttpError, clientIp, sessionToken } from './http.js';
import { checkSessionIp } from './ipTrust.js';
import { ConfigurableMailer, type Mailer } from './mail.js';
import { countStale } from './rotate.js';
import { registerAccountRoutes } from './routes/account.js';
import { registerAccountLifecycleRoutes } from './routes/accountLifecycle.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerJumpHostRoutes } from './routes/jumpHosts.js';
import { registerKeyRoutes } from './routes/keys.js';
import { registerTrustedIpRoutes } from './routes/trustedIps.js';
import { registerServerRoutes } from './routes/servers.js';
import { registerSettingsRoutes } from './routes/settings.js';
import { registerUserRoutes } from './routes/users.js';
import { SessionStore } from './sessions.js';
import { Settings } from './settings.js';
import { TerminalRegistry } from './ssh/registry.js';
import { registerTerminalRoute } from './ssh/terminal.js';
import type { AppContext } from './types.js';
import { UpdateChecker } from './updates.js';
import { UpdateRequests } from './updateRequests.js';
import { updateNoticeText } from './routes/version.js';
import { registerVersionRoutes } from './routes/version.js';
import { registerHealthRoutes } from './routes/health.js';

/** Header the web client sends on every state-changing request (see docs/SECURITY.md, CSRF). */
export const CSRF_HEADER = 'x-any-ssh';

export interface BuiltApp {
  app: FastifyInstance;
  ctx: AppContext;
  /** One-time token required to create the first administrator; null once any user exists. */
  setup: { token: string | null };
}

export async function buildApp(config: Config, opts: { db?: DB; logger?: boolean; mailer?: Mailer; updates?: ConstructorParameters<typeof UpdateChecker>[2] } = {}): Promise<BuiltApp> {
  const db = opts.db ?? openDatabase(config.dbPath);
  const box = new SecretBox(config.masterKey, config.previousMasterKeys);
  const settings = new Settings(db, box, config);
  const sessions = new SessionStore(db, settings);
  const terminals = new TerminalRegistry();
  sessions.setRevokeListener((hashes) => terminals.closeForSessions(hashes, 'You were signed out.'));
  sessions.setLockListener((hash, locked) => terminals.setLockedForSession(hash, locked));

  const userCount = (db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number }).n;
  const setup = { token: userCount === 0 ? randomToken(18) : null };

  const app = Fastify({
    logger: opts.logger === false ? false : { level: config.logLevel, redact: ['req.headers.cookie', 'req.headers.authorization'] },
    trustProxy: config.trustProxy,
    bodyLimit: 256 * 1024,
  });
  let mailer = opts.mailer;
  if (!mailer) {
    const configurable = new ConfigurableMailer(() => {
      const mail = settings.mail;
      return { smtp: mail.smtp, mailFrom: mail.from };
    }, app.log);
    settings.onChange((group) => group === 'mail' && configurable.reload());
    mailer = configurable;
  }
  const audit = new AuditLog(db);
  const ctx: AppContext = {
    config, db, box, audit, bruteForce: new BruteForce(db, settings, audit), sessions, terminals, mailer, settings,
    updates: new UpdateChecker(config, app.log, opts.updates),
    updateRequests: new UpdateRequests(db),
    backups: new BackupService({ db, settings, box, audit, mailer, config, log: app.log }),
  };
  const stale = countStale(db, ctx.box);
  if (stale > 0) app.log.warn(`${stale} secret(s) are sealed with a retired master key. Run \`npm run rotate-keys\`.`);
  app.decorateRequest('auth', null);

  await app.register(cookie);
  await app.register(rateLimit, { global: true, max: 600, timeWindow: '1 minute' });
  await app.register(websocket, { options: { maxPayload: 256 * 1024 } });

  const wsOrigins = config.allowedOrigins.map((o) => o.replace(/^http/, 'ws'));
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        // xterm.js injects a <style> element for its renderer.
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'", ...wsOrigins],
        workerSrc: ["'self'"],
        manifestSrc: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        baseUri: ["'none'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: config.cookieSecure ? [] : null,
      },
    },
    hsts: config.cookieSecure ? { maxAge: 31536000, includeSubDomains: true } : false,
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: 'no-referrer' },
  });

  // CSRF defence in depth (cookies are already SameSite=Strict): state-changing API calls must
  // carry a custom header, which a cross-site form or simple fetch cannot add without a CORS
  // preflight that we never approve, and any Origin they send must be ours.
  app.addHook('onRequest', async (req) => {
    if (!req.url.startsWith('/api/')) return;
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      if (req.headers[CSRF_HEADER] !== '1') throw new HttpError(403, 'The request was blocked: a required security header is missing.', 'csrf');
      const origin = req.headers.origin;
      if (origin && !config.allowedOrigins.includes(origin)) throw new HttpError(403, 'The request was blocked: it came from an unrecognised origin.', 'csrf');
    }
    req.auth = sessions.resolve(sessionToken(ctx, req));
    // The lock screen's background state check is not activity; everything else is.
    if (req.auth?.session.stage === 'full' && req.url.split('?')[0] !== '/api/auth/state') sessions.touch(req.auth.session);
    if (req.auth?.session.stage === 'full') {
      // Every request (and so every terminal WebSocket upgrade) is checked against the trusted IP list.
      checkSessionIp(ctx, req.log, req.auth.user, req.auth.session, clientIp(req));
    }
  });

  app.addHook('onSend', async (req, reply) => {
    if (req.url.startsWith('/api/')) reply.header('Cache-Control', 'no-store');
  });

  app.setErrorHandler((err: Error & { statusCode?: number; code?: string }, req, reply) => {
    if (err instanceof HttpError) return reply.status(err.statusCode).send({ error: err.message, code: err.code });
    if (err.statusCode === 429) return reply.status(429).send({ error: 'Too many requests. Slow down and try again.', code: 'rate_limited' });
    if (err.statusCode && err.statusCode >= 400 && err.statusCode < 500) {
      return reply.status(err.statusCode).send({ error: 'Bad request', code: err.code ?? 'bad_request' });
    }
    req.log.error(err);
    return reply.status(500).send({ error: 'Something went wrong.', code: 'internal' });
  });

  app.get('/api/health', async () => ({ ok: true }));
  registerAuthRoutes(app, ctx);
  registerAccountRoutes(app, ctx);
  registerAccountLifecycleRoutes(app, ctx);
  registerTrustedIpRoutes(app, ctx);
  registerUserRoutes(app, ctx, setup);
  registerKeyRoutes(app, ctx);
  registerJumpHostRoutes(app, ctx);
  registerServerRoutes(app, ctx);
  registerSettingsRoutes(app, ctx);
  registerBackupRoutes(app, ctx);
  registerTerminalRoute(app, ctx);
  registerVersionRoutes(app, ctx);
  registerHealthRoutes(app, ctx);

  if (config.webRoot && existsSync(path.join(config.webRoot, 'index.html'))) {
    await app.register(fastifyStatic, { root: config.webRoot, wildcard: false });
    // Single-page app: unknown non-API paths get index.html.
    app.setNotFoundHandler((req, reply) => {
      if (req.method === 'GET' && !req.url.startsWith('/api/')) return reply.sendFile('index.html');
      return reply.status(404).send({ error: 'Not found.', code: 'not_found' });
    });
  } else {
    app.setNotFoundHandler((_req, reply) => reply.status(404).send({ error: 'Not found.', code: 'not_found' }));
  }

  // Tests build many apps; only a real server (which has a data dir on disk) polls the registry.
  if (!opts.db) {
    ctx.updates.start();
    ctx.backups.start();
  }
  const purge = setInterval(() => {
    sessions.purgeExpired();
    ctx.bruteForce.purge();
  }, 10 * 60_000);
  purge.unref();
  // Warn people with open terminals as soon as an update is requested (the host starts it after the warning period).
  const announce = setInterval(() => {
    const pending = ctx.updateRequests.pending();
    if (pending && !pending.announced) {
      ctx.updateRequests.markAnnounced(pending.id);
      terminals.notifyAll(updateNoticeText(pending.scheduledFor));
    }
  }, 10_000);
  announce.unref();
  app.addHook('onClose', async () => {
    clearInterval(purge);
    clearInterval(announce);
    ctx.updates.stop();
    ctx.backups.stop();
    terminals.closeAll('Server shutting down');
    if (!opts.db) db.close();
  });

  return { app, ctx, setup };
}
