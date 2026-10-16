import type { FastifyInstance } from 'fastify';
import { statSync, statfsSync } from 'node:fs';
import { connect as tlsConnect } from 'node:tls';
import { requireAdmin } from '../http.js';
import { SCHEMA_VERSION } from '../db.js';
import { tcpLatency } from '../ssh/jump.js';
import { resolveTarget } from '../ssh/target.js';
import type { AppContext, JumpHostRow, ServerRow } from '../types.js';

const CONCURRENCY = 8;
const CERT_TTL_MS = 10 * 60_000;
const STARTED_AT = Date.now();

export interface Probe {
  reachable: boolean;
  latencyMs: number | null;
  /** Why it could not be reached, in words an admin can act on. */
  error: string | null;
  checkedAt: number;
}

interface CertResult {
  host: string;
  /** Epoch ms, or null if the check failed. */
  notAfter: number | null;
  daysLeft: number | null;
  issuer: string | null;
  /** The certificate does not validate for this name (expired, self-signed, wrong host). */
  trusted: boolean | null;
  error: string | null;
  checkedAt: number;
}

const key = (host: string, port: number) => `${host.toLowerCase()}:${port}`;

/** Runs `fn` over `items` with at most `limit` in flight. */
async function pool<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) await fn(items[next++]!);
    }),
  );
}

/** Looks at the certificate the public address presents. Only the handshake is made; nothing is sent. */
function checkCertificate(publicUrl: string): Promise<CertResult | null> {
  let url: URL;
  try {
    url = new URL(publicUrl);
  } catch {
    return Promise.resolve(null);
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (url.protocol !== 'https:' || host === 'localhost' || /^[\d.]+$/.test(host) || host.includes(':')) return Promise.resolve(null);
  const port = url.port ? Number(url.port) : 443;
  return new Promise((resolve) => {
    const base = { host, checkedAt: Date.now() };
    const fail = (error: string): CertResult => ({ ...base, notAfter: null, daysLeft: null, issuer: null, trusted: null, error });
    const socket = tlsConnect({ host, port, servername: host, rejectUnauthorized: false, timeout: 5000 }, () => {
      const cert = socket.getPeerCertificate();
      const notAfter = cert?.valid_to ? Date.parse(cert.valid_to) : NaN;
      const trusted = socket.authorized;
      socket.destroy();
      if (!Number.isFinite(notAfter)) return resolve(fail('The server didn’t present a certificate.'));
      const issuer = cert.issuer?.O ?? cert.issuer?.CN ?? null;
      resolve({ ...base, notAfter, daysLeft: Math.floor((notAfter - Date.now()) / 86_400_000), issuer: typeof issuer === 'string' ? issuer : null, trusted, error: null });
    });
    socket.once('timeout', () => (socket.destroy(), resolve(fail('The connection to the public address timed out.'))));
    socket.once('error', (e) => resolve(fail(`Couldn’t connect to the public address (${e.message}).`)));
  });
}

/**
 * Admin-only status of this install and of every host it connects to. Reachability is a plain TCP
 * connect from this server (the same vantage point terminals use), so it needs no credentials and
 * sends no data. Servers that are reached through a jump host cannot be tested from here and are
 * reported through that jump host instead.
 */
export function registerHealthRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { db, config } = ctx;
  const probes = new Map<string, Probe>();
  let cert: CertResult | null = null;

  async function probe(host: string, port: number): Promise<Probe> {
    const checkedAt = Date.now();
    try {
      const address = await resolveTarget(host, config.allowLoopbackTargets);
      const ms = await tcpLatency(address, port);
      if (ms === null) return { reachable: false, latencyMs: null, error: 'No response on that port. The connection was refused, blocked or timed out.', checkedAt };
      return { reachable: true, latencyMs: Math.round(ms), error: null, checkedAt };
    } catch (e) {
      return { reachable: false, latencyMs: null, error: e instanceof Error ? e.message.slice(0, 200) : 'Couldn’t find that host.', checkedAt };
    }
  }

  function storage() {
    let free: number | null = null;
    let total: number | null = null;
    try {
      const fs = statfsSync(config.dataDir);
      free = fs.bavail * fs.bsize;
      total = fs.blocks * fs.bsize;
    } catch {
      /* not available on this platform */
    }
    let dbBytes: number | null = null;
    if (config.dbPath !== ':memory:') {
      dbBytes = 0;
      for (const suffix of ['', '-wal']) {
        try {
          dbBytes += statSync(config.dbPath + suffix).size;
        } catch {
          /* no WAL file yet */
        }
      }
    }
    return { freeBytes: free, totalBytes: total, databaseBytes: dbBytes };
  }

  function snapshot() {
    const jumpRows = db.prepare('SELECT * FROM jump_hosts ORDER BY name').all() as JumpHostRow[];
    const jumpName = new Map(jumpRows.map((j) => [j.id, j.name]));
    const serverRows = db
      .prepare('SELECT s.*, u.username AS owner_username FROM servers s JOIN users u ON u.id = s.owner_id ORDER BY lower(s.name)')
      .all() as (ServerRow & { owner_username: string })[];
    const anyJump = jumpRows.some((j) => j.enabled === 1);
    const status = ctx.backups.status();

    const servers = serverRows.map((s) => {
      const routed = s.jump_mode !== 'none';
      return {
        id: s.id,
        name: s.name,
        host: s.host,
        port: s.port,
        owner: s.owner_username,
        hostKey: s.host_key_pending ? ('changed' as const) : s.host_key_fingerprint ? ('pinned' as const) : ('unverified' as const),
        route: {
          mode: s.jump_mode,
          jumpHost: s.jump_mode === 'fixed' ? (jumpName.get(s.jump_host_id ?? '') ?? null) : null,
          /** Reached through a jump host, so a direct test from here would say nothing useful. */
          testable: !routed,
        },
        probe: routed ? null : (probes.get(key(s.host, s.port)) ?? null),
      };
    });
    const jumpHosts = jumpRows.map((j) => ({
      id: j.id,
      name: j.name,
      host: j.host,
      port: j.port,
      enabled: j.enabled === 1,
      hostKey: j.host_key_fingerprint ? ('pinned' as const) : ('unverified' as const),
      serverCount: serverRows.filter((s) => s.jump_host_id === j.id).length,
      probe: probes.get(key(j.host, j.port)) ?? null,
    }));

    const direct = servers.filter((s) => s.route.testable);
    return {
      generatedAt: Date.now(),
      app: {
        version: ctx.updates.build.version,
        commit: ctx.updates.build.commit,
        builtAt: ctx.updates.build.builtAt,
        startedAt: STARTED_AT,
        uptimeSeconds: Math.round(process.uptime()),
        node: process.version,
        schemaVersion: SCHEMA_VERSION,
        updateAvailable: ctx.updates.current.updateAvailable,
        updateCheckedAt: ctx.updates.current.checkedAt,
        terminals: ctx.terminals.count(),
      },
      storage: storage(),
      certificate: cert,
      backups: {
        configured: status.configured,
        scheduled: status.scheduled,
        stale: status.stale,
        lastSuccessAt: status.lastSuccess?.startedAt ?? null,
        lastOutcome: status.last?.outcome ?? null,
      },
      summary: {
        servers: servers.length,
        reachable: direct.filter((s) => s.probe?.reachable).length,
        unreachable: direct.filter((s) => s.probe && !s.probe.reachable).length,
        viaJumpHost: servers.length - direct.length,
        hostKeyChanged: servers.filter((s) => s.hostKey === 'changed').length,
        hostKeyUnverified: servers.filter((s) => s.hostKey === 'unverified').length,
        jumpHostsDown: jumpHosts.filter((j) => j.enabled && j.probe && !j.probe.reachable).length,
        noJumpHostAvailable: servers.some((s) => s.route.mode === 'auto') && !anyJump,
      },
      servers,
      jumpHosts,
    };
  }

  // What was last measured, with no network traffic. The page shows this straight away.
  app.get('/api/admin/health', async (req) => {
    requireAdmin(req);
    return snapshot();
  });

  // Measure now. Each distinct host and port is tried once however many servers share it.
  app.post('/api/admin/health/check', { config: { rateLimit: { max: 6, timeWindow: '1 minute' } } }, async (req) => {
    requireAdmin(req);
    const endpoints = new Map<string, { host: string; port: number }>();
    for (const r of db.prepare("SELECT host, port FROM servers WHERE jump_mode = 'none'").all() as { host: string; port: number }[]) endpoints.set(key(r.host, r.port), r);
    for (const r of db.prepare('SELECT host, port FROM jump_hosts').all() as { host: string; port: number }[]) endpoints.set(key(r.host, r.port), r);
    probes.clear();
    await pool([...endpoints.entries()], CONCURRENCY, async ([k, e]) => void probes.set(k, await probe(e.host, e.port)));
    if (!cert || Date.now() - cert.checkedAt > CERT_TTL_MS) cert = await checkCertificate(config.publicUrl);
    return snapshot();
  });
}
