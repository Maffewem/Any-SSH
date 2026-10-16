import { connect as tcpConnect, isIP, type Socket } from 'node:net';
import ssh2 from 'ssh2';
import type { ClientChannel } from 'ssh2';
import type { AppContext, JumpHostRow, ServerRow } from '../types.js';
import { jumpHostContext } from '../rotate.js';
import { sshFingerprint } from './fingerprint.js';
import { isBlockedAddress, resolveTarget } from './target.js';
import type { StoredPrivateKey } from '../routes/keys.js';

const { Client } = ssh2;

/** Latencies are re-measured at most this often when picking the closest jump host. */
const LATENCY_TTL_MS = 60_000;
const PROBE_TIMEOUT_MS = 3_000;

const latencyCache = new Map<string, { ms: number | null; at: number }>();

export class JumpError extends Error {
  constructor(
    message: string,
    readonly code: 'host_key_mismatch' | 'host_key_unverified' | 'unavailable' | 'failed',
    readonly presented?: string,
  ) {
    super(message);
  }
}

/** How long a TCP handshake to the jump host takes from this server, or null if it is unreachable. */
export function tcpLatency(address: string, port: number): Promise<number | null> {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint();
    let socket: Socket | null = tcpConnect({ host: address, port, timeout: PROBE_TIMEOUT_MS });
    const done = (ms: number | null) => {
      socket?.destroy();
      socket = null;
      resolve(ms);
    };
    socket.once('connect', () => done(Number(process.hrtime.bigint() - started) / 1e6));
    socket.once('timeout', () => done(null));
    socket.once('error', () => done(null));
  });
}

async function measure(ctx: AppContext, jh: JumpHostRow): Promise<number | null> {
  const hit = latencyCache.get(jh.id);
  if (hit && Date.now() - hit.at < LATENCY_TTL_MS) return hit.ms;
  let ms: number | null = null;
  try {
    ms = await tcpLatency(await resolveTarget(jh.host, ctx.config.allowLoopbackTargets), jh.port);
  } catch {
    ms = null;
  }
  latencyCache.set(jh.id, { ms, at: Date.now() });
  return ms;
}

export function forgetLatency(id: string): void {
  latencyCache.delete(id);
}

/**
 * The jump hosts to try for a server, best first; empty means connect directly.
 * 'fixed' is exactly the admin's choice and fails closed (no fallback to a direct connection or another jump host).
 * 'auto' means the enabled, host-key-verified jump hosts ordered by lowest TCP connect time from this
 * server, measured now (cached for a minute); unreachable ones are dropped and the connection
 * falls over to the next if one fails.
 */
export async function jumpCandidates(ctx: AppContext, server: ServerRow): Promise<JumpHostRow[]> {
  if (server.jump_mode === 'none') return [];
  const all = ctx.db.prepare('SELECT * FROM jump_hosts WHERE enabled = 1').all() as JumpHostRow[];
  if (server.jump_mode === 'fixed') {
    const chosen = all.find((j) => j.id === server.jump_host_id);
    if (!chosen) throw new JumpError('The jump host for this server was removed or turned off, so the server can’t be reached.', 'unavailable');
    return [chosen];
  }
  const usable = all.filter((j) => j.host_key_fingerprint);
  if (!usable.length) throw new JumpError('No jump host is available. Ask an administrator to add and verify one.', 'unavailable');
  const timed = await Promise.all(usable.map(async (j) => ({ j, ms: await measure(ctx, j) })));
  const reachable = timed.filter((t): t is { j: JumpHostRow; ms: number } => t.ms !== null).sort((a, b) => a.ms - b.ms);
  if (!reachable.length) throw new JumpError('No jump host is available right now.', 'unavailable');
  return reachable.map((t) => t.j);
}

function privateKeyOf(ctx: AppContext, jh: JumpHostRow): string {
  return (JSON.parse(ctx.box.openString(jh.private_key_enc, jumpHostContext(jh.id))) as StoredPrivateKey).privateKey;
}

/**
 * Logs in to the jump host with its own key and opens a TCP channel to the target. The caller
 * then runs a complete, separate SSH session to the target over that channel: the target's host
 * key check, authentication and every byte of the terminal are end to end, so the jump host
 * relays ciphertext and never sees the user's key, password or keystrokes.
 *
 * The jump host's host key must already be pinned; a changed key is refused.
 */
export async function openThroughJumpHost(
  ctx: AppContext,
  jh: JumpHostRow,
  target: { host: string; port: number },
): Promise<{ stream: ClientChannel; conn: InstanceType<typeof Client> }> {
  // Re-read the pin: an admin may have forgotten or changed it since the candidates were listed.
  const current = ctx.db.prepare('SELECT host_key_fingerprint, enabled FROM jump_hosts WHERE id = ?').get(jh.id) as
    | Pick<JumpHostRow, 'host_key_fingerprint' | 'enabled'>
    | undefined;
  if (!current || !current.enabled) throw new JumpError(`Jump host ${jh.name} is no longer available.`, 'unavailable');
  const pinned = current.host_key_fingerprint;
  if (!pinned) throw new JumpError(`The fingerprint of jump host ${jh.name} hasn’t been verified by an administrator yet.`, 'host_key_unverified');
  const address = await resolveTarget(jh.host, ctx.config.allowLoopbackTargets);
  // The target is looked up and dialled by the jump host, so a name need not resolve here. A literal
  // address is still held to the same SSRF rules as a direct connection.
  if (!ctx.config.allowLoopbackTargets && isIP(target.host) !== 0 && isBlockedAddress(target.host)) {
    throw new JumpError('That address can’t be reached through a jump host.', 'failed');
  }

  const conn = new Client();
  let mismatch: string | undefined;
  return new Promise((resolve, reject) => {
    const fail = (err: unknown) => {
      conn.end();
      if (mismatch) {
        return reject(
          new JumpError(`The fingerprint for jump host ${jh.name} has changed. Expected ${pinned} but it presented ${mismatch}. The connection was blocked.`, 'host_key_mismatch', mismatch),
        );
      }
      reject(err instanceof JumpError ? err : new JumpError(`Jump host ${jh.name}: ${err instanceof Error ? err.message : String(err)}`.slice(0, 300), 'failed'));
    };
    conn.once('error', fail);
    conn.once('ready', () => {
      conn.forwardOut('127.0.0.1', 0, target.host, target.port, (err, stream) => {
        if (err) return fail(err);
        conn.removeListener('error', fail);
        resolve({ stream, conn });
      });
    });
    conn.connect({
      host: address,
      port: jh.port,
      username: jh.username,
      privateKey: privateKeyOf(ctx, jh),
      readyTimeout: ctx.config.sshConnectTimeoutMs,
      keepaliveInterval: 15_000,
      keepaliveCountMax: 4,
      hostVerifier: (key: Buffer, verify: (ok: boolean) => void) => {
        const fp = sshFingerprint(key);
        if (fp === pinned) return verify(true);
        mismatch = fp;
        verify(false);
      },
    });
  });
}

export interface JumpTestResult {
  /** Fingerprint the jump host presented, if it got that far. */
  fingerprint: string | null;
  hostKey: 'unpinned' | 'match' | 'mismatch' | 'unknown';
  /** True once the key was accepted by the jump host (only attempted when the host key is pinned and matches). */
  authenticated: boolean;
  latencyMs: number | null;
  error?: string;
}

/**
 * Checks a jump host without using it. Unpinned or changed host keys stop the probe before
 * authentication, so the admin sees the fingerprint to confirm out of band; a matching key
 * goes on to prove the Any-SSH key is accepted.
 */
export async function testJumpHost(ctx: AppContext, jh: JumpHostRow): Promise<JumpTestResult> {
  const result: JumpTestResult = { fingerprint: null, hostKey: 'unknown', authenticated: false, latencyMs: null };
  let address: string;
  try {
    address = await resolveTarget(jh.host, ctx.config.allowLoopbackTargets);
  } catch (err) {
    return { ...result, error: err instanceof Error ? err.message : String(err) };
  }
  result.latencyMs = await tcpLatency(address, jh.port);
  latencyCache.set(jh.id, { ms: result.latencyMs, at: Date.now() });
  const conn = new Client();
  return new Promise((resolve) => {
    const finish = (extra: Partial<JumpTestResult> = {}) => {
      conn.end();
      resolve({ ...result, ...extra });
    };
    conn.once('ready', () => finish({ authenticated: true }));
    conn.once('error', (err) => {
      if (result.hostKey === 'unpinned' || result.hostKey === 'mismatch') return finish();
      finish({ error: /All configured authentication methods failed/i.test(err.message) ? 'The jump host rejected the Any-SSH key. Add the public key to its authorized_keys file.' : err.message.slice(0, 300) });
    });
    conn.connect({
      host: address,
      port: jh.port,
      username: jh.username,
      privateKey: privateKeyOf(ctx, jh),
      readyTimeout: ctx.config.sshConnectTimeoutMs,
      hostVerifier: (key: Buffer, verify: (ok: boolean) => void) => {
        result.fingerprint = sshFingerprint(key);
        if (!jh.host_key_fingerprint) {
          result.hostKey = 'unpinned';
          return verify(false);
        }
        result.hostKey = result.fingerprint === jh.host_key_fingerprint ? 'match' : 'mismatch';
        verify(result.hostKey === 'match');
      },
    });
  });
}
