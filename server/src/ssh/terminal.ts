import type { FastifyInstance, FastifyRequest } from 'fastify';
import { StringDecoder } from 'node:string_decoder';
import ssh2 from 'ssh2';
import type { ClientChannel, ConnectConfig } from 'ssh2';
import type { WebSocket } from 'ws';
import { z } from 'zod';
import { clientIp } from '../http.js';
import { emails } from '../mail.js';
import { keyContext, type StoredPrivateKey } from '../routes/keys.js';
import { getServerAccess, serverPasswordContext } from '../routes/servers.js';
import { randomToken } from '../crypto.js';
import type { AppContext, JumpHostRow, ServerAccess, ServerRow, SessionRow, SshKeyRow, UserRow } from '../types.js';
import { sshFingerprint } from './fingerprint.js';
import { JumpError, jumpCandidates, openThroughJumpHost } from './jump.js';
import type { ConnectCredential, LiveTerminal, TerminalTicket } from './registry.js';
import { resolveTarget } from './target.js';

const { Client, utils } = ssh2;

const clientMessage = z.discriminatedUnion('type', [
  z.object({ type: z.literal('input'), data: z.string().max(64 * 1024) }),
  z.object({ type: z.literal('resize'), cols: z.number().int().min(1).max(1000), rows: z.number().int().min(1).max(500) }),
  z.object({ type: z.literal('hostkey'), accept: z.boolean() }),
  z.object({ type: z.literal('password'), password: z.string().max(1024) }),
]);
type ClientMessage = z.infer<typeof clientMessage>;

const PROMPT_TIMEOUT_MS = 120_000;
const SESSION_CHECK_MS = 30_000;
const HIGH_WATER = 1024 * 1024;
/** Output kept for a re-attaching browser. Older output is dropped first. */
const REPLAY_LIMIT = 512 * 1024;

export function registerTerminalRoute(app: FastifyInstance, ctx: AppContext): void {
  app.get('/api/terminal', { websocket: true }, (socket: WebSocket, req: FastifyRequest) => {
    void runTerminal(ctx, socket, req);
  });
}

async function runTerminal(ctx: AppContext, ws: WebSocket, req: FastifyRequest): Promise<void> {
  const { terminals, config } = ctx;
  const fail = (code: string, message: string) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ type: 'error', code, message }));
    ws.close(4000, code);
  };

  // 1. Who is this? Browser origin, logged-in session and a fresh single-use ticket must all agree.
  const auth = req.auth;
  const { ticket: token, cols, rows } = z
    .object({
      ticket: z.string().max(100).default(''),
      cols: z.coerce.number().int().min(1).max(1000).default(80),
      rows: z.coerce.number().int().min(1).max(500).default(24),
    })
    .parse(req.query);
  // Redeem first so a ticket is burned by any attempt, including a rejected one.
  const ticket = terminals.redeemTicket(token);
  const origin = req.headers.origin;
  if (!origin || !config.allowedOrigins.includes(origin)) return fail('bad_origin', 'The request was blocked: it came from an unrecognised origin.');
  if (!auth || auth.session.stage !== 'full' || auth.session.ip_challenge === 1 || !ticket || ticket.sessionIdHash !== auth.session.id_hash) {
    return fail('unauthorized', 'Not authorised. Reload and try again.');
  }
  if (auth.session.locked_at !== null) return fail('session_locked', 'This session is locked. Unlock it and try again.');
  const user = auth.user;
  const ip = clientIp(req);

  // Re-attach to a terminal that outlived its browser connection.
  if (ticket.resume) {
    const live = terminals.resumable(user.id, ticket.resume);
    if (!live || live.serverId !== ticket.serverId || !getServerAccess(ctx, user.id, live.serverId)) {
      return fail('session_gone', 'That terminal is no longer running.');
    }
    (live as LiveSession).attach(ws, cols, rows, auth.session, ip);
    return;
  }

  const found = getServerAccess(ctx, user.id, ticket.serverId);
  if (!found) return fail('not_found', 'Server not found');
  // Re-checked here: the owner may have withdrawn use of their credentials since the ticket was issued.
  if (ticket.credential.type === 'saved' && found.credentials === 'own') {
    return fail('own_credentials_required', 'The owner asked you to connect with your own credentials.');
  }
  const session = new LiveSession(ctx, user, auth.session, found.server, found.access, ticket, ip);
  session.attach(ws, cols, rows, auth.session, ip);
  void session.start(cols, rows);
}

/**
 * One SSH terminal. It outlives the browser connection that opened it: when that drops, the SSH
 * session (and any jump host channel under it) is kept for `detachMinutes`, output is buffered, and a
 * browser holding the session id can attach again with a fresh single-use ticket. The web session
 * still governs it: logout, expiry, revocation, an idle lock and removed access all end or pause it
 * exactly as they do an attached terminal.
 */
class LiveSession implements LiveTerminal {
  readonly id = randomToken(32);
  readonly userId: string;
  readonly serverId: string;
  sessionIdHash: string;
  jumpHostId: string | null = null;

  private ws: WebSocket | null = null;
  private shell: ClientChannel | null = null;
  private readonly conn = new Client();
  private jumpConn: InstanceType<typeof Client> | null = null;
  private readonly waiters = new Map<string, (m: ClientMessage) => void>();
  private chunks: string[] = [];
  private chunkChars = 0;
  private locked = false;
  private backpressured = false;
  private closed = false;
  private ready = false;
  private connected = false;
  private hostKeyRejected = false;
  private lastTouch = Date.now();
  private readonly startedAt = Date.now();
  private bytesOut = 0;
  private detachTimer: NodeJS.Timeout | null = null;
  private readonly sessionCheck: NodeJS.Timeout;
  private readonly unregister: () => void;
  private auditBase: { actorId: string; actorUsername: string; targetType: string; targetId: string; ip: string | undefined };

  constructor(
    private readonly ctx: AppContext,
    private readonly user: UserRow,
    private webSession: SessionRow,
    private readonly server: ServerRow,
    private readonly access: ServerAccess,
    private readonly ticket: TerminalTicket,
    ip: string | undefined,
  ) {
    this.userId = user.id;
    this.serverId = server.id;
    this.sessionIdHash = webSession.id_hash;
    this.auditBase = { actorId: user.id, actorUsername: user.username, targetType: 'server', targetId: server.id, ip };
    this.unregister = ctx.terminals.add(this);
    this.sessionCheck = setInterval(() => {
      const state = ctx.sessions.state(this.sessionIdHash);
      if (state === 'dead') this.close('Your session expired. Sign in again.');
      else this.setLocked(state === 'locked');
    }, SESSION_CHECK_MS);
  }

  get detached(): boolean {
    return this.ws === null && this.ready && !this.closed;
  }

  private send(msg: Record<string, unknown>): void {
    if (this.ws && this.ws.readyState === this.ws.OPEN) this.ws.send(JSON.stringify(msg));
  }

  /** Connects a browser: the first one when the session starts, or a later one after a drop. */
  attach(ws: WebSocket, cols: number, rows: number, webSession: SessionRow, ip: string | undefined): void {
    const resumed = this.ready;
    const previous = this.ws;
    this.ws = ws;
    this.webSession = webSession;
    this.sessionIdHash = webSession.id_hash;
    this.auditBase = { ...this.auditBase, ip };
    if (this.detachTimer) clearTimeout(this.detachTimer);
    this.detachTimer = null;
    // A takeover (another tab or device) replaces the earlier connection rather than sharing it.
    if (previous && previous !== ws) previous.close(4001, 'taken over');

    ws.on('message', (raw, isBinary) => {
      if (this.ws === ws && !isBinary) this.onMessage(raw.toString());
    });
    ws.on('close', () => this.ws === ws && this.detach('Browser disconnected'));
    ws.on('error', () => this.ws === ws && this.detach('Browser connection error'));

    if (!resumed) return;
    this.shell?.setWindow(rows, cols, 0, 0);
    this.send({ type: 'status', message: 'Reconnected' });
    this.send({ type: 'replay', data: this.chunks.join(''), session: this.id });
    this.send({ type: 'ready', session: this.id });
    if (this.locked) this.send({ type: 'locked' });
    if (!this.locked && !this.backpressured) this.shell?.resume();
    this.ctx.audit.record({ ...this.auditBase, action: 'ssh.session_resume', details: { detachedMs: Date.now() - this.detachedAt } });
  }

  private detachedAt = 0;

  /** The browser went away. Keep the SSH session for a while if it is up, otherwise end it. */
  private detach(reason: string): void {
    if (this.closed) return;
    this.ws = null;
    const minutes = this.ctx.settings.limits.detachMinutes;
    if (!this.ready || minutes <= 0) return this.close(reason);
    this.detachedAt = Date.now();
    this.backpressured = false;
    this.ctx.audit.record({ ...this.auditBase, action: 'ssh.session_detach', details: { reason, keptMinutes: minutes } });
    if (!this.locked) this.shell?.resume();
    this.detachTimer = setTimeout(() => this.close('Disconnected too long; the terminal was closed.'), minutes * 60_000);
    this.detachTimer.unref();
  }

  notify(message: string): void {
    this.send({ type: 'status', message });
  }

  setLocked(value: boolean): void {
    if (value === this.locked || this.closed) return;
    this.locked = value;
    if (value) this.shell?.pause();
    else if (!this.backpressured) this.shell?.resume();
    this.send({ type: value ? 'locked' : 'unlocked' });
  }

  private onMessage(raw: string): void {
    let msg: ClientMessage;
    try {
      msg = clientMessage.parse(JSON.parse(raw));
    } catch {
      return;
    }
    // While locked nothing from the browser reaches SSH.
    if (this.locked && msg.type !== 'resize') return;
    if (msg.type === 'input') {
      this.shell?.write(msg.data);
      if (Date.now() - this.lastTouch > 60_000) {
        this.lastTouch = Date.now();
        this.ctx.sessions.touch(this.webSession);
      }
    } else if (msg.type === 'resize') {
      this.shell?.setWindow(msg.rows, msg.cols, 0, 0);
    } else {
      const w = this.waiters.get(msg.type);
      this.waiters.delete(msg.type);
      w?.(msg);
    }
  }

  private ask<T extends ClientMessage['type']>(type: T, prompt: Record<string, unknown>) {
    return new Promise<Extract<ClientMessage, { type: T }> | null>((resolve) => {
      const timer = setTimeout(() => {
        this.waiters.delete(type);
        resolve(null);
      }, PROMPT_TIMEOUT_MS);
      this.waiters.set(type, (m) => {
        clearTimeout(timer);
        resolve(m as Extract<ClientMessage, { type: T }>);
      });
      this.send(prompt);
    });
  }

  close(reason: string): void {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this.sessionCheck);
    if (this.detachTimer) clearTimeout(this.detachTimer);
    this.unregister();
    this.send({ type: 'exit', reason });
    this.conn.end();
    this.jumpConn?.end();
    this.ws?.close(1000, 'closed');
    this.chunks = [];
    if (this.connected) {
      this.ctx.audit.record({ ...this.auditBase, action: 'ssh.session_end', details: { reason, durationMs: Date.now() - this.startedAt, bytesOut: this.bytesOut } });
    }
  }

  private closeWithError(err: unknown): void {
    const message = err instanceof Error ? err.message : String(err);
    if (!this.hostKeyRejected) this.send({ type: 'error', code: err instanceof JumpError ? `jump_${err.code}` : 'ssh_error', message: friendlyError(message) });
    this.close('Connection failed');
  }

  private remember(data: string): void {
    this.chunks.push(data);
    this.chunkChars += data.length;
    while (this.chunkChars > REPLAY_LIMIT && this.chunks.length > 1) this.chunkChars -= this.chunks.shift()!.length;
  }

  async start(cols: number, rows: number): Promise<void> {
    const { ctx, server, access, ticket } = this;
    const { db, audit, config } = ctx;
    const { credential, username } = ticket;

    // Credentials are decrypted only here, in memory, for the duration of the handshake.
    let creds: Creds;
    // Which key was used is recorded with the session, so every use of a key is attributable.
    let credentialFingerprint: string | null = null;
    let usedKeyId: string | null = null;
    try {
      ({ creds, fingerprint: credentialFingerprint, keyId: usedKeyId } = await loadCredentials(ctx, server, this.userId, credential, username, (prompt) =>
        this.ask('password', prompt),
      ));
    } catch (err) {
      return this.closeWithError(err);
    }
    if (this.closed) return;

    // Either dial the target directly, or open a channel to it through a jump host. Through a jump
    // host the target's own SSH session still runs end to end over that channel.
    let sock: ClientChannel | undefined;
    let address: string | undefined;
    let jump: JumpHostRow | null = null;
    try {
      if (server.jump_mode === 'none') {
        address = await resolveTarget(server.host, config.allowLoopbackTargets);
      } else {
        let lastError: unknown = null;
        for (const candidate of await jumpCandidates(ctx, server)) {
          this.send({ type: 'status', message: `Connecting through ${candidate.name}…` });
          try {
            const opened = await openThroughJumpHost(ctx, candidate, { host: server.host, port: server.port });
            ({ stream: sock, conn: this.jumpConn } = opened);
            jump = candidate;
            break;
          } catch (err) {
            lastError = err;
            audit.record({
              ...this.auditBase,
              action: err instanceof JumpError && err.code === 'host_key_mismatch' ? 'ssh.jump_host_key_mismatch' : 'ssh.jump_connect',
              outcome: 'failure',
              details: { jumpHost: candidate.name, mode: server.jump_mode, reason: (err instanceof Error ? err.message : String(err)).slice(0, 200) },
            });
            if (this.closed) return;
          }
        }
        if (!sock) throw lastError ?? new JumpError('No jump host could be used.', 'unavailable');
        this.jumpHostId = jump!.id;
        this.jumpConn!.on('error', (err) => this.closeWithError(err));
        this.jumpConn!.on('close', () => this.close('Jump host connection closed'));
      }
    } catch (err) {
      audit.record({ ...this.auditBase, action: 'ssh.connect', outcome: 'failure', details: { reason: err instanceof JumpError ? err.code : 'target_blocked_or_unresolved' } });
      return this.closeWithError(err);
    }
    if (this.closed) return;

    // Host key verification: pinned fingerprint must match; unknown keys need explicit trust.
    const hostVerifier = (key: Buffer, verify: (ok: boolean) => void) => {
      const fingerprint = sshFingerprint(key);
      const parsed = utils.parseKey(key);
      const keyType = parsed instanceof Error ? 'unknown' : (Array.isArray(parsed) ? parsed[0]?.type : parsed.type) ?? 'unknown';
      // Re-read: the owner may have pinned, accepted or forgotten a key since the ticket was issued.
      const current = db
        .prepare('SELECT host_key_fingerprint, host_key_type, host_key_pending FROM servers WHERE id = ?')
        .get(server.id) as Pick<ServerRow, 'host_key_fingerprint' | 'host_key_type' | 'host_key_pending'> | undefined;
      const pinned = current?.host_key_fingerprint ?? null;
      if (pinned) {
        if (pinned === fingerprint) return verify(true);
        // Refused, always. The new key is parked for the owner to review; they are emailed the first
        // time each different key shows up, not on every retry.
        const firstSighting = current?.host_key_pending !== fingerprint;
        if (firstSighting) {
          db.prepare('UPDATE servers SET host_key_pending = ?, host_key_pending_type = ?, host_key_pending_at = ? WHERE id = ?').run(
            fingerprint, keyType, Date.now(), server.id,
          );
          const owner = db.prepare('SELECT email, display_name FROM users WHERE id = ?').get(server.owner_id) as
            | { email: string | null; display_name: string }
            | undefined;
          if (owner?.email) {
            ctx.mailer
              .send(
                emails.hostKeyChanged({
                  to: owner.email, displayName: owner.display_name, server: server.name, endpoint: `${server.host}:${server.port}`,
                  attemptedBy: this.user.username, expected: pinned, presented: fingerprint, presentedType: keyType,
                }),
              )
              .catch(() => {});
          }
        }
        audit.record({
          ...this.auditBase, action: 'ssh.host_key_mismatch', outcome: 'failure',
          details: { host: server.host, port: server.port, expected: pinned, presented: fingerprint, keyType, ownerNotified: firstSighting },
        });
        this.send({
          type: 'hostkey_changed',
          host: server.host,
          port: server.port,
          expected: pinned,
          expectedType: current?.host_key_type ?? null,
          presented: fingerprint,
          presentedType: keyType,
          isOwner: access === 'owner',
        });
        this.send({
          type: 'error',
          code: 'host_key_mismatch',
          message: `HOST KEY CHANGED for ${server.host}. Expected ${pinned} but the server presented ${fingerprint}. This could be an attack. Connection refused.`,
        });
        this.hostKeyRejected = true;
        return verify(false);
      }
      if (access === 'use') {
        this.send({ type: 'error', code: 'host_key_unverified', message: 'The owner has not verified this server’s host key yet. Ask them to connect once first.' });
        this.hostKeyRejected = true;
        return verify(false);
      }
      void this.ask('hostkey', { type: 'hostkey', fingerprint, keyType, host: server.host, port: server.port }).then((reply) => {
        if (!reply?.accept) {
          this.hostKeyRejected = true;
          this.send({ type: 'error', code: 'host_key_rejected', message: 'Host key not trusted. Connection cancelled.' });
          return verify(false);
        }
        const now = Date.now();
        db.prepare(
          `UPDATE servers SET host_key_fingerprint = ?, host_key_type = ?, host_key_pinned_at = ?, host_key_pinned_by = ?,
             host_key_pending = NULL, host_key_pending_type = NULL, host_key_pending_at = NULL, updated_at = ?
           WHERE id = ? AND host_key_fingerprint IS NULL`,
        ).run(fingerprint, keyType, now, this.user.username, now, server.id);
        audit.record({ ...this.auditBase, action: 'ssh.host_key_trust', details: { host: server.host, port: server.port, fingerprint, keyType } });
        verify(true);
      });
    };

    // Connect and open an interactive shell.
    const { conn } = this;
    conn.on('ready', () => {
      this.connected = true;
      if (usedKeyId) db.prepare('UPDATE ssh_keys SET last_used_at = ? WHERE id = ?').run(Date.now(), usedKeyId);
      audit.record({
        ...this.auditBase,
        action: 'ssh.session_start',
        details: {
          host: server.host, port: server.port, username, access,
          credentials: credentialSource(credential, server), keyFingerprint: credentialFingerprint,
          ...(jump ? { jumpHost: jump.name, jumpMode: server.jump_mode } : {}),
        },
      });
      this.send({ type: 'status', message: 'Connected' });
      conn.shell({ term: 'xterm-256color', cols, rows }, (err, stream) => {
        if (err) return this.closeWithError(err);
        this.shell = stream;
        this.ready = true;
        if (this.locked) stream.pause();
        this.send({ type: 'ready', session: this.id });
        const decoder = new StringDecoder('utf8');
        const forward = (chunk: Buffer) => {
          this.bytesOut += chunk.length;
          const data = decoder.write(chunk);
          if (!data) return;
          this.remember(data);
          this.send({ type: 'data', data });
          // Simple backpressure: stop reading from SSH while an attached browser is behind.
          const ws = this.ws;
          if (ws && ws.bufferedAmount > HIGH_WATER && !this.backpressured) {
            this.backpressured = true;
            stream.pause();
            const wait = setInterval(() => {
              if (this.ws !== ws || ws.bufferedAmount < HIGH_WATER / 4 || this.closed) {
                clearInterval(wait);
                this.backpressured = false;
                if (!this.locked && !this.closed) stream.resume();
              }
            }, 50);
          }
        };
        stream.on('data', forward);
        stream.stderr.on('data', forward);
        stream.on('close', () => this.close('Session ended'));
      });
    });
    conn.on('error', (err) => {
      if (!this.connected) {
        audit.record({ ...this.auditBase, action: 'ssh.connect', outcome: 'failure', details: { reason: err.message.slice(0, 200) } });
      }
      this.closeWithError(err);
    });
    conn.on('close', () => this.close('Connection closed'));

    this.send({ type: 'status', message: `Connecting to ${server.host}:${server.port}…` });
    conn.connect({
      ...(address ? { host: address, port: server.port } : { sock: sock! }),
      username,
      readyTimeout: config.sshConnectTimeoutMs,
      keepaliveInterval: 15_000,
      keepaliveCountMax: 4,
      hostVerifier,
      ...creds,
    });
  }
}

type Creds = Pick<ConnectConfig, 'privateKey' | 'passphrase' | 'password'>;

/** How the session authenticated, for the audit log. */
function credentialSource(credential: ConnectCredential, server: ServerRow): string {
  if (credential.type === 'saved') return server.auth_method === 'prompt' ? 'password_prompt' : `owner_${server.auth_method}`;
  if (credential.type === 'key') return 'own_key';
  if (credential.type === 'oneoff') return 'one_off_key';
  return 'password_prompt';
}

async function loadCredentials(
  ctx: AppContext,
  server: ServerRow,
  userId: string,
  credential: ConnectCredential,
  username: string,
  askPassword: (prompt: Record<string, unknown>) => Promise<{ password: string } | null>,
): Promise<{ creds: Creds; fingerprint: string | null; keyId: string | null }> {
  const fromStoredKey = (keyId: string | null, ownerId: string) => {
    const key = ctx.db.prepare('SELECT * FROM ssh_keys WHERE id = ? AND owner_id = ?').get(keyId, ownerId) as SshKeyRow | undefined;
    if (!key) throw new Error('That SSH key no longer exists.');
    const stored = JSON.parse(ctx.box.openString(key.private_key_enc, keyContext(key.id))) as StoredPrivateKey;
    return {
      creds: { privateKey: stored.privateKey, ...(stored.passphrase ? { passphrase: stored.passphrase } : {}) },
      fingerprint: key.fingerprint,
      keyId: key.id,
    };
  };
  const prompt = async () => {
    const reply = await askPassword({ type: 'password', username, host: server.host });
    if (!reply) throw new Error('No password entered.');
    return { creds: { password: reply.password }, fingerprint: null, keyId: null };
  };

  switch (credential.type) {
    case 'key':
      // The connecting user's own key, never anyone else's.
      return fromStoredKey(credential.keyId, userId);
    case 'oneoff':
      return {
        creds: { privateKey: credential.privateKey, ...(credential.passphrase ? { passphrase: credential.passphrase } : {}) },
        fingerprint: credential.fingerprint,
        keyId: null,
      };
    case 'password':
      return prompt();
    case 'saved':
      if (server.auth_method === 'key') return fromStoredKey(server.key_id, server.owner_id);
      if (server.auth_method === 'password') {
        if (!server.password_enc) throw new Error('No password is stored for this server.');
        return { creds: { password: ctx.box.openString(server.password_enc, serverPasswordContext(server.id)) }, fingerprint: null, keyId: null };
      }
      return prompt();
  }
}

function friendlyError(message: string): string {
  if (/All configured authentication methods failed/i.test(message)) return 'Authentication failed. Check the username and credentials.';
  if (/Timed out while waiting for handshake/i.test(message)) return 'Timed out connecting to the server.';
  if (/ECONNREFUSED/.test(message)) return 'Connection refused by the server.';
  if (/EHOSTUNREACH|ENETUNREACH/.test(message)) return 'Server is unreachable from Any-SSH.';
  if (/ENOTFOUND|EAI_AGAIN/.test(message)) return 'Could not resolve that hostname.';
  return message.slice(0, 300);
}
