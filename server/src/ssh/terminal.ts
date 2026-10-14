import type { FastifyInstance, FastifyRequest } from 'fastify';
import { StringDecoder } from 'node:string_decoder';
import ssh2 from 'ssh2';
import type { ClientChannel, ConnectConfig } from 'ssh2';
import type { WebSocket } from 'ws';
import { z } from 'zod';
import { clientIp } from '../http.js';
import { keyContext, type StoredPrivateKey } from '../routes/keys.js';
import { getServerAccess, serverPasswordContext } from '../routes/servers.js';
import type { AppContext, ServerRow, SshKeyRow } from '../types.js';
import { sshFingerprint } from './fingerprint.js';
import type { ConnectCredential } from './registry.js';
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

export function registerTerminalRoute(app: FastifyInstance, ctx: AppContext): void {
  app.get('/api/terminal', { websocket: true }, (socket: WebSocket, req: FastifyRequest) => {
    void runTerminal(ctx, socket, req);
  });
}

async function runTerminal(ctx: AppContext, ws: WebSocket, req: FastifyRequest): Promise<void> {
  const { db, box, audit, sessions, terminals, config } = ctx;
  const send = (msg: Record<string, unknown>) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(msg));
  };
  const fail = (code: string, message: string) => {
    send({ type: 'error', code, message });
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
  if (!origin || !config.allowedOrigins.includes(origin)) return fail('bad_origin', 'Origin not allowed');
  if (!auth || auth.session.stage !== 'full' || auth.session.ip_challenge === 1 || !ticket || ticket.sessionIdHash !== auth.session.id_hash) {
    return fail('unauthorized', 'Not authorised. Reload and try again.');
  }
  const user = auth.user;
  const found = getServerAccess(ctx, user.id, ticket.serverId);
  if (!found) return fail('not_found', 'Server not found');
  const { server, access } = found;
  // Re-checked here: the owner may have withdrawn use of their credentials since the ticket was issued.
  if (ticket.credential.type === 'saved' && found.credentials === 'own') {
    return fail('own_credentials_required', 'The owner asked you to connect with your own credentials.');
  }
  const { credential, username } = ticket;
  const ip = clientIp(req);
  const auditBase = { actorId: user.id, actorUsername: user.username, targetType: 'server', targetId: server.id, ip };

  // 2. Wire up client messages. Prompts (host key, password) wait on the next matching reply.
  let shell: ClientChannel | null = null;
  const waiters = new Map<string, (m: ClientMessage) => void>();
  let lastTouch = Date.now();
  ws.on('message', (raw, isBinary) => {
    if (isBinary) return;
    let msg: ClientMessage;
    try {
      msg = clientMessage.parse(JSON.parse(raw.toString()));
    } catch {
      return;
    }
    if (msg.type === 'input') {
      shell?.write(msg.data);
      if (Date.now() - lastTouch > 60_000) {
        lastTouch = Date.now();
        sessions.touch(auth.session);
      }
    } else if (msg.type === 'resize') {
      shell?.setWindow(msg.rows, msg.cols, 0, 0);
    } else {
      const w = waiters.get(msg.type);
      waiters.delete(msg.type);
      w?.(msg);
    }
  });
  const ask = <T extends ClientMessage['type']>(type: T, prompt: Record<string, unknown>) =>
    new Promise<Extract<ClientMessage, { type: T }> | null>((resolve) => {
      const timer = setTimeout(() => {
        waiters.delete(type);
        resolve(null);
      }, PROMPT_TIMEOUT_MS);
      waiters.set(type, (m) => {
        clearTimeout(timer);
        resolve(m as Extract<ClientMessage, { type: T }>);
      });
      send(prompt);
    });

  const conn = new Client();
  let closed = false;
  const startedAt = Date.now();
  let bytesOut = 0;
  let connected = false;
  const close = (reason: string) => {
    if (closed) return;
    closed = true;
    clearInterval(sessionCheck);
    unregister();
    send({ type: 'exit', reason });
    conn.end();
    ws.close(1000, 'closed');
    if (connected) {
      audit.record({ ...auditBase, action: 'ssh.session_end', details: { reason, durationMs: Date.now() - startedAt, bytesOut } });
    }
  };
  const unregister = terminals.add({ userId: user.id, serverId: server.id, sessionIdHash: auth.session.id_hash, close });
  const sessionCheck = setInterval(() => {
    if (!sessions.isAlive(auth.session.id_hash)) close('Your session expired. Sign in again.');
  }, SESSION_CHECK_MS);
  ws.on('close', () => close('Browser disconnected'));
  ws.on('error', () => close('Browser connection error'));

  // 3. Credentials. They are decrypted only here, in memory, for the duration of the handshake.
  let creds: Pick<ConnectConfig, 'privateKey' | 'passphrase' | 'password'>;
  // Which key was used is recorded with the session, so every use of a key is attributable.
  let credentialFingerprint: string | null = null;
  let usedKeyId: string | null = null;
  try {
    ({ creds, fingerprint: credentialFingerprint, keyId: usedKeyId } = await loadCredentials(ctx, server, user.id, credential, username, (prompt) =>
      ask('password', prompt),
    ));
  } catch (err) {
    return closeWithError(err);
  }
  if (closed) return;

  let address: string;
  try {
    address = await resolveTarget(server.host, config.allowLoopbackTargets);
  } catch (err) {
    audit.record({ ...auditBase, action: 'ssh.connect', outcome: 'failure', details: { reason: 'target_blocked_or_unresolved' } });
    return closeWithError(err);
  }
  if (closed) return;

  // 4. Host key verification: pinned fingerprint must match; unknown keys need explicit trust.
  let hostKeyRejected = false;
  const hostVerifier = (key: Buffer, verify: (ok: boolean) => void) => {
    const fingerprint = sshFingerprint(key);
    const parsed = utils.parseKey(key);
    const keyType = parsed instanceof Error ? 'unknown' : (Array.isArray(parsed) ? parsed[0]?.type : parsed.type) ?? 'unknown';
    // Re-read: the owner may have pinned or forgotten the key since the ticket was issued.
    const current = db.prepare('SELECT host_key_fingerprint FROM servers WHERE id = ?').get(server.id) as
      | Pick<ServerRow, 'host_key_fingerprint'>
      | undefined;
    const pinned = current?.host_key_fingerprint ?? null;
    if (pinned) {
      if (pinned === fingerprint) return verify(true);
      audit.record({ ...auditBase, action: 'ssh.host_key_mismatch', outcome: 'failure', details: { expected: pinned, presented: fingerprint } });
      send({
        type: 'error',
        code: 'host_key_mismatch',
        message: `HOST KEY CHANGED for ${server.host}. Expected ${pinned} but the server presented ${fingerprint}. This could be an attack. Connection refused.`,
      });
      hostKeyRejected = true;
      return verify(false);
    }
    if (access === 'use') {
      send({ type: 'error', code: 'host_key_unverified', message: 'The owner has not verified this server’s host key yet. Ask them to connect once first.' });
      hostKeyRejected = true;
      return verify(false);
    }
    void ask('hostkey', { type: 'hostkey', fingerprint, keyType, host: server.host, port: server.port }).then((reply) => {
      if (!reply?.accept) {
        hostKeyRejected = true;
        send({ type: 'error', code: 'host_key_rejected', message: 'Host key not trusted. Connection cancelled.' });
        return verify(false);
      }
      db.prepare('UPDATE servers SET host_key_fingerprint = ?, updated_at = ? WHERE id = ? AND host_key_fingerprint IS NULL').run(
        fingerprint,
        Date.now(),
        server.id,
      );
      audit.record({ ...auditBase, action: 'ssh.host_key_trust', details: { fingerprint, keyType } });
      verify(true);
    });
  };

  // 5. Connect and open an interactive shell.
  conn.on('ready', () => {
    connected = true;
    if (usedKeyId) db.prepare('UPDATE ssh_keys SET last_used_at = ? WHERE id = ?').run(Date.now(), usedKeyId);
    audit.record({
      ...auditBase,
      action: 'ssh.session_start',
      details: {
        host: server.host, port: server.port, username, access,
        credentials: credentialSource(credential, server), keyFingerprint: credentialFingerprint,
      },
    });
    send({ type: 'status', message: 'Connected' });
    conn.shell({ term: 'xterm-256color', cols, rows }, (err, stream) => {
      if (err) return closeWithError(err);
      shell = stream;
      send({ type: 'ready' });
      const decoder = new StringDecoder('utf8');
      const forward = (chunk: Buffer) => {
        bytesOut += chunk.length;
        const data = decoder.write(chunk);
        if (data) send({ type: 'data', data });
        // Simple backpressure: stop reading from SSH while the browser is behind.
        if (ws.bufferedAmount > HIGH_WATER) {
          stream.pause();
          const wait = setInterval(() => {
            if (ws.bufferedAmount < HIGH_WATER / 4 || closed) {
              clearInterval(wait);
              stream.resume();
            }
          }, 50);
        }
      };
      stream.on('data', forward);
      stream.stderr.on('data', forward);
      stream.on('close', () => close('Session ended'));
    });
  });
  conn.on('error', (err) => {
    if (!connected) {
      audit.record({ ...auditBase, action: 'ssh.connect', outcome: 'failure', details: { reason: err.message.slice(0, 200) } });
    }
    closeWithError(err);
  });
  conn.on('close', () => close('Connection closed'));

  send({ type: 'status', message: `Connecting to ${server.host}:${server.port}…` });
  conn.connect({
    host: address,
    port: server.port,
    username,
    readyTimeout: config.sshConnectTimeoutMs,
    keepaliveInterval: 15_000,
    keepaliveCountMax: 4,
    hostVerifier,
    ...creds,
  });

  function closeWithError(err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (!hostKeyRejected) send({ type: 'error', code: 'ssh_error', message: friendlyError(message) });
    close('Connection failed');
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
