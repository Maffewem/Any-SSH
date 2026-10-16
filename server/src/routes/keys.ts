import type { FastifyInstance } from 'fastify';
import { randomUUID } from 'node:crypto';
import ssh2 from 'ssh2';
import { z } from 'zod';
import { notify } from '../accountTokens.js';
import { recordReauthFailure } from '../bruteForce.js';
import { HttpError, badRequest, clientIp, idParam, notFound, parse, requireUser } from '../http.js';
import { verifyPassword } from '../passwords.js';
import { sshFingerprint } from '../ssh/fingerprint.js';
import type { AppContext, SshKeyRow } from '../types.js';

const { utils } = ssh2;

const keyName = z.string().trim().min(1).max(100);
const generateBody = z.object({
  name: keyName,
  type: z.enum(['ed25519', 'ecdsa', 'rsa']).default('ed25519'),
});
const importBody = z.object({
  name: keyName,
  privateKey: z.string().min(1).max(64 * 1024),
  passphrase: z.string().max(1024).optional(),
});

/** What we keep (sealed) for a private key. Never returned by the API. */
export interface StoredPrivateKey {
  privateKey: string;
  passphrase?: string;
}

export function generateKeyPair(type: 'ed25519' | 'ecdsa' | 'rsa'): Promise<{ private: string; public: string }> {
  // Async so a 4096-bit RSA generation does not stall every other connection.
  return new Promise((resolve, reject) => {
    const done = (err: Error | null, pair: { private: string; public: string }) => (err ? reject(err) : resolve(pair));
    if (type === 'rsa') utils.generateKeyPair('rsa', { bits: 4096 }, done);
    else if (type === 'ecdsa') utils.generateKeyPair('ecdsa', { bits: 256 }, done);
    else utils.generateKeyPair('ed25519', done);
  });
}

/** Rejects key types and sizes that are no longer considered safe. */
export function keyWeakness(type: string, publicBlob: Buffer): string | null {
  if (type === 'ssh-dss') return 'DSA keys are no longer secure. Use an Ed25519 key instead.';
  if (type === 'ssh-rsa') {
    // Public blob: string "ssh-rsa", mpint e, mpint n. Modulus size = length of n without its sign byte.
    let off = 0;
    const read = () => {
      const len = publicBlob.readUInt32BE(off);
      const v = publicBlob.subarray(off + 4, off + 4 + len);
      off += 4 + len;
      return v;
    };
    read();
    read();
    const n = read();
    const bits = (n[0] === 0 ? n.length - 1 : n.length) * 8;
    if (bits < 2048) return `This RSA key is only ${bits} bits. Use at least 2048 bits, or better, Ed25519.`;
  }
  return null;
}

export const keyContext = (keyId: string) => `ssh_key:${keyId}:private`;

/**
 * Reads a pasted private key and rejects public keys and weak key types.
 * Returns what can safely be shown or logged about it: never the key itself.
 */
export function inspectPrivateKey(privateKey: string, passphrase?: string): { type: string; publicBlob: Buffer; fingerprint: string } {
  const parsed = utils.parseKey(privateKey, passphrase);
  if (parsed instanceof Error) throw badRequest(`Could not read that private key: ${parsed.message}`);
  const key = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!key || !key.isPrivateKey()) throw badRequest('That’s a public key. Paste the private key instead.');
  const blob = key.getPublicSSH();
  const weakness = keyWeakness(key.type, blob);
  if (weakness) throw badRequest(weakness);
  return { type: key.type, publicBlob: blob, fingerprint: sshFingerprint(blob) };
}

/** Normalises a pasted key the same way for storage and for one-off use. */
export const normalisePrivateKey = (privateKey: string) => privateKey.trim() + '\n';

/** A filename like id_ed25519_work-servers, safe for any OS. */
export function exportFilename(name: string, keyType: string): string {
  const base = keyType.startsWith('ssh-') ? keyType.slice(4) : keyType.startsWith('ecdsa') ? 'ecdsa' : keyType;
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
  return `id_${base}${slug ? `_${slug}` : ''}`;
}

export function publicKeyView(k: SshKeyRow) {
  return { id: k.id, name: k.name, type: k.key_type, publicKey: k.public_key, fingerprint: k.fingerprint, createdAt: k.created_at, lastUsedAt: k.last_used_at };
}

export function registerKeyRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { db, box, audit } = ctx;

  function store(ownerId: string, name: string, secret: StoredPrivateKey): SshKeyRow {
    const key = inspectPrivateKey(secret.privateKey, secret.passphrase);
    const blob = key.publicBlob;
    const id = randomUUID();
    const row: SshKeyRow = {
      id,
      owner_id: ownerId,
      name,
      key_type: key.type,
      public_key: `${key.type} ${blob.toString('base64')} ${name.replace(/\s+/g, '-')}`,
      fingerprint: key.fingerprint,
      private_key_enc: box.seal(JSON.stringify(secret), keyContext(id)),
      created_at: Date.now(),
      last_used_at: null,
    };
    db.prepare(
      `INSERT INTO ssh_keys (id, owner_id, name, key_type, public_key, fingerprint, private_key_enc, created_at)
       VALUES (@id, @owner_id, @name, @key_type, @public_key, @fingerprint, @private_key_enc, @created_at)`,
    ).run(row);
    return row;
  }

  app.get('/api/keys', async (req) => {
    const { user } = requireUser(req);
    const rows = db.prepare('SELECT * FROM ssh_keys WHERE owner_id = ? ORDER BY name').all(user.id) as SshKeyRow[];
    return { keys: rows.map(publicKeyView) };
  });

  app.post('/api/keys/generate', async (req) => {
    const { user } = requireUser(req);
    const body = parse(generateBody, req.body);
    const pair = await generateKeyPair(body.type);
    const row = store(user.id, body.name, { privateKey: pair.private });
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'key.generate', targetType: 'ssh_key', targetId: row.id,
      ip: clientIp(req), details: { name: row.name, type: row.key_type, fingerprint: row.fingerprint },
    });
    return { key: publicKeyView(row) };
  });

  app.post('/api/keys/import', async (req) => {
    const { user } = requireUser(req);
    const body = parse(importBody, req.body);
    const row = store(user.id, body.name, {
      privateKey: normalisePrivateKey(body.privateKey),
      ...(body.passphrase ? { passphrase: body.passphrase } : {}),
    });
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'key.import', targetType: 'ssh_key', targetId: row.id,
      ip: clientIp(req), details: { name: row.name, type: row.key_type, fingerprint: row.fingerprint },
    });
    return { key: publicKeyView(row) };
  });

  app.patch('/api/keys/:id', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    const { name } = parse(z.object({ name: keyName }), req.body);
    const res = db.prepare('UPDATE ssh_keys SET name = ? WHERE id = ? AND owner_id = ?').run(name, id, user.id);
    if (!res.changes) throw notFound('Key not found');
    return { key: publicKeyView(db.prepare('SELECT * FROM ssh_keys WHERE id = ?').get(id) as SshKeyRow) };
  });

  // Hands the private key back to its owner as a file. Re-checks the account password, because a
  // hijacked session must not be enough to walk off with a key.
  app.post('/api/keys/:id/export', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    const { password } = parse(z.object({ password: z.string().min(1).max(1024) }), req.body);
    const key = db.prepare('SELECT * FROM ssh_keys WHERE id = ? AND owner_id = ?').get(id, user.id) as SshKeyRow | undefined;
    if (!key) throw notFound('Key not found');
    const auditBase = { actorId: user.id, actorUsername: user.username, action: 'key.export', targetType: 'ssh_key', targetId: id, ip: clientIp(req) };
    if (!(await verifyPassword(user.password_hash, password))) {
      recordReauthFailure(ctx, req.log, clientIp(req), user);
      audit.record({ ...auditBase, outcome: 'failure', details: { name: key.name, reason: 'bad_password' } });
      throw badRequest('The password isn’t correct.');
    }
    const stored = JSON.parse(box.openString(key.private_key_enc, keyContext(key.id))) as StoredPrivateKey;
    audit.record({ ...auditBase, details: { name: key.name, fingerprint: key.fingerprint } });
    notify(ctx, req.log, user, `the private key of your SSH key "${key.name}" (${key.fingerprint}) was exported`);
    return {
      filename: exportFilename(key.name, key.key_type),
      privateKey: stored.privateKey,
      // Imported keys are kept exactly as pasted, so a passphrase-protected key still needs that passphrase.
      passphraseProtected: !!stored.passphrase,
    };
  });

  app.delete('/api/keys/:id', async (req) => {
    const { user } = requireUser(req);
    const { id } = parse(idParam, req.params);
    const key = db.prepare('SELECT * FROM ssh_keys WHERE id = ? AND owner_id = ?').get(id, user.id) as SshKeyRow | undefined;
    if (!key) throw notFound('Key not found');
    const usedBy = db.prepare('SELECT name FROM servers WHERE key_id = ?').all(id) as { name: string }[];
    if (usedBy.length) {
      throw new HttpError(409, `This key is used by: ${usedBy.map((s) => s.name).join(', ')}. Change those servers first.`, 'conflict');
    }
    db.prepare('DELETE FROM ssh_keys WHERE id = ?').run(id);
    audit.record({
      actorId: user.id, actorUsername: user.username, action: 'key.delete', targetType: 'ssh_key', targetId: id,
      ip: clientIp(req), details: { name: key.name, fingerprint: key.fingerprint },
    });
    return { ok: true };
  });
}
