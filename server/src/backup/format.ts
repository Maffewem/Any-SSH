import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, type KeyObject } from 'node:crypto';
import { open, rm, type FileHandle } from 'node:fs/promises';

/**
 * Encrypted backup files (.anybak).
 *
 * Backups are encrypted to a *recovery public key*, in the style of age: the server only ever holds the public half,
 * so a stolen server (or a stolen backup bucket) cannot decrypt old backups. The matching secret key is shown once
 * when generated and belongs in a password manager, apart from the master key.
 *
 *   header  = "ANYBAK1\n" | key id (8 bytes) | ephemeral X25519 public key (32 bytes)
 *   frames  = flag (1 byte, 1 = last) | ciphertext length (u32 BE) | AES-256-GCM ciphertext | tag (16 bytes)
 *
 * A fresh ephemeral key per file gives a fresh AES key (X25519 → HKDF-SHA256). Each frame uses a counter nonce with the
 * "last" flag folded in, and the header as AAD, so frames cannot be reordered, dropped, truncated or moved to another file.
 *
 * With system-managed encryption the same format is used, but the key pair is derived from the master key
 * (serverBackupKeyPair), so restoring needs only the master key. Unencrypted backups are the plain SQLite file.
 */

const MAGIC = Buffer.from('ANYBAK1\n', 'latin1');
const HEADER_LENGTH = MAGIC.length + 8 + 32;
const CHUNK = 1024 * 1024;
const TAG_LENGTH = 16;
const PUBLIC_PREFIX = 'anybak-pub-1-';
const SECRET_PREFIX = 'anybak-secret-1-';
const PKCS8_X25519_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SQLITE_MAGIC = Buffer.from('SQLite format 3\0', 'latin1');

/** How backups are protected. 'recovery': to the admin's recovery key. 'system': to a key derived from the master key. */
export type BackupEncryption = 'recovery' | 'system' | 'none';

export class BackupFormatError extends Error {}

export function generateBackupKeyPair(): { publicKey: string; secretKey: string } {
  const { privateKey } = generateKeyPairSync('x25519');
  const jwk = privateKey.export({ format: 'jwk' });
  return { publicKey: PUBLIC_PREFIX + jwk.x, secretKey: SECRET_PREFIX + jwk.d };
}

export function parsePublicKey(text: string): Buffer {
  const t = text.trim();
  const raw = t.startsWith(PUBLIC_PREFIX) ? Buffer.from(t.slice(PUBLIC_PREFIX.length), 'base64url') : null;
  if (!raw || raw.length !== 32) throw new BackupFormatError('That is not an Any-SSH backup public key (it should start with "anybak-pub-1-").');
  return raw;
}

function secretKeyObject(text: string): KeyObject {
  const t = text.trim();
  const raw = t.startsWith(SECRET_PREFIX) ? Buffer.from(t.slice(SECRET_PREFIX.length), 'base64url') : null;
  if (!raw || raw.length !== 32) throw new BackupFormatError('That is not an Any-SSH backup secret key (it should start with "anybak-secret-1-").');
  return createPrivateKey({ key: Buffer.concat([PKCS8_X25519_PREFIX, raw]), format: 'der', type: 'pkcs8' });
}

/**
 * The key pair for system-managed encryption, derived from a master key. It is never stored: anyone holding the
 * master key can re-derive it, which is the point (no separate key to keep) and the trade-off (the server alone can
 * read its backups).
 */
export function serverBackupKeyPair(masterKey: Buffer): { publicKey: string; secretKey: string } {
  const raw = Buffer.from(hkdfSync('sha256', masterKey, Buffer.from('any-ssh-backup-system-key'), Buffer.from('v1'), 32));
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_X25519_PREFIX, raw]), format: 'der', type: 'pkcs8' });
  return { publicKey: PUBLIC_PREFIX + createPublicKey(privateKey).export({ format: 'jwk' }).x, secretKey: SECRET_PREFIX + raw.toString('base64url') };
}

const publicKeyObject = (raw: Buffer) => createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: raw.toString('base64url') }, format: 'jwk' });

export function publicKeyFromSecret(secretKey: string): string {
  return PUBLIC_PREFIX + createPublicKey(secretKeyObject(secretKey)).export({ format: 'jwk' }).x;
}

/** Short identifier of a recovery public key, shown in the UI and stored in each backup's header. */
export function backupKeyId(publicKey: string): string {
  return createHash('sha256').update(parsePublicKey(publicKey)).digest('hex').slice(0, 16);
}

const deriveKey = (shared: Buffer, ephemeral: Buffer, recipient: Buffer) =>
  Buffer.from(hkdfSync('sha256', shared, ephemeral, Buffer.concat([Buffer.from('any-ssh-backup-v1'), recipient]), 32));

const nonce = (counter: number, last: boolean) => {
  const iv = Buffer.alloc(12);
  iv.writeBigUInt64BE(BigInt(counter), 0);
  iv[11] = last ? 1 : 0;
  return iv;
};

/** Reads up to `n` bytes (fewer only at end of file). Position-less reads, so pipes and /dev/stdin work. */
async function readUpTo(fh: FileHandle, n: number): Promise<Buffer> {
  const buf = Buffer.alloc(n);
  let off = 0;
  while (off < n) {
    const { bytesRead } = await fh.read(buf, off, n - off, null);
    if (bytesRead === 0) break;
    off += bytesRead;
  }
  return buf.subarray(0, off);
}

export async function encryptFile(src: string, dest: string, publicKey: string): Promise<{ bytes: number; sha256: string }> {
  const recipient = parsePublicKey(publicKey);
  const ephemeral = generateKeyPairSync('x25519');
  const ephemeralRaw = Buffer.from(ephemeral.publicKey.export({ format: 'jwk' }).x!, 'base64url');
  const key = deriveKey(diffieHellman({ privateKey: ephemeral.privateKey, publicKey: publicKeyObject(recipient) }), ephemeralRaw, recipient);
  const header = Buffer.concat([MAGIC, Buffer.from(backupKeyId(publicKey), 'hex'), ephemeralRaw]);
  const hash = createHash('sha256');
  let bytes = 0;
  const input = await open(src, 'r');
  let output: FileHandle | undefined;
  try {
    output = await open(dest, 'wx', 0o600);
    const write = async (b: Buffer) => {
      hash.update(b);
      bytes += b.length;
      await output!.write(b);
    };
    await write(header);
    let counter = 0;
    let current = await readUpTo(input, CHUNK);
    for (;;) {
      // Reading ahead tells us which frame is the last one.
      const next = current.length === CHUNK ? await readUpTo(input, CHUNK) : Buffer.alloc(0);
      const last = next.length === 0;
      const cipher = createCipheriv('aes-256-gcm', key, nonce(counter++, last));
      cipher.setAAD(header);
      const ct = Buffer.concat([cipher.update(current), cipher.final()]);
      const frameHeader = Buffer.alloc(5);
      frameHeader[0] = last ? 1 : 0;
      frameHeader.writeUInt32BE(ct.length, 1);
      await write(Buffer.concat([frameHeader, ct, cipher.getAuthTag()]));
      if (last) break;
      current = next;
    }
    await output.sync();
  } catch (err) {
    await output?.close().catch(() => {});
    output = undefined;
    await rm(dest, { force: true });
    throw err;
  } finally {
    await input.close();
    await output?.close();
  }
  return { bytes, sha256: hash.digest('hex') };
}

/**
 * Writes the database held in a backup to `dest` (which must not exist): decrypts an .anybak with whichever of
 * `secretKeys` it was made for, or copies an unencrypted SQLite backup as is. Removes `dest` and throws if no key fits
 * or the file was changed.
 */
export async function openBackupFile(src: string, dest: string, secretKeys: string[]): Promise<{ bytes: number; keyId: string | null }> {
  const input = await open(src, 'r');
  let output: FileHandle | undefined;
  try {
    const header = await readUpTo(input, HEADER_LENGTH);
    if (header.subarray(0, SQLITE_MAGIC.length).equals(SQLITE_MAGIC)) {
      output = await open(dest, 'wx', 0o600);
      await output.write(header);
      let bytes = header.length;
      for (;;) {
        const chunk = await readUpTo(input, CHUNK);
        if (!chunk.length) break;
        await output.write(chunk);
        bytes += chunk.length;
      }
      await output.sync();
      return { bytes, keyId: null };
    }
    if (header.length < HEADER_LENGTH || !header.subarray(0, MAGIC.length).equals(MAGIC)) {
      throw new BackupFormatError('This is not an Any-SSH backup.');
    }
    const fileKeyId = header.subarray(MAGIC.length, MAGIC.length + 8).toString('hex');
    const privateKey = secretKeys.map(secretKeyObject).find((k) => backupKeyId(PUBLIC_PREFIX + createPublicKey(k).export({ format: 'jwk' }).x) === fileKeyId);
    if (!privateKey) {
      throw new BackupFormatError(
        `This backup was encrypted for key ${fileKeyId}. Give the recovery secret key it was made with, or, for a system-managed backup, run this where the master key it was made with is set.`,
      );
    }
    const recipient = Buffer.from(createPublicKey(privateKey).export({ format: 'jwk' }).x!, 'base64url');
    const ephemeral = header.subarray(MAGIC.length + 8);
    const key = deriveKey(diffieHellman({ privateKey, publicKey: publicKeyObject(ephemeral) }), ephemeral, recipient);
    output = await open(dest, 'wx', 0o600);
    let counter = 0;
    let bytes = 0;
    for (;;) {
      const frameHeader = await readUpTo(input, 5);
      if (frameHeader.length < 5) throw new BackupFormatError('The backup is cut short.');
      const last = frameHeader[0] === 1;
      const length = frameHeader.readUInt32BE(1);
      if (length > CHUNK) throw new BackupFormatError('The backup is damaged.');
      const body = await readUpTo(input, length + TAG_LENGTH);
      if (body.length < length + TAG_LENGTH) throw new BackupFormatError('The backup is cut short.');
      const decipher = createDecipheriv('aes-256-gcm', key, nonce(counter++, last));
      decipher.setAAD(header);
      decipher.setAuthTag(body.subarray(length));
      let plain: Buffer;
      try {
        plain = Buffer.concat([decipher.update(body.subarray(0, length)), decipher.final()]);
      } catch {
        throw new BackupFormatError('The backup is damaged or has been tampered with.');
      }
      await output.write(plain);
      bytes += plain.length;
      if (last) {
        if ((await readUpTo(input, 1)).length) throw new BackupFormatError('The backup has unexpected data after its end.');
        break;
      }
    }
    await output.sync();
    return { bytes, keyId: fileKeyId };
  } catch (err) {
    await output?.close().catch(() => {});
    output = undefined;
    await rm(dest, { force: true });
    throw err;
  } finally {
    await input.close();
    await output?.close();
  }
}

/** Decrypts an encrypted backup to `dest` with its recovery secret key. Refuses unencrypted files. */
export async function decryptFile(src: string, dest: string, secretKey: string): Promise<{ bytes: number; keyId: string }> {
  const r = await openBackupFile(src, dest, [secretKey]);
  if (r.keyId === null) {
    await rm(dest, { force: true });
    throw new BackupFormatError('This backup is not encrypted.');
  }
  return { bytes: r.bytes, keyId: r.keyId };
}
