import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Authenticated encryption for secrets at rest (AES-256-GCM).
 *
 * Every ciphertext is bound to a context string (AAD) such as "ssh_key:<id>:private_key",
 * so a blob copied into another row or column fails to decrypt instead of silently
 * handing one user's secret to another.
 *
 * Format: "v1.<keyId>.<iv b64url>.<tag b64url>.<ciphertext b64url>"
 * keyId is a short fingerprint of the master key that sealed the value, which is how key
 * rotation (src/rotate.ts) finds values still sealed with a retired key.
 */
export class SecretBox {
  readonly keyId: string;
  private readonly keys = new Map<string, Buffer>();

  /**
   * @param key current master key, used for all new ciphertexts
   * @param previousKeys retired keys, accepted for decryption only (during key rotation)
   */
  constructor(key: Buffer, previousKeys: Buffer[] = []) {
    if (key.length !== 32) throw new Error('SecretBox key must be 32 bytes');
    this.keyId = SecretBox.idOf(key);
    this.keys.set(this.keyId, key);
    for (const k of previousKeys) this.keys.set(SecretBox.idOf(k), k);
  }

  static idOf(key: Buffer): string {
    return createHash('sha256').update(key).digest('hex').slice(0, 8);
  }

  seal(plaintext: string | Buffer, context: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.keys.get(this.keyId)!, iv);
    cipher.setAAD(Buffer.from(context, 'utf8'));
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return ['v1', this.keyId, iv.toString('base64url'), tag.toString('base64url'), ct.toString('base64url')].join('.');
  }

  open(sealed: string, context: string): Buffer {
    const parts = sealed.split('.');
    if (parts.length !== 5 || parts[0] !== 'v1') throw new Error('Unsupported secret format');
    const [, keyId, ivB64, tagB64, ctB64] = parts as [string, string, string, string, string];
    const key = this.keys.get(keyId);
    if (!key) throw new Error('Secret was sealed with a different master key');
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64url'));
    decipher.setAAD(Buffer.from(context, 'utf8'));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
    return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64url')), decipher.final()]);
  }

  openString(sealed: string, context: string): string {
    return this.open(sealed, context).toString('utf8');
  }

  /** True when the ciphertext was sealed with a retired key and should be re-sealed. */
  isStale(sealed: string): boolean {
    return sealed.split('.')[1] !== this.keyId;
  }

  /** Re-encrypts under the current key (same context), or returns the input if already current. */
  reseal(sealed: string, context: string): string {
    return this.isStale(sealed) ? this.seal(this.open(sealed, context), context) : sealed;
  }
}

/** URL-safe random token with `bytes` of entropy. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** Tokens (session ids, tickets, recovery codes) are stored only as SHA-256 hashes. */
export function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
