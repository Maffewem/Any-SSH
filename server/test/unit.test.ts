import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AuditLog } from '../src/audit.js';
import { SecretBox } from '../src/crypto.js';
import { openDatabase } from '../src/db.js';
import { checkPasswordPolicy, hashPassword, verifyPassword } from '../src/passwords.js';
import { isBlockedAddress } from '../src/ssh/target.js';
import { base32Encode, hotp, totpCounter, verifyTotp } from '../src/totp.js';

describe('SecretBox', () => {
  const box = new SecretBox(randomBytes(32));

  it('round-trips', () => {
    const sealed = box.seal('top secret', 'ctx:a');
    expect(sealed).not.toContain('top secret');
    expect(box.openString(sealed, 'ctx:a')).toBe('top secret');
  });

  it('refuses a ciphertext moved to another context', () => {
    const sealed = box.seal('top secret', 'ssh_key:1:private');
    expect(() => box.open(sealed, 'ssh_key:2:private')).toThrow();
  });

  it('detects tampering', () => {
    const parts = box.seal('top secret', 'c').split('.');
    const ct = Buffer.from(parts[4]!, 'base64url');
    ct[0]! ^= 1;
    parts[4] = ct.toString('base64url');
    expect(() => box.open(parts.join('.'), 'c')).toThrow();
  });

  it('refuses a different master key', () => {
    const other = new SecretBox(randomBytes(32));
    expect(() => other.open(box.seal('x', 'c'), 'c')).toThrow(/different master key/);
  });
});

describe('TOTP', () => {
  // RFC 6238 Appendix B (SHA-1), truncated to 6 digits.
  const secret = base32Encode(Buffer.from('12345678901234567890'));

  it('matches RFC 6238 vectors', () => {
    expect(hotp(secret, totpCounter(59_000))).toBe('287082');
    expect(hotp(secret, totpCounter(1111111109_000))).toBe('081804');
    expect(hotp(secret, totpCounter(2000000000_000))).toBe('279037');
  });

  it('accepts ±1 step and rejects replays', () => {
    const now = 1111111109_000;
    const code = hotp(secret, totpCounter(now));
    const used = verifyTotp(secret, code, null, now);
    expect(used).toBe(totpCounter(now));
    expect(verifyTotp(secret, code, used, now)).toBeNull();
    expect(verifyTotp(secret, hotp(secret, totpCounter(now) - 1), null, now)).not.toBeNull();
    expect(verifyTotp(secret, hotp(secret, totpCounter(now) - 3), null, now)).toBeNull();
  });
});

describe('passwords', () => {
  it('hashes with argon2id and verifies', async () => {
    const hash = await hashPassword('a perfectly fine passphrase');
    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(await verifyPassword(hash, 'a perfectly fine passphrase')).toBe(true);
    expect(await verifyPassword(hash, 'wrong')).toBe(false);
  });

  it('enforces the policy', () => {
    expect(checkPasswordPolicy('short')).toMatch(/at least/);
    expect(checkPasswordPolicy('aaaaaaaaaaaaaaaa')).toMatch(/repetitive/);
    expect(checkPasswordPolicy('matthew-is-great-1', 'matthew')).toMatch(/username/);
    expect(checkPasswordPolicy('violet-ladder-93-orbit')).toBeNull();
  });
});

describe('audit log', () => {
  it('chains hashes and blocks edits', () => {
    const db = openDatabase(':memory:');
    const audit = new AuditLog(db);
    audit.record({ action: 'a' });
    audit.record({ action: 'b', details: { x: 1 } });
    expect(audit.verify()).toEqual({ ok: true, checked: 2, brokenAt: null });
    expect(() => db.prepare("UPDATE audit_log SET action = 'z'").run()).toThrow(/append-only/);
    expect(() => db.prepare('DELETE FROM audit_log').run()).toThrow(/append-only/);

    // Someone with raw DB access drops the trigger and rewrites history: verify() notices.
    db.exec('DROP TRIGGER audit_log_no_update');
    db.prepare("UPDATE audit_log SET action = 'z' WHERE seq = 1").run();
    expect(audit.verify()).toMatchObject({ ok: false, brokenAt: 1 });
  });
});

describe('SSRF guard', () => {
  it.each([
    ['127.0.0.1', true],
    ['169.254.169.254', true],
    ['::1', true],
    ['::ffff:127.0.0.1', true],
    ['0.0.0.0', true],
    ['10.0.0.5', false],
    ['192.168.1.20', false],
    ['203.0.113.7', false],
  ])('%s blocked=%s', (addr, blocked) => {
    expect(isBlockedAddress(addr)).toBe(blocked);
  });
});
