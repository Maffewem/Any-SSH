import argon2 from 'argon2';
import { randomBytes, randomInt } from 'node:crypto';

// OWASP-recommended Argon2id parameters (64 MiB, 3 passes, 4 lanes).
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
} as const;

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 256;

const COMMON_PASSWORDS = new Set([
  'password1234', 'password12345', 'password123456', '123456789012', 'qwertyuiop12',
  'letmein12345', 'administrator', 'welcome12345', 'changeme1234', 'iloveyou1234',
  'passwordpassword', 'qwerty123456', '1q2w3e4r5t6y', 'adminadmin123',
]);

export function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON2_OPTIONS);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

export function needsRehash(hash: string): boolean {
  return argon2.needsRehash(hash, ARGON2_OPTIONS);
}

let dummyHash: Promise<string> | undefined;
/**
 * Burn the same CPU as a real verification when the username does not exist,
 * so response timing does not reveal which usernames are valid.
 */
export async function verifyDummy(password: string): Promise<void> {
  dummyHash ??= hashPassword(randomBytes(16).toString('hex'));
  await verifyPassword(await dummyHash, password);
}

/** Returns a human-readable problem with the password, or null if acceptable. */
export function checkPasswordPolicy(password: string, username?: string): string | null {
  if (password.length < PASSWORD_MIN_LENGTH) return `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`;
  if (password.length > PASSWORD_MAX_LENGTH) return `Password must be at most ${PASSWORD_MAX_LENGTH} characters.`;
  const lower = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) return 'That password is too common.';
  if (username && lower.includes(username.toLowerCase())) return 'Password must not contain your username.';
  if (new Set(password).size < 5) return 'Password is too repetitive.';
  return null;
}

/** Generates a temporary password for admin-created accounts and resets. */
export function generateTemporaryPassword(): string {
  // 20 chars from an unambiguous alphabet ≈ 110 bits.
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  let out = '';
  for (let i = 0; i < 20; i++) out += alphabet[randomInt(alphabet.length)];
  return out;
}
