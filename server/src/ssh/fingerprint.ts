import { createHash } from 'node:crypto';

/** OpenSSH-style fingerprint of a public key blob: "SHA256:<unpadded base64>". */
export function sshFingerprint(publicKeyBlob: Buffer): string {
  return `SHA256:${createHash('sha256').update(publicKeyBlob).digest('base64').replace(/=+$/, '')}`;
}
