// Prints a fresh 256-bit master key for ANYSSH_MASTER_KEY. Store it in a secret manager or a
// file readable only by the service user; losing it makes stored keys and passwords unreadable.
import { randomBytes } from 'node:crypto';

console.log(randomBytes(32).toString('base64'));
