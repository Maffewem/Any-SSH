// Master key rotation. Usage:
//   1. Generate a new key:            npm run gen-key
//   2. Restart with   ANYSSH_MASTER_KEY=<new>  ANYSSH_PREVIOUS_MASTER_KEYS=<old>
//   3. Re-seal everything:            npm run rotate-keys   (same environment)
//   4. Remove ANYSSH_PREVIOUS_MASTER_KEYS and restart. Destroy the old key.
import { AuditLog } from '../audit.js';
import { loadConfig } from '../config.js';
import { SecretBox } from '../crypto.js';
import { openDatabase } from '../db.js';
import { rotateSecrets } from '../rotate.js';

const config = loadConfig();
const db = openDatabase(config.dbPath);
const box = new SecretBox(config.masterKey, config.previousMasterKeys);
let result: ReturnType<typeof rotateSecrets>;
try {
  result = rotateSecrets(db, box);
} catch (err) {
  console.error(
    `Rotation stopped: ${err instanceof Error ? err.message : String(err)}.\n` +
      'Put the key(s) that sealed the existing data in ANYSSH_PREVIOUS_MASTER_KEYS (comma-separated) and run again.',
  );
  process.exit(1);
}
new AuditLog(db).record({ action: 'system.master_key_rotate', details: { keyId: box.keyId, ...result } });
db.close();

console.log(`Re-sealed ${result.resealed} secret(s) under key ${box.keyId}.`);
if (result.remainingStale > 0) {
  console.error(`${result.remainingStale} secret(s) are still sealed with a retired key. Run again.`);
  process.exit(1);
}
console.log('All secrets use the current key. You can now remove ANYSSH_PREVIOUS_MASTER_KEYS.');
