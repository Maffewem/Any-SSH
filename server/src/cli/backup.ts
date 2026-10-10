// Consistent online backup of the database (safe while the server is running).
// Usage: npm run backup [-- <output file>]   default: <data dir>/backups/any-ssh-<timestamp>.db
// The backup holds encrypted secrets only; it is useless without the master key, so store
// the key somewhere else (and back that up separately).
import { chmodSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { loadConfig } from '../config.js';
import { openDatabase } from '../db.js';

const config = loadConfig();
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const out = path.resolve(process.argv[2] ?? path.join(config.dataDir, 'backups', `any-ssh-${stamp}.db`));
mkdirSync(path.dirname(out), { recursive: true, mode: 0o700 });

const db = openDatabase(config.dbPath);
await db.backup(out);
db.close();
chmodSync(out, 0o600);
console.log(`Backup written to ${out}`);
