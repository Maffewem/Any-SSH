// Records a software update in the audit log, so updates show up in the app's Update history.
// Run by the host-side `any-ssh` script through `docker compose exec`; it holds no secrets.
// Usage: node dist/cli/record-update.js <success|failure|rolled_back> <manual|auto> <from> <to> [note]
//   <from>/<to> are free text such as "1.4.0 (abc1234)". Everything is length-limited and stored as data.
import { AuditLog } from '../audit.js';
import { loadConfig } from '../config.js';
import { openDatabase } from '../db.js';

const [result, trigger, from = '', to = '', note = ''] = process.argv.slice(2);
if (!['success', 'failure', 'rolled_back'].includes(result ?? '') || !['manual', 'auto'].includes(trigger ?? '')) {
  console.error('Usage: record-update <success|failure|rolled_back> <manual|auto> <from> <to> [note]');
  process.exit(2);
}
const clip = (s: string, n: number) => s.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, n);

const db = openDatabase(loadConfig().dbPath);
new AuditLog(db).record({
  action: 'system.update',
  targetType: 'system',
  outcome: result === 'success' ? 'success' : 'failure',
  details: { result, trigger, from: clip(from, 80), to: clip(to, 80), ...(note ? { note: clip(note, 200) } : {}) },
});
db.close();
