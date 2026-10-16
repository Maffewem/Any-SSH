// Turns the Cloudflare browser check off (removes its settings and saved secret key). For when the check is
// required but can't be passed, for example after saving the wrong keys, so nobody can sign in to fix it.
// Run by the host-side `any-ssh browser-check-off`, which restarts the app afterwards to pick the change up.
import { AuditLog } from '../audit.js';
import { loadConfig } from '../config.js';
import { openDatabase } from '../db.js';

const db = openDatabase(loadConfig().dbPath);
const removed = db.prepare("DELETE FROM settings WHERE id = 'turnstile'").run().changes;
new AuditLog(db).record({ action: 'system.browser_check_off', targetType: 'system', details: { removed: removed > 0 } });
db.close();
console.log(removed > 0 ? 'The browser check settings were removed.' : 'The browser check was not configured.');
