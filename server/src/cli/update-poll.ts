// Run by the host's `any-ssh update-poll` (through `docker compose exec`) every few minutes.
// Prints one line telling the host what to do, and records that the agent is alive:
//   none                    nothing to do
//   check-auto              look for a newer image; if there is one, run `schedule-auto`
//   run <manual|auto> <by>  an update is due: start it
// Usage: node dist/cli/update-poll.js [schedule-auto]
import { loadConfig } from '../config.js';
import { openDatabase } from '../db.js';
import { Settings } from '../settings.js';
import { SecretBox } from '../crypto.js';
import { UpdateRequests } from '../updateRequests.js';

const config = loadConfig();
const db = openDatabase(config.dbPath);
const settings = new Settings(db, new SecretBox(config.masterKey, config.previousMasterKeys), config);
const requests = new UpdateRequests(db);

if (process.argv[2] === 'schedule-auto') {
  console.log(requests.scheduleAuto(settings.maintenance) ? 'scheduled' : 'skipped');
} else {
  requests.heartbeat();
  const due = requests.claimDue();
  if (due) console.log(`run ${due.trigger} ${due.requestedBy.replace(/\s+/g, '_')}`);
  else if (requests.shouldCheckAuto(config.autoUpdate, settings.maintenance)) console.log('check-auto');
  else console.log('none');
}
db.close();
