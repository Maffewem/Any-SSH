// Backup tooling. Run with `node dist/cli/backup.js <command>` (or `npm run backup -- <command>`).
//
//   file [path]                 Write a backup file now, protected as Settings → Backups says (.anybak when encrypted;
//                               a plain .db when unencrypted, or before a recovery key is set). Prints the path.
//                               No path = <data dir>/backups/any-ssh-<time>.
//   run                         Do what the schedule does: encrypt, store at the configured destination, prune.
//   keygen                      Print a new recovery key pair (works offline, on any machine with Node).
//   decrypt <file> <out>        Decrypt a backup (see "Keys" below).
//   restore <file> [--into <db>] [--force] [--verify-only]
//                               Decrypt, verify and (unless --verify-only) put the database in place. Stop Any-SSH first.
//
// Keys: a recovery-key backup needs its secret key (--key-file <file|->, or ANYSSH_BACKUP_KEY). A system-managed one
// opens with the master key (current or previous) in the environment. An unencrypted one needs neither.
// <file> may be "-" or /dev/stdin. The master key is used, when available, to prove the backup opens with it.
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync } from 'node:fs';
import path from 'node:path';
import { BackupConfigError, BackupService } from '../backup/service.js';
import { encryptFile, generateBackupKeyPair, openBackupFile, publicKeyFromSecret, backupKeyId, serverBackupKeyPair } from '../backup/format.js';
import { verifyDatabaseFile } from '../backup/verify.js';
import { AuditLog } from '../audit.js';
import { loadConfig, type Config } from '../config.js';
import { SecretBox } from '../crypto.js';
import { openDatabase } from '../db.js';
import { ConfigurableMailer } from '../mail.js';
import { Settings } from '../settings.js';

const COMMANDS = ['file', 'run', 'keygen', 'decrypt', 'restore'];
const argv = process.argv.slice(2);
// `npm run backup -- <path>` keeps working: anything that is not a command is the output path of `file`.
const [command, ...rest] = argv[0] && COMMANDS.includes(argv[0]) ? argv : ['file', ...argv];
const flag = (name: string) => {
  const i = rest.indexOf(`--${name}`);
  return i === -1 ? undefined : rest[i + 1];
};
const has = (name: string) => rest.includes(`--${name}`);
const positional = rest.filter((a, i) => !a.startsWith('--') && !(rest[i - 1]?.startsWith('--') && !['force', 'verify-only'].includes(rest[i - 1]!.slice(2))));
const log = { info: (o: object | string, m?: string) => console.log(m ?? (typeof o === 'string' ? o : JSON.stringify(o))), warn: (o: object | string, m?: string) => console.error(m ?? (typeof o === 'string' ? o : JSON.stringify(o))) };
const stamp = () => new Date().toISOString().replace(/[-:]|\.\d{3}/g, '');

/** The recovery secret key, if one was given. */
function secretKey(): string | null {
  const file = flag('key-file');
  const raw = file ? readFileSync(file === '-' ? '/dev/stdin' : file, 'utf8') : process.env.ANYSSH_BACKUP_KEY;
  delete process.env.ANYSSH_BACKUP_KEY;
  return raw?.trim() || null;
}

/** Every key a backup could be opened with here: the recovery secret key given, then the system keys of each master key. */
function openingKeys(config: Config | null): string[] {
  const given = secretKey();
  if (given) console.log(`Recovery key ${backupKeyId(publicKeyFromSecret(given))}`);
  const masters = config ? [config.masterKey, ...config.previousMasterKeys] : [];
  return [...(given ? [given] : []), ...masters.map((k) => serverBackupKeyPair(k).secretKey)];
}


function fail(message: string, code = 1): never {
  console.error(message);
  process.exit(code);
}

function tryConfig(): Config | null {
  try {
    return loadConfig();
  } catch {
    return null;
  }
}

function services() {
  const config = loadConfig();
  const db = openDatabase(config.dbPath);
  const box = new SecretBox(config.masterKey, config.previousMasterKeys);
  const settings = new Settings(db, box, config);
  const audit = new AuditLog(db);
  const mailer = new ConfigurableMailer(() => ({ smtp: settings.mail.smtp, mailFrom: settings.mail.from }), log);
  return { config, db, box, settings, service: new BackupService({ db, settings, box, audit, mailer, config, log }) };
}

try {
  switch (command) {
    case 'keygen': {
      const { publicKey, secretKey: secret } = generateBackupKeyPair();
      console.log(`Public key (paste into Settings → Backups):\n${publicKey}\n\nSecret key (keep it offline; it is the only way to read backups):\n${secret}`);
      break;
    }

    case 'file': {
      const { config, db, settings, box } = services();
      const b = settings.backup;
      const key = b.encryption === 'recovery' ? b.publicKey : b.encryption === 'system' ? serverBackupKeyPair(config.masterKey).publicKey : '';
      const base = path.resolve(positional[0] ?? path.join(config.dataDir, 'backups', `any-ssh-${stamp()}`)).replace(/\.(db|anybak)$/, '');
      mkdirSync(path.dirname(base), { recursive: true, mode: 0o700 });
      const plain = `${base}.${key ? 'snapshot' : 'db'}`;
      await db.backup(plain);
      const report = verifyDatabaseFile(plain, box);
      if (!report.ok) {
        rmSync(plain, { force: true });
        fail(`The database failed its check: ${report.checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`).join('; ')}`);
      }
      let out = plain;
      if (key) {
        out = `${base}.anybak`;
        await encryptFile(plain, out, key);
        rmSync(plain, { force: true });
      } else if (b.encryption === 'none') {
        console.error('Note: backups are set to be stored without encryption (Settings → Backups).');
      } else {
        console.error('Note: no recovery key is set, so this backup is not encrypted. Set one in Settings → Backups.');
      }
      db.close();
      chmodSync(out, 0o600);
      console.log(out);
      break;
    }

    case 'run': {
      const { db, service } = services();
      try {
        const run = await service.run('cli');
        db.close();
        if (run.outcome !== 'success') fail(`Backup failed: ${run.error}`);
        console.log(`Backup ${run.name} stored at ${run.destination}${run.warning ? `\nWarning: ${run.warning}` : ''}`);
      } catch (err) {
        db.close();
        if (err instanceof BackupConfigError) fail(err.message, 3);
        throw err;
      }
      break;
    }

    case 'decrypt': {
      const [file, out] = positional;
      if (!file || !out) fail('Usage: decrypt <backup file> <output file> [--key-file <secret key file>]');
      const r = await openBackupFile(file === '-' ? '/dev/stdin' : file, path.resolve(out), openingKeys(tryConfig()));
      console.log(`${r.keyId ? 'Decrypted' : 'Copied (it was not encrypted)'} ${r.bytes} bytes to ${out}`);
      break;
    }

    case 'restore': {
      const [file] = positional;
      if (!file) fail('Usage: restore <backup file> [--into <database file>] [--force] [--verify-only] [--key-file <secret key file>]');
      const config = tryConfig();
      const into = path.resolve(flag('into') ?? config?.dbPath ?? 'any-ssh.db');
      const tmp = `${into}.restoring-${stamp()}`;
      mkdirSync(path.dirname(into), { recursive: true, mode: 0o700 });
      const r = await openBackupFile(file === '-' ? '/dev/stdin' : file, tmp, openingKeys(config));
      console.log(r.keyId ? `Decrypted and authenticated ${r.bytes} bytes (key ${r.keyId}).` : `Read ${r.bytes} bytes. This backup is not encrypted.`);
      const box = config ? new SecretBox(config.masterKey, config.previousMasterKeys) : undefined;
      const report = verifyDatabaseFile(tmp, box);
      for (const c of report.checks) console.log(`  ${c.ok ? 'OK  ' : 'FAIL'} ${c.name}: ${c.detail}`);
      if (!box) console.log('  --   Master key: not checked (no master key available here)');
      if (!report.ok) {
        rmSync(tmp, { force: true });
        fail('The backup did not pass verification, so nothing was changed.');
      }
      if (has('verify-only')) {
        rmSync(tmp, { force: true });
        console.log('The backup is good. Nothing was changed.');
        break;
      }
      if (existsSync(into) && !has('force')) {
        rmSync(tmp, { force: true });
        fail(`${into} already exists. Run again with --force to replace it (the old one is kept next to it).`);
      }
      if (existsSync(into)) {
        const aside = `${into}.before-restore-${stamp()}`;
        renameSync(into, aside);
        console.log(`The previous database was kept as ${aside}`);
      }
      for (const ext of ['-wal', '-shm']) rmSync(`${into}${ext}`, { force: true });
      renameSync(tmp, into);
      chmodSync(into, 0o600);
      console.log(`Restored to ${into}. Start Any-SSH again.`);
      break;
    }

    default:
      fail('Commands: file, run, keygen, decrypt, restore', 2);
  }
} catch (err) {
  fail(err instanceof Error ? err.message : String(err));
}
