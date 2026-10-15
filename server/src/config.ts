import { readFileSync } from 'node:fs';
import path from 'node:path';

export interface Config {
  host: string;
  port: number;
  dataDir: string;
  dbPath: string;
  /** 32-byte key used to encrypt secrets (private keys, passwords, TOTP seeds) at rest. */
  masterKey: Buffer;
  /** Retired master keys, still accepted for decryption until `npm run rotate-keys` re-seals everything. */
  previousMasterKeys: Buffer[];
  /** Public origin(s) of the web app, e.g. https://ssh.example.com. Used for Origin checks. */
  allowedOrigins: string[];
  cookieSecure: boolean;
  trustProxy: boolean;
  /** Idle minutes before a session locks (unlock with the account password, no 2FA). 0 = never lock. */
  sessionLockMinutes: number;
  /** Idle minutes before a session is signed out entirely. */
  sessionIdleMinutes: number;
  /** Absolute session lifetime, however active. */
  sessionMaxHours: number;
  maxTerminalsPerUser: number;
  /** Minutes a dropped browser connection keeps its SSH session alive for re-attaching. 0 = close at once. */
  detachMinutes: number;
  sshConnectTimeoutMs: number;
  /** Allow SSH targets on loopback / link-local / metadata addresses. Off by default (SSRF guard). */
  allowLoopbackTargets: boolean;
  webRoot: string | null;
  logLevel: string;
  /** Base URL used in links inside emails. */
  publicUrl: string;
  /** Outgoing mail. null = emails are written to the server log instead (development). */
  smtp: SmtpConfig | null;
  mailFrom: string;
  /** Periodically ask the image registry whether a newer build of this release channel exists. */
  updateCheck: boolean;
  /** Image repository the server is installed from, e.g. ghcr.io/maffewem/any-ssh. */
  updateImage: string;
  /** Tag the install follows (ANYSSH_VERSION in .env): latest, or a release line like 1.2. */
  updateTag: string;
  /** Whether the host runs automatic updates (`any-ssh auto-update on`). Informational only. */
  autoUpdate: boolean;
}

export interface SmtpConfig {
  host: string;
  port: number;
  /** true = implicit TLS (port 465); otherwise STARTTLS is required. */
  secure: boolean;
  user?: string;
  pass?: string;
}

function bool(v: string | undefined, dflt: boolean): boolean {
  if (v === undefined || v === '') return dflt;
  return ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
}

function int(v: string | undefined, dflt: number, min = 1): number {
  if (v === undefined || v === '') return dflt;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n) || n < min) throw new Error(`Invalid integer config value: ${v}`);
  return n;
}

export function parseMasterKey(raw: string): Buffer {
  const key = Buffer.from(raw.trim(), 'base64');
  if (key.length !== 32) {
    throw new Error('ANYSSH_MASTER_KEY must be 32 bytes, base64 encoded (run `npm run gen-key`).');
  }
  return key;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const dataDir = path.resolve(env.ANYSSH_DATA_DIR ?? './data');

  let rawKey = env.ANYSSH_MASTER_KEY;
  if (!rawKey && env.ANYSSH_MASTER_KEY_FILE) rawKey = readFileSync(env.ANYSSH_MASTER_KEY_FILE, 'utf8');
  let rawPrevious = env.ANYSSH_PREVIOUS_MASTER_KEYS ?? '';
  if (!rawPrevious && env.ANYSSH_PREVIOUS_MASTER_KEYS_FILE) rawPrevious = readFileSync(env.ANYSSH_PREVIOUS_MASTER_KEYS_FILE, 'utf8');
  let smtpPass = env.ANYSSH_SMTP_PASS;
  if (!smtpPass && env.ANYSSH_SMTP_PASS_FILE) smtpPass = readFileSync(env.ANYSSH_SMTP_PASS_FILE, 'utf8').trim();
  // Drop secrets from process.env once read, so child processes do not inherit them and code
  // that dumps the environment (crash reporters, debug endpoints) cannot leak them.
  if (env === process.env) {
    delete process.env.ANYSSH_MASTER_KEY;
    delete process.env.ANYSSH_PREVIOUS_MASTER_KEYS;
    delete process.env.ANYSSH_SMTP_PASS;
  }
  if (!rawKey) {
    throw new Error(
      'No master key configured. Set ANYSSH_MASTER_KEY or ANYSSH_MASTER_KEY_FILE (generate one with `npm run gen-key`).',
    );
  }

  const production = env.NODE_ENV === 'production';
  const port = int(env.ANYSSH_PORT ?? env.PORT, 8080);
  const origins = (env.ANYSSH_ORIGIN ?? `http://localhost:${port}`)
    .split(',')
    .map((o) => o.trim().replace(/\/$/, ''))
    .filter(Boolean);

  const smtpHost = env.ANYSSH_SMTP_HOST;
  const smtpPort = int(env.ANYSSH_SMTP_PORT, 587);
  return {
    host: env.ANYSSH_HOST ?? '127.0.0.1',
    port,
    dataDir,
    dbPath: env.ANYSSH_DB_PATH ?? path.join(dataDir, 'any-ssh.db'),
    masterKey: parseMasterKey(rawKey),
    previousMasterKeys: rawPrevious
      .split(',')
      .map((k) => k.trim())
      .filter(Boolean)
      .map(parseMasterKey),
    allowedOrigins: origins,
    cookieSecure: bool(env.ANYSSH_COOKIE_SECURE, production),
    trustProxy: bool(env.ANYSSH_TRUST_PROXY, false),
    sessionLockMinutes: int(env.ANYSSH_SESSION_LOCK_MINUTES, 15, 0),
    sessionIdleMinutes: int(env.ANYSSH_SESSION_IDLE_MINUTES, 120),
    sessionMaxHours: int(env.ANYSSH_SESSION_MAX_HOURS, 12),
    maxTerminalsPerUser: int(env.ANYSSH_MAX_TERMINALS_PER_USER, 8),
    detachMinutes: int(env.ANYSSH_DETACH_MINUTES, 5, 0),
    sshConnectTimeoutMs: int(env.ANYSSH_SSH_CONNECT_TIMEOUT_MS, 15000),
    allowLoopbackTargets: bool(env.ANYSSH_ALLOW_LOOPBACK_TARGETS, false),
    webRoot: env.ANYSSH_WEB_ROOT === '' ? null : path.resolve(env.ANYSSH_WEB_ROOT ?? '../web/dist'),
    logLevel: env.ANYSSH_LOG_LEVEL ?? (production ? 'info' : 'debug'),
    publicUrl: (env.ANYSSH_PUBLIC_URL ?? origins[0] ?? `http://localhost:${port}`).replace(/\/$/, ''),
    smtp: smtpHost
      ? {
          host: smtpHost,
          port: smtpPort,
          secure: bool(env.ANYSSH_SMTP_SECURE, smtpPort === 465),
          ...(env.ANYSSH_SMTP_USER ? { user: env.ANYSSH_SMTP_USER } : {}),
          ...(smtpPass ? { pass: smtpPass } : {}),
        }
      : null,
    mailFrom: env.ANYSSH_MAIL_FROM ?? 'Any-SSH <no-reply@localhost>',
    updateCheck: bool(env.ANYSSH_UPDATE_CHECK, true),
    updateImage: env.ANYSSH_UPDATE_IMAGE || 'ghcr.io/maffewem/any-ssh',
    updateTag: env.ANYSSH_VERSION || 'latest',
    autoUpdate: bool(env.ANYSSH_AUTO_UPDATE, false),
  };
}
