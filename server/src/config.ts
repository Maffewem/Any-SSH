import { readFileSync } from 'node:fs';
import path from 'node:path';

export interface Config {
  host: string;
  port: number;
  dataDir: string;
  dbPath: string;
  /** 32-byte key used to encrypt secrets (private keys, passwords, TOTP seeds) at rest. */
  masterKey: Buffer;
  /** Public origin(s) of the web app, e.g. https://ssh.example.com. Used for Origin checks. */
  allowedOrigins: string[];
  cookieSecure: boolean;
  trustProxy: boolean;
  sessionIdleMinutes: number;
  sessionMaxHours: number;
  maxTerminalsPerUser: number;
  sshConnectTimeoutMs: number;
  /** Allow SSH targets on loopback / link-local / metadata addresses. Off by default (SSRF guard). */
  allowLoopbackTargets: boolean;
  webRoot: string | null;
  logLevel: string;
}

function bool(v: string | undefined, dflt: boolean): boolean {
  if (v === undefined || v === '') return dflt;
  return ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
}

function int(v: string | undefined, dflt: number): number {
  if (v === undefined || v === '') return dflt;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`Invalid integer config value: ${v}`);
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

  return {
    host: env.ANYSSH_HOST ?? '127.0.0.1',
    port,
    dataDir,
    dbPath: env.ANYSSH_DB_PATH ?? path.join(dataDir, 'any-ssh.db'),
    masterKey: parseMasterKey(rawKey),
    allowedOrigins: origins,
    cookieSecure: bool(env.ANYSSH_COOKIE_SECURE, production),
    trustProxy: bool(env.ANYSSH_TRUST_PROXY, false),
    sessionIdleMinutes: int(env.ANYSSH_SESSION_IDLE_MINUTES, 30),
    sessionMaxHours: int(env.ANYSSH_SESSION_MAX_HOURS, 12),
    maxTerminalsPerUser: int(env.ANYSSH_MAX_TERMINALS_PER_USER, 8),
    sshConnectTimeoutMs: int(env.ANYSSH_SSH_CONNECT_TIMEOUT_MS, 15000),
    allowLoopbackTargets: bool(env.ANYSSH_ALLOW_LOOPBACK_TARGETS, false),
    webRoot: env.ANYSSH_WEB_ROOT === '' ? null : path.resolve(env.ANYSSH_WEB_ROOT ?? '../web/dist'),
    logLevel: env.ANYSSH_LOG_LEVEL ?? (production ? 'info' : 'debug'),
  };
}
