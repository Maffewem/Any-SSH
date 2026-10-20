export interface User {
  id: string;
  username: string;
  displayName: string;
  email: string | null;
  role: 'admin' | 'user';
  status: 'active' | 'disabled';
  /** Set while a self-registered account is waiting for email confirmation or for an administrator. */
  registrationState: 'unverified' | 'pending_approval' | null;
  mfaEnabled: boolean;
  mustChangePassword: boolean;
  lastLoginAt: number | null;
  createdAt: number;
  locked?: boolean;
}

export interface SettingsView {
  mail: {
    source: 'environment' | 'web';
    enabled: boolean;
    host: string;
    port: number;
    security: 'tls' | 'starttls';
    username: string;
    hasPassword: boolean;
    from: string;
  };
  sessions: { source: 'environment' | 'web'; lockMinutes: number; idleMinutes: number; maxHours: number };
  limits: {
    source: 'environment' | 'web';
    maxTerminalsPerUser: number;
    maxTerminalsPerAdmin: number | null;
    detachMinutes: number;
    defaults: { maxTerminalsPerUser: number; maxTerminalsPerAdmin: number | null; detachMinutes: number };
  };
  security: {
    source: 'environment' | 'web';
    accountThreshold: number;
    ipThreshold: number;
    windowMinutes: number;
    lockoutMinutes: number;
    notifyOwner: boolean;
  };
  registration: { source: 'environment' | 'web'; mode: RegistrationMode; mailReady: boolean };
  turnstile: { source: 'environment' | 'web'; siteKey: string; signup: boolean; reset: boolean; login: boolean; hasSecretKey: boolean };
  maintenance: MaintenanceView;
  backup: BackupSettingsView;
}

/** invite: administrators create accounts. approval: anyone may register, an administrator approves. open: anyone may register. */
export type RegistrationMode = 'invite' | 'approval' | 'open';

/** What the sign-in and Create account pages need before anyone is signed in. */
export interface AuthConfig {
  registration: RegistrationMode;
  turnstile: { siteKey: string; signup: boolean; reset: boolean; login: boolean } | null;
}

export interface MaintenanceView {
  source: 'environment' | 'web';
  enabled: boolean;
  /** 0 = Sunday … 6 = Saturday. */
  days: number[];
  start: string;
  durationMinutes: number;
  timezone: string;
}

export type BackupTargetView =
  | { kind: 'none' }
  | { kind: 'local' }
  | { kind: 's3'; endpoint: string; region: string; bucket: string; prefix: string; accessKeyId: string; pathStyle: boolean; hasSecretKey: boolean }
  | { kind: 'sftp'; host: string; port: number; username: string; path: string; hostKeyFingerprint: string; hasPassword: boolean; hasPrivateKey: boolean };

export interface BackupSettingsView {
  enabled: boolean;
  frequency: 'hourly' | 'daily' | 'weekly';
  hourUtc: number;
  weekday: number;
  keep: number;
  encryption: BackupEncryption;
  publicKey: string;
  keyId: string | null;
  target: BackupTargetView;
}

/** recovery: to the admin's recovery key. system: to a key derived from the master key. none: not encrypted. */
export type BackupEncryption = 'recovery' | 'system' | 'none';

export interface BackupRunView {
  id: string;
  startedAt: number;
  finishedAt: number | null;
  trigger: 'schedule' | 'manual' | 'cli';
  outcome: 'running' | 'success' | 'failure';
  name: string | null;
  bytes: number | null;
  destination: string | null;
  encryption: BackupEncryption;
  error: string | null;
  warning: string | null;
}

export interface BackupStatusView {
  configured: boolean;
  scheduled: boolean;
  running: boolean;
  last: BackupRunView | null;
  lastSuccess: BackupRunView | null;
  nextRunAt: number | null;
  stale: boolean;
}

export type Access = 'owner' | 'manage' | 'use';
/** Whose credentials a share connects with. */
export type ShareCredentials = 'owner' | 'own';
/** none: direct. auto: through the closest jump host. fixed: through the one an admin chose. */
export type JumpMode = 'none' | 'auto' | 'fixed';

export interface JumpHost {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  publicKey: string;
  keyFingerprint: string;
  hostKeyFingerprint: string | null;
  enabled: boolean;
  serverCount: number;
}

export interface JumpTest {
  fingerprint: string | null;
  hostKey: 'unpinned' | 'match' | 'mismatch' | 'unknown';
  authenticated: boolean;
  latencyMs: number | null;
  error?: string;
}

export type AuthMethod = 'key' | 'password' | 'prompt';

export interface HostKeyPin {
  fingerprint: string;
  type: string | null;
  pinnedAt: number | null;
  pinnedBy: string | null;
}
export interface HostKeyChange {
  fingerprint: string;
  type: string | null;
  seenAt: number | null;
}
export interface HostKeyRow {
  serverId: string;
  name: string;
  host: string;
  port: number;
  owner: { id: string; username: string; displayName: string };
  hostKey: HostKeyPin | null;
  hostKeyChange: HostKeyChange | null;
  conflict: boolean;
}

export interface Server {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authMethod: AuthMethod;
  key: { id: string; name: string; fingerprint: string } | null;
  hasStoredPassword: boolean;
  hostKeyFingerprint: string | null;
  jump: { mode: JumpMode; host: { id: string; name: string; enabled: boolean } | null };
  hostKey: HostKeyPin | null;
  /** A different key the server presented; connections stay refused until the owner accepts or dismisses it. */
  hostKeyChange: HostKeyChange | null;
  notes: string;
  tags: string[];
  access: Access;
  credentials: ShareCredentials;
  canShare: boolean;
  owner: { id: string; username: string; displayName: string } | null;
  shareCount: number;
}

/** What the browser connects with. A one-off key is held in memory and never sent anywhere but the connect call. */
export type ConnectCredential =
  | { type: 'saved' }
  | { type: 'key'; keyId: string }
  | { type: 'oneoff'; privateKey: string; passphrase?: string }
  | { type: 'password' };

export interface ConnectChoice {
  credential: ConnectCredential;
  username?: string;
}

export interface SshKey {
  id: string;
  name: string;
  type: string;
  publicKey: string;
  fingerprint: string;
  createdAt: number;
  lastUsedAt: number | null;
}

export interface Share {
  userId: string;
  username: string;
  displayName: string;
  permission: 'use' | 'manage';
  credentials: ShareCredentials;
  canReshare: boolean;
  sharedBy: string | null;
}

export interface AuditEntry {
  seq: number;
  ts: number;
  actorUsername: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  ip: string | null;
  outcome: 'success' | 'failure';
  details: Record<string, unknown>;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code?: string,
  ) {
    super(message);
  }
}

/** Calls that are expected to fail with 401 while signed out; they must not bounce to the login page. */
const SIGNED_OUT_PATHS = ['/api/auth/login', '/api/auth/mfa', '/api/auth/me', '/api/auth/forgot', '/api/auth/token/', '/api/auth/unlock'];

let onIpChallenge: (() => void) | null = null;
/** Called when the server holds this session until the user verifies a sign-in from a new address. */
export function setIpChallengeHandler(fn: () => void) {
  onIpChallenge = fn;
}

let onUnauthenticated: (() => void) | null = null;
export function setUnauthenticatedHandler(fn: () => void) {
  onUnauthenticated = fn;
}

/** Called when the server says this session is locked (idle, or locked from another tab). */
let onLocked: (() => void) | null = null;
export function setLockedHandler(fn: () => void) {
  onLocked = fn;
}
export function notifyLocked() {
  onLocked?.();
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: {
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      // Required by the server's CSRF check on every write.
      ...(method !== 'GET' ? { 'X-Any-SSH': '1' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    const err = new ApiError(res.status, data?.error ?? `Request failed (${res.status})`, data?.code);
    if (res.status === 401 && err.code === 'session_locked') onLocked?.();
    else if (res.status === 401 && !SIGNED_OUT_PATHS.some((p) => path.startsWith(p))) onUnauthenticated?.();
    if (res.status === 403 && data?.code === 'ip_challenge') onIpChallenge?.();
    throw err;
  }
  return data as T;
}

export const get = <T>(path: string) => api<T>('GET', path);
export const post = <T>(path: string, body: unknown = {}) => api<T>('POST', path, body);
export const patch = <T>(path: string, body: unknown) => api<T>('PATCH', path, body);
export const put = <T>(path: string, body: unknown) => api<T>('PUT', path, body);
export const del = <T>(path: string) => api<T>('DELETE', path);

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Hands the browser a file without it ever touching disk on the server side of the UI. */
export function downloadText(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function formatTime(ts: number | null | undefined): string {
  return ts ? new Date(ts).toLocaleString() : '—';
}

export interface HealthProbe {
  reachable: boolean;
  latencyMs: number | null;
  error: string | null;
  checkedAt: number;
}

export interface Health {
  generatedAt: number;
  app: {
    version: string;
    commit: string | null;
    builtAt: string | null;
    startedAt: number;
    uptimeSeconds: number;
    node: string;
    schemaVersion: number;
    updateAvailable: boolean | null;
    updateCheckedAt: number | null;
    terminals: { open: number; detached: number };
  };
  storage: { freeBytes: number | null; totalBytes: number | null; databaseBytes: number | null };
  certificate: { host: string; notAfter: number | null; daysLeft: number | null; issuer: string | null; trusted: boolean | null; error: string | null; checkedAt: number } | null;
  backups: { configured: boolean; scheduled: boolean; stale: boolean; lastSuccessAt: number | null; lastOutcome: string | null };
  summary: {
    servers: number;
    reachable: number;
    unreachable: number;
    viaJumpHost: number;
    hostKeyChanged: number;
    hostKeyUnverified: number;
    jumpHostsDown: number;
    noJumpHostAvailable: boolean;
  };
  servers: {
    id: string;
    name: string;
    host: string;
    port: number;
    owner: string;
    hostKey: 'pinned' | 'unverified' | 'changed';
    route: { mode: JumpMode; jumpHost: string | null; testable: boolean };
    probe: HealthProbe | null;
  }[];
  jumpHosts: {
    id: string;
    name: string;
    host: string;
    port: number;
    enabled: boolean;
    hostKey: 'pinned' | 'unverified';
    serverCount: number;
    probe: HealthProbe | null;
  }[];
}

const REVIEW_KEY = 'anyssh.reviewHostKey';
export const REVIEW_HOST_KEY_EVENT = 'anyssh:review-host-key';

/** Takes the user to Servers with the changed-key review for this server open. */
export function reviewHostKey(serverId: string) {
  try {
    sessionStorage.setItem(REVIEW_KEY, serverId);
  } catch {
    /* storage unavailable: they land on Servers and use the card */
  }
  if (location.hash === '#/servers') window.dispatchEvent(new Event(REVIEW_HOST_KEY_EVENT));
  else location.hash = '#/servers';
}

/** The server a pending review was requested for, once. */
export function takeHostKeyReview(): string | null {
  try {
    const id = sessionStorage.getItem(REVIEW_KEY);
    sessionStorage.removeItem(REVIEW_KEY);
    return id;
  } catch {
    return null;
  }
}
