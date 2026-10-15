export interface User {
  id: string;
  username: string;
  displayName: string;
  email: string | null;
  role: 'admin' | 'user';
  status: 'active' | 'disabled';
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
  limits: { source: 'environment' | 'web'; maxTerminalsPerUser: number };
  security: {
    source: 'environment' | 'web';
    accountThreshold: number;
    ipThreshold: number;
    windowMinutes: number;
    lockoutMinutes: number;
    notifyOwner: boolean;
  };
}

export type Access = 'owner' | 'manage' | 'use';
/** Whose credentials a share connects with. */
export type ShareCredentials = 'owner' | 'own';
export type AuthMethod = 'key' | 'password' | 'prompt';

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
  notes: string;
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
