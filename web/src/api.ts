export interface User {
  id: string;
  username: string;
  displayName: string;
  role: 'admin' | 'user';
  status: 'active' | 'disabled';
  mfaEnabled: boolean;
  mustChangePassword: boolean;
  lastLoginAt: number | null;
  createdAt: number;
  locked?: boolean;
}

export type Access = 'owner' | 'manage' | 'use';
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
  owner: { id: string; username: string; displayName: string } | null;
  shareCount: number;
}

export interface SshKey {
  id: string;
  name: string;
  type: string;
  publicKey: string;
  fingerprint: string;
  createdAt: number;
}

export interface Share {
  userId: string;
  username: string;
  displayName: string;
  permission: 'use' | 'manage';
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

let onUnauthenticated: (() => void) | null = null;
export function setUnauthenticatedHandler(fn: () => void) {
  onUnauthenticated = fn;
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
    if (res.status === 401 && path !== '/api/auth/login' && path !== '/api/auth/mfa' && path !== '/api/auth/me') {
      onUnauthenticated?.();
    }
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

export function formatTime(ts: number | null | undefined): string {
  return ts ? new Date(ts).toLocaleString() : '—';
}
