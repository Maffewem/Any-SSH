import type { AuditLog } from './audit.js';
import type { Config } from './config.js';
import type { SecretBox } from './crypto.js';
import type { DB } from './db.js';
import type { Mailer } from './mail.js';
import type { SessionStore } from './sessions.js';
import type { Settings } from './settings.js';
import type { TerminalRegistry } from './ssh/registry.js';
import type { UpdateChecker } from './updates.js';

export type Role = 'admin' | 'user';

export interface UserRow {
  id: string;
  username: string;
  display_name: string;
  email: string | null;
  password_hash: string;
  role: Role;
  status: 'active' | 'disabled';
  must_change_password: number;
  totp_secret_enc: string | null;
  totp_enabled: number;
  totp_last_counter: number | null;
  failed_logins: number;
  locked_until: number | null;
  trusted_ip_enabled: number;
  trusted_ip_policy: 'notify' | 'challenge';
  last_login_at: number | null;
  password_changed_at: number;
  created_at: number;
  updated_at: number;
}

export interface SessionRow {
  id_hash: string;
  user_id: string;
  stage: 'mfa' | 'full';
  created_at: number;
  last_seen_at: number;
  expires_at: number;
  ip: string | null;
  user_agent: string | null;
  ip_challenge: number;
  flagged_ip: string | null;
  locked_at: number | null;
  unlock_failures: number;
}

export interface SshKeyRow {
  id: string;
  owner_id: string;
  name: string;
  key_type: string;
  public_key: string;
  fingerprint: string;
  private_key_enc: string;
  created_at: number;
  last_used_at: number | null;
}

export interface ServerRow {
  id: string;
  owner_id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  auth_method: 'key' | 'password' | 'prompt';
  key_id: string | null;
  password_enc: string | null;
  host_key_fingerprint: string | null;
  notes: string;
  created_at: number;
  updated_at: number;
}

export type SharePermission = 'use' | 'manage';
/** Whose credentials a share connects with: the owner's saved ones, or the grantee's own. */
export type ShareCredentials = 'owner' | 'own';

export interface ServerShareRow {
  server_id: string;
  user_id: string;
  permission: SharePermission;
  credentials: ShareCredentials;
  can_reshare: number;
  created_by: string | null;
  created_at: number;
}
/** How the current user relates to a server: owner, or a share grant. */
export type ServerAccess = 'owner' | SharePermission;

export interface AppContext {
  config: Config;
  db: DB;
  box: SecretBox;
  audit: AuditLog;
  sessions: SessionStore;
  terminals: TerminalRegistry;
  mailer: Mailer;
  settings: Settings;
  updates: UpdateChecker;
}

export function publicUser(u: UserRow) {
  return {
    id: u.id,
    username: u.username,
    displayName: u.display_name,
    email: u.email,
    role: u.role,
    status: u.status,
    mfaEnabled: u.totp_enabled === 1,
    mustChangePassword: u.must_change_password === 1,
    lastLoginAt: u.last_login_at,
    createdAt: u.created_at,
  };
}
