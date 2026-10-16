import { z } from 'zod';
import { BackupFormatError, backupKeyId, parsePublicKey, type BackupEncryption } from './backup/format.js';
import type { Config, SmtpConfig } from './config.js';
import type { SecretBox } from './crypto.js';
import type { DB } from './db.js';
import { DEFAULT_MAINTENANCE, validTimezone, type MaintenanceWindow } from './maintenance.js';

/**
 * Runtime settings an administrator can change from the web UI. Each group falls back to the
 * environment (config.ts) until an admin saves it, and returns to the environment value when
 * reset. Bootstrap-critical values (master key, database, origins, public URL, cookie and
 * proxy flags, the SSRF guard) stay environment-only on purpose: they decide who can reach
 * the server and how its secrets are protected, so a stolen admin session must not change them.
 *
 * Secrets (the SMTP password) live in their own sealed column and are never returned to clients.
 */

export interface MailSettings {
  /** null = mail is written to the server log instead of sent. */
  smtp: SmtpConfig | null;
  from: string;
}

export interface SessionSettings {
  lockMinutes: number;
  idleMinutes: number;
  maxHours: number;
}

export interface LimitSettings {
  /** Open terminals for a standard user. */
  maxTerminalsPerUser: number;
  /** Open terminals for an administrator; null = the same as a standard user. */
  maxTerminalsPerAdmin: number | null;
  /** How long a terminal outlives a dropped browser connection. 0 = close at once. */
  detachMinutes: number;
}

export interface SecuritySettings {
  /** Failed attempts on one account inside the window that lock it. */
  accountThreshold: number;
  /** Failed attempts from one address inside the window that block it. */
  ipThreshold: number;
  windowMinutes: number;
  lockoutMinutes: number;
  /** Email the account owner when their account is locked. */
  notifyOwner: boolean;
}

export const DEFAULT_SECURITY: SecuritySettings = {
  accountThreshold: 5,
  ipThreshold: 30,
  windowMinutes: 15,
  lockoutMinutes: 15,
  notifyOwner: true,
};

export const securitySettingsSchema = z.object({
  accountThreshold: z.number().int().min(3).max(100),
  ipThreshold: z.number().int().min(3).max(1000),
  windowMinutes: z.number().int().min(1).max(24 * 60),
  lockoutMinutes: z.number().int().min(1).max(7 * 24 * 60),
  notifyOwner: z.boolean(),
});

export type SettingsGroup = 'mail' | 'sessions' | 'limits' | 'security' | 'backup' | 'maintenance' | 'registration' | 'turnstile';
export type SettingsSource = 'environment' | 'web';

export const maintenanceSettingsSchema = z.object({
  enabled: z.boolean(),
  days: z.array(z.number().int().min(0).max(6)).max(7).transform((d) => [...new Set(d)].sort()),
  start: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, 'Use 24-hour HH:MM'),
  durationMinutes: z.number().int().min(15).max(24 * 60),
  timezone: z.string().max(64).refine(validTimezone, 'Unknown timezone (use a name like Europe/London)'),
}).refine((m) => !m.enabled || m.days.length > 0, { message: 'Select at least one day.', path: ['days'] });

// ---- Registration and Turnstile ----

/** invite: only administrators create accounts. approval: anyone can register, an administrator approves. open: anyone can register. */
export type RegistrationMode = 'invite' | 'approval' | 'open';

export interface RegistrationSettings {
  mode: RegistrationMode;
}

export const DEFAULT_REGISTRATION: RegistrationSettings = { mode: 'invite' };

export const registrationSettingsSchema = z.object({ mode: z.enum(['invite', 'approval', 'open']) });

export interface TurnstileSettings {
  siteKey: string;
  /** Require the Cloudflare check on the Create account page. */
  signup: boolean;
  /** Require it when requesting a password reset email. */
  reset: boolean;
  /** Require it on the Sign in page. */
  login: boolean;
}

export const DEFAULT_TURNSTILE: TurnstileSettings = { siteKey: '', signup: false, reset: false, login: false };

export const turnstileSettingsSchema = z.object({
  siteKey: z.string().trim().max(100).regex(/^[A-Za-z0-9_-]*$/, 'Enter the site key exactly as Cloudflare shows it'),
  /** Omitted = keep the stored secret key; '' = remove it. */
  secretKey: z.string().trim().max(200).regex(/^[A-Za-z0-9_-]*$/, 'Enter the secret key exactly as Cloudflare shows it').optional(),
  signup: z.boolean(),
  reset: z.boolean(),
  login: z.boolean(),
});
export type TurnstileSettingsInput = z.infer<typeof turnstileSettingsSchema>;

export const settingContext = (id: string) => `setting:${id}`;

const minutes = (min: number, max: number) => z.number().int().min(min).max(max);

export const sessionSettingsSchema = z
  .object({
    lockMinutes: minutes(0, 24 * 60),
    idleMinutes: minutes(5, 7 * 24 * 60),
    maxHours: z.number().int().min(1).max(30 * 24),
  })
  .refine((s) => s.lockMinutes === 0 || s.lockMinutes < s.idleMinutes, {
    message: 'The lock must come before the inactivity sign-out.',
    path: ['lockMinutes'],
  })
  .refine((s) => s.idleMinutes <= s.maxHours * 60, {
    message: 'The inactivity sign-out can’t be longer than the maximum session length.',
    path: ['idleMinutes'],
  });

export const limitSettingsSchema = z.object({
  maxTerminalsPerUser: z.number().int().min(1).max(100),
  maxTerminalsPerAdmin: z.number().int().min(1).max(100).nullable().default(null),
  detachMinutes: z.number().int().min(0).max(24 * 60),
});

const hostname = z
  .string()
  .trim()
  .min(1)
  .max(253)
  .regex(/^[A-Za-z0-9.:-]+$/, 'Enter a hostname or IP address');

export const mailSettingsSchema = z.object({
  /** false = no SMTP; emails go to the server log. */
  enabled: z.boolean(),
  host: hostname.optional(),
  port: z.number().int().min(1).max(65535).default(587),
  /** 'tls' = implicit TLS (465); 'starttls' = STARTTLS required. Plaintext is never offered. */
  security: z.enum(['tls', 'starttls']).default('starttls'),
  username: z.string().trim().max(320).optional(),
  /** Omitted = keep the stored password; '' = remove it. */
  password: z.string().max(1024).optional(),
  from: z.string().trim().min(3).max(320).regex(/^[^\r\n]+$/, 'One line only'),
});
export type MailSettingsInput = z.infer<typeof mailSettingsSchema>;


// ---- Backups ----

export type BackupFrequency = 'hourly' | 'daily' | 'weekly';

export type BackupTargetSettings =
  | { kind: 'none' }
  | { kind: 'local' }
  | { kind: 's3'; endpoint: string; region: string; bucket: string; prefix: string; accessKeyId: string; pathStyle: boolean }
  | { kind: 'sftp'; host: string; port: number; username: string; path: string; hostKeyFingerprint: string };

export interface BackupSettings {
  /** Run on a schedule. Manual runs and the CLI work whenever a key and destination are set. */
  enabled: boolean;
  frequency: BackupFrequency;
  hourUtc: number;
  /** 0 = Sunday. Used for weekly backups. */
  weekday: number;
  /** How many backups to keep at the destination. */
  keep: number;
  /** How backups are protected. See docs/SECURITY.md "Backups" for the trade-offs. */
  encryption: BackupEncryption;
  /** Recovery public key backups are encrypted to ('' = not set). Used when encryption is 'recovery'. */
  publicKey: string;
  target: BackupTargetSettings;
}

/** Whether backups can run: a destination, and a recovery key when the mode needs one. */
export const backupReady = (b: BackupSettings) => b.target.kind !== 'none' && (b.encryption !== 'recovery' || !!b.publicKey);

export interface BackupSecrets {
  s3SecretKey?: string;
  sftpPassword?: string;
  sftpPrivateKey?: string;
}

const DEFAULT_BACKUP: BackupSettings = { enabled: false, frequency: 'daily', hourUtc: 3, weekday: 0, keep: 14, encryption: 'recovery', publicKey: '', target: { kind: 'none' } };

const backupHost = z.string().trim().min(1).max(253).regex(/^[A-Za-z0-9.:-]+$/, 'Enter a hostname or IP address');

const backupTargetSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('none') }),
  z.object({ kind: z.literal('local') }),
  z.object({
    kind: z.literal('s3'),
    /** Blank = AWS S3 in `region`. */
    endpoint: z
      .string()
      .trim()
      .max(300)
      .regex(/^(https?:\/\/[A-Za-z0-9.:-]+\/?)?$/, 'Enter the endpoint as https://host (no path), or leave it empty for AWS')
      .transform((v) => v.replace(/\/$/, ''))
      .default(''),
    region: z.string().trim().regex(/^[a-z0-9-]{2,30}$/, 'For example us-east-1').default('us-east-1'),
    bucket: z.string().trim().regex(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/, 'Enter the bucket name'),
    prefix: z
      .string()
      .trim()
      .max(200)
      .regex(/^[A-Za-z0-9._/-]*$/, 'Letters, numbers and . _ - / only')
      .transform((v) => v.replace(/^\/+|\/+$/g, ''))
      .default(''),
    accessKeyId: z.string().trim().min(1).max(128).regex(/^[\w\-./+=@]+$/, 'Enter the access key ID'),
    /** Omitted = keep the stored one; '' = remove it. */
    secretKey: z.string().max(256).optional(),
    pathStyle: z.boolean().default(false),
  }),
  z.object({
    kind: z.literal('sftp'),
    host: backupHost,
    port: z.number().int().min(1).max(65535).default(22),
    username: z.string().trim().min(1).max(64).regex(/^[A-Za-z0-9._-]+$/, 'Enter the SFTP username'),
    path: z.string().trim().min(1).max(300).regex(/^[^\u0000-\u001f]+$/, 'Enter the folder to store backups in'),
    /** "SHA256:…" of the server's host key. Required before any connection is made. */
    hostKeyFingerprint: z.string().trim().regex(/^(SHA256:[A-Za-z0-9+/]{43})?$/, 'Enter it as SHA256:… (as shown by ssh-keygen -lf)').default(''),
    password: z.string().max(1024).optional(),
    privateKey: z.string().max(20_000).optional(),
  }),
]);

export const backupSettingsSchema = z
  .object({
    enabled: z.boolean(),
    frequency: z.enum(['hourly', 'daily', 'weekly']).default('daily'),
    hourUtc: z.number().int().min(0).max(23).default(3),
    weekday: z.number().int().min(0).max(6).default(0),
    keep: z.number().int().min(1).max(365).default(14),
    encryption: z.enum(['recovery', 'system', 'none']).default('recovery'),
    publicKey: z.string().trim().max(200).default(''),
    target: backupTargetSchema,
    /** Must be true to save unencrypted backups, so it is never chosen by accident. */
    acceptUnencrypted: z.boolean().default(false),
  })
  .superRefine((v, ctx) => {
    if (v.publicKey) {
      try {
        parsePublicKey(v.publicKey);
      } catch (err) {
        ctx.addIssue({ code: 'custom', path: ['publicKey'], message: err instanceof BackupFormatError ? err.message : 'Invalid key' });
      }
    }
    if (v.encryption === 'recovery' && v.target.kind !== 'none' && !v.publicKey) {
      ctx.addIssue({ code: 'custom', path: ['publicKey'], message: 'Set a recovery key first, or choose another kind of encryption.' });
    }
    if (v.encryption === 'none' && !v.acceptUnencrypted) {
      ctx.addIssue({ code: 'custom', path: ['acceptUnencrypted'], message: 'Confirm that you want backups stored without encryption.' });
    }
    if (v.enabled && v.target.kind === 'none') {
      ctx.addIssue({ code: 'custom', path: ['target'], message: 'Choose where scheduled backups go.' });
    }
  });
export type BackupSettingsInput = z.infer<typeof backupSettingsSchema>;

interface StoredMail {
  enabled: boolean;
  host?: string;
  port: number;
  security: 'tls' | 'starttls';
  username?: string;
  from: string;
}

interface Row {
  id: string;
  value: string;
  value_enc: string | null;
  updated_at: number;
  updated_by: string | null;
}

export class Settings {
  private cache = new Map<string, Row | null>();
  private listeners: ((group: SettingsGroup) => void)[] = [];

  constructor(
    private readonly db: DB,
    private readonly box: SecretBox,
    private readonly env: Pick<
      Config,
      'smtp' | 'mailFrom' | 'sessionLockMinutes' | 'sessionIdleMinutes' | 'sessionMaxHours' | 'maxTerminalsPerUser' | 'detachMinutes'
    >,
  ) {}

  onChange(fn: (group: SettingsGroup) => void): void {
    this.listeners.push(fn);
  }

  private row(id: SettingsGroup): Row | null {
    if (!this.cache.has(id)) {
      this.cache.set(id, (this.db.prepare('SELECT * FROM settings WHERE id = ?').get(id) as Row | undefined) ?? null);
    }
    return this.cache.get(id)!;
  }

  source(group: SettingsGroup): SettingsSource {
    return this.row(group) ? 'web' : 'environment';
  }

  get mail(): MailSettings {
    const row = this.row('mail');
    if (!row) return { smtp: this.env.smtp, from: this.env.mailFrom };
    const stored = JSON.parse(row.value) as StoredMail;
    if (!stored.enabled || !stored.host) return { smtp: null, from: stored.from };
    const pass = row.value_enc ? this.box.openString(row.value_enc, settingContext('mail')) : undefined;
    return {
      smtp: {
        host: stored.host,
        port: stored.port,
        secure: stored.security === 'tls',
        ...(stored.username ? { user: stored.username } : {}),
        ...(pass ? { pass } : {}),
      },
      from: stored.from,
    };
  }

  get sessions(): SessionSettings {
    const row = this.row('sessions');
    if (row) return JSON.parse(row.value) as SessionSettings;
    return { lockMinutes: this.env.sessionLockMinutes, idleMinutes: this.env.sessionIdleMinutes, maxHours: this.env.sessionMaxHours };
  }

  get limits(): LimitSettings {
    const row = this.row('limits');
    // Rows saved before detachMinutes existed fall back to the environment for it.
    if (row) return { detachMinutes: this.env.detachMinutes, maxTerminalsPerAdmin: null, ...(JSON.parse(row.value) as Partial<LimitSettings>) } as LimitSettings;
    return { maxTerminalsPerUser: this.env.maxTerminalsPerUser, maxTerminalsPerAdmin: null, detachMinutes: this.env.detachMinutes };
  }

  /** The open-terminal allowance for someone in this role. */
  terminalLimit(role: 'admin' | 'user'): number {
    const l = this.limits;
    return role === 'admin' ? (l.maxTerminalsPerAdmin ?? l.maxTerminalsPerUser) : l.maxTerminalsPerUser;
  }


  get backup(): BackupSettings {
    const row = this.row('backup');
    return row ? { ...DEFAULT_BACKUP, ...(JSON.parse(row.value) as BackupSettings) } : DEFAULT_BACKUP;
  }

  backupSecrets(): BackupSecrets {
    const row = this.row('backup');
    return row?.value_enc ? (JSON.parse(this.box.openString(row.value_enc, settingContext('backup'))) as BackupSecrets) : {};
  }

  /**
   * Saves backup settings. A stored secret is kept only while the destination it belongs to is unchanged, so a
   * hijacked admin session cannot re-point backups at its own storage and reuse the saved credentials.
   * Returns the names of the fields that changed (for the audit log).
   */
  setBackup(input: BackupSettingsInput, actorId: string): { changed: string[]; changes: Record<string, { from: unknown; to: unknown }> } {
    const before = this.backup;
    const old = this.backupSecrets();
    const t = input.target;
    const secrets: BackupSecrets = {};
    let target: BackupTargetSettings;
    if (t.kind === 's3') {
      const { secretKey, ...rest } = t;
      target = rest;
      const b = before.target;
      const same = b.kind === 's3' && b.endpoint === t.endpoint && b.region === t.region && b.bucket === t.bucket && b.accessKeyId === t.accessKeyId;
      const secret = secretKey !== undefined ? secretKey : same ? old.s3SecretKey : undefined;
      if (secret) secrets.s3SecretKey = secret;
    } else if (t.kind === 'sftp') {
      const { password, privateKey, ...rest } = t;
      target = rest;
      const b = before.target;
      const same = b.kind === 'sftp' && b.host === t.host && b.port === t.port && b.username === t.username;
      const pass = password !== undefined ? password : same ? old.sftpPassword : undefined;
      const key = privateKey !== undefined ? privateKey : same ? old.sftpPrivateKey : undefined;
      if (pass) secrets.sftpPassword = pass;
      if (key) secrets.sftpPrivateKey = key;
    } else {
      target = t;
    }
    const stored: BackupSettings = {
      enabled: input.enabled,
      frequency: input.frequency,
      hourUtc: input.hourUtc,
      weekday: input.weekday,
      keep: input.keep,
      encryption: input.encryption,
      publicKey: input.publicKey,
      target,
    };
    this.write('backup', JSON.stringify(stored), Object.keys(secrets).length ? this.box.seal(JSON.stringify(secrets), settingContext('backup')) : null, actorId);

    // Names and old/new values of what changed. Secrets are reported only as present or absent.
    const changed: string[] = [];
    const changes: Record<string, { from: unknown; to: unknown }> = {};
    const note = (name: string, from: unknown, to: unknown) => {
      if (from === to) return;
      changed.push(name);
      changes[name] = { from, to };
    };
    for (const k of ['enabled', 'frequency', 'hourUtc', 'weekday', 'keep', 'encryption', 'publicKey'] as const) note(k, before[k], stored[k]);
    const bt = before.target as Record<string, unknown>;
    const at = target as Record<string, unknown>;
    for (const k of new Set([...Object.keys(bt), ...Object.keys(at)])) note(k === 'kind' ? 'destination' : `destination.${k}`, bt[k], at[k]);
    for (const k of ['s3SecretKey', 'sftpPassword', 'sftpPrivateKey'] as const) note(k, !!old[k], !!secrets[k]);
    return { changed, changes };
  }

  get maintenance(): MaintenanceWindow {
    const row = this.row('maintenance');
    return row ? { ...DEFAULT_MAINTENANCE, ...(JSON.parse(row.value) as Partial<MaintenanceWindow>) } : DEFAULT_MAINTENANCE;
  }

  setMaintenance(input: MaintenanceWindow, actorId: string): void {
    this.write('maintenance', JSON.stringify(maintenanceSettingsSchema.parse(input)), null, actorId);
  }

  get registration(): RegistrationSettings {
    const row = this.row('registration');
    return row ? { ...DEFAULT_REGISTRATION, ...(JSON.parse(row.value) as Partial<RegistrationSettings>) } : DEFAULT_REGISTRATION;
  }

  setRegistration(input: RegistrationSettings, actorId: string): void {
    this.write('registration', JSON.stringify(registrationSettingsSchema.parse(input)), null, actorId);
  }

  get turnstile(): TurnstileSettings {
    const row = this.row('turnstile');
    return row ? { ...DEFAULT_TURNSTILE, ...(JSON.parse(row.value) as Partial<TurnstileSettings>) } : DEFAULT_TURNSTILE;
  }

  /** The Cloudflare secret key, or null when none is saved. Never sent to clients. */
  turnstileSecret(): string | null {
    const row = this.row('turnstile');
    return row?.value_enc ? this.box.openString(row.value_enc, settingContext('turnstile')) : null;
  }

  /** The check is available only when both keys are saved. */
  get turnstileConfigured(): boolean {
    return !!this.turnstile.siteKey && !!this.row('turnstile')?.value_enc;
  }

  /** Whether the check is required for this action. Enforced settings without a complete key pair still count (the check then fails closed). */
  turnstileRequired(action: 'signup' | 'reset' | 'login'): boolean {
    return this.turnstile[action];
  }

  /**
   * Saves the Turnstile settings. Changing the site key drops the stored secret unless a new one is given, so a hijacked
   * admin session cannot swap in its own site key and keep using the saved secret.
   */
  setTurnstile(input: TurnstileSettingsInput, actorId: string): { changed: string[]; changes: Record<string, { from: unknown; to: unknown }> } {
    const before = this.turnstile;
    const hadSecret = this.turnstileSecret() !== null;
    let secret: string | null;
    if (input.secretKey !== undefined) secret = input.secretKey || null;
    else secret = input.siteKey === before.siteKey ? this.turnstileSecret() : null;
    if ((input.signup || input.reset || input.login) && (!input.siteKey || !secret)) {
      throw new Error('Enter both the site key and the secret key before turning the check on.');
    }
    const stored: TurnstileSettings = { siteKey: input.siteKey, signup: input.signup, reset: input.reset, login: input.login };
    this.write('turnstile', JSON.stringify(stored), secret ? this.box.seal(secret, settingContext('turnstile')) : null, actorId);
    const changed: string[] = [];
    const changes: Record<string, { from: unknown; to: unknown }> = {};
    for (const k of ['siteKey', 'signup', 'reset', 'login'] as const) {
      if (before[k] !== stored[k]) {
        changed.push(k);
        changes[k] = { from: before[k], to: stored[k] };
      }
    }
    if (hadSecret !== !!secret || input.secretKey) {
      changed.push('secretKey');
      changes.secretKey = { from: hadSecret, to: !!secret };
    }
    return { changed, changes };
  }

  get security(): SecuritySettings {
    const row = this.row('security');
    return row ? { ...DEFAULT_SECURITY, ...(JSON.parse(row.value) as Partial<SecuritySettings>) } : DEFAULT_SECURITY;
  }

  // Getters in the shape SessionStore reads, so changes apply without a restart.
  get sessionLockMinutes(): number {
    return this.sessions.lockMinutes;
  }
  get sessionIdleMinutes(): number {
    return this.sessions.idleMinutes;
  }
  get sessionMaxHours(): number {
    return this.sessions.maxHours;
  }

  /** What the admin page shows. The SMTP password is reported only as present or absent. */
  describe() {
    const mail = this.mail;
    return {
      mail: {
        source: this.source('mail'),
        enabled: mail.smtp !== null,
        host: mail.smtp?.host ?? '',
        port: mail.smtp?.port ?? 587,
        security: mail.smtp?.secure ? ('tls' as const) : ('starttls' as const),
        username: mail.smtp?.user ?? '',
        hasPassword: !!mail.smtp?.pass,
        from: mail.from,
      },
      sessions: { source: this.source('sessions'), ...this.sessions },
      limits: {
        source: this.source('limits'),
        ...this.limits,
        // What "Reset to defaults" would restore, so the page can show it beside each limit.
        defaults: { maxTerminalsPerUser: this.env.maxTerminalsPerUser, maxTerminalsPerAdmin: null, detachMinutes: this.env.detachMinutes },
      },
      security: { source: this.source('security'), ...this.security },
      registration: { source: this.source('registration'), ...this.registration, mailReady: this.mail.smtp !== null },
      turnstile: { source: this.source('turnstile'), ...this.turnstile, hasSecretKey: this.turnstileSecret() !== null },
      maintenance: { source: this.source('maintenance'), ...this.maintenance },
      backup: this.describeBackup(),
    };
  }


  /** What the admin page shows. Secrets are reported only as present or absent. */
  private describeBackup() {
    const b = this.backup;
    const secrets = this.backupSecrets();
    return {
      enabled: b.enabled,
      frequency: b.frequency,
      hourUtc: b.hourUtc,
      weekday: b.weekday,
      keep: b.keep,
      encryption: b.encryption,
      publicKey: b.publicKey,
      keyId: b.publicKey ? backupKeyId(b.publicKey) : null,
      target:
        b.target.kind === 's3'
          ? { ...b.target, hasSecretKey: !!secrets.s3SecretKey }
          : b.target.kind === 'sftp'
            ? { ...b.target, hasPassword: !!secrets.sftpPassword, hasPrivateKey: !!secrets.sftpPrivateKey }
            : b.target,
    };
  }

  /**
   * Saves mail settings. Returns which fields changed (names only, for the audit log).
   * Changing the server or username drops a stored password unless a new one is given, so a
   * hijacked admin session cannot point SMTP at its own server and collect the old password.
   */
  setMail(input: MailSettingsInput, actorId: string): { changed: string[]; changes: Record<string, { from: unknown; to: unknown }> } {
    if (input.enabled && !input.host) throw new Error('Enter the SMTP server.');
    const before = this.describe().mail;
    const row = this.row('mail');
    const stored: StoredMail = {
      enabled: input.enabled,
      ...(input.host ? { host: input.host } : {}),
      port: input.port,
      security: input.security,
      ...(input.username ? { username: input.username } : {}),
      from: input.from,
    };
    const destinationChanged = (stored.host ?? '') !== before.host || (stored.username ?? '') !== before.username;
    let passEnc: string | null;
    if (input.password !== undefined) {
      passEnc = input.password ? this.box.seal(input.password, settingContext('mail')) : null;
    } else if (destinationChanged) {
      passEnc = null;
    } else if (row) {
      passEnc = row.value_enc;
    } else {
      // First save over environment settings: carry the environment password across.
      const envPass = this.env.smtp?.pass;
      passEnc = envPass ? this.box.seal(envPass, settingContext('mail')) : null;
    }
    this.write('mail', JSON.stringify(stored), passEnc, actorId);

    const after = this.describe().mail;
    const changed: string[] = (['enabled', 'host', 'port', 'security', 'username', 'from'] as const).filter((k) => before[k] !== after[k]);
    if (input.password !== undefined) changed.push('password');
    else if (before.hasPassword && !after.hasPassword) changed.push('password_cleared');
    // Old → new for the audit log. The password is never included, only whether it changed.
    const changes: Record<string, { from: unknown; to: unknown }> = {};
    for (const k of changed) if (k in before) changes[k] = { from: before[k as keyof typeof before], to: after[k as keyof typeof after] };
    return { changed, changes };
  }

  setSessions(input: SessionSettings, actorId: string): void {
    this.write('sessions', JSON.stringify(sessionSettingsSchema.parse(input)), null, actorId);
  }

  setLimits(input: z.input<typeof limitSettingsSchema>, actorId: string): void {
    this.write('limits', JSON.stringify(limitSettingsSchema.parse(input)), null, actorId);
  }

  setSecurity(input: SecuritySettings, actorId: string): void {
    this.write('security', JSON.stringify(securitySettingsSchema.parse(input)), null, actorId);
  }

  /** Back to the environment's values (the built-in defaults for the security group). */
  reset(group: SettingsGroup): void {
    this.db.prepare('DELETE FROM settings WHERE id = ?').run(group);
    this.changed(group);
  }

  private write(id: SettingsGroup, value: string, valueEnc: string | null, actorId: string): void {
    this.db
      .prepare(
        `INSERT INTO settings (id, value, value_enc, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET value = excluded.value, value_enc = excluded.value_enc,
           updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
      )
      .run(id, value, valueEnc, Date.now(), actorId);
    this.changed(id);
  }

  private changed(group: SettingsGroup): void {
    this.cache.delete(group);
    for (const fn of this.listeners) fn(group);
  }
}
