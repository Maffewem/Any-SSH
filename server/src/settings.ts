import { z } from 'zod';
import type { Config, SmtpConfig } from './config.js';
import type { SecretBox } from './crypto.js';
import type { DB } from './db.js';

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
  maxTerminalsPerUser: number;
}

export type SettingsGroup = 'mail' | 'sessions' | 'limits';
export type SettingsSource = 'environment' | 'web';

export const settingContext = (id: string) => `setting:${id}`;

const minutes = (min: number, max: number) => z.number().int().min(min).max(max);

export const sessionSettingsSchema = z
  .object({
    lockMinutes: minutes(0, 24 * 60),
    idleMinutes: minutes(5, 7 * 24 * 60),
    maxHours: z.number().int().min(1).max(30 * 24),
  })
  .refine((s) => s.lockMinutes === 0 || s.lockMinutes < s.idleMinutes, {
    message: 'The lock must come before the idle sign-out.',
    path: ['lockMinutes'],
  })
  .refine((s) => s.idleMinutes <= s.maxHours * 60, {
    message: 'The idle sign-out cannot be longer than the session lifetime.',
    path: ['idleMinutes'],
  });

export const limitSettingsSchema = z.object({ maxTerminalsPerUser: z.number().int().min(1).max(100) });

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
      'smtp' | 'mailFrom' | 'sessionLockMinutes' | 'sessionIdleMinutes' | 'sessionMaxHours' | 'maxTerminalsPerUser'
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
    if (row) return JSON.parse(row.value) as LimitSettings;
    return { maxTerminalsPerUser: this.env.maxTerminalsPerUser };
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
      limits: { source: this.source('limits'), ...this.limits },
    };
  }

  /**
   * Saves mail settings. Returns which fields changed (names only, for the audit log).
   * Changing the server or username drops a stored password unless a new one is given, so a
   * hijacked admin session cannot point SMTP at its own server and collect the old password.
   */
  setMail(input: MailSettingsInput, actorId: string): string[] {
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
    return changed;
  }

  setSessions(input: SessionSettings, actorId: string): void {
    this.write('sessions', JSON.stringify(sessionSettingsSchema.parse(input)), null, actorId);
  }

  setLimits(input: LimitSettings, actorId: string): void {
    this.write('limits', JSON.stringify(limitSettingsSchema.parse(input)), null, actorId);
  }

  /** Back to the environment's values. */
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
