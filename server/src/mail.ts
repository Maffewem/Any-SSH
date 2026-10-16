import nodemailer from 'nodemailer';
import type { Config } from './config.js';

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
}

export interface Mailer {
  /** 'smtp' when mail really leaves the server; 'log' when it only goes to the server log. */
  readonly delivery: 'smtp' | 'log';
  send(msg: MailMessage): Promise<void>;
}

type Log = { info(obj: object, msg: string): void };

/**
 * SMTP when configured, otherwise a development fallback that writes the message to the
 * server log. Mail is plain text only: nothing user-controlled is ever rendered as HTML.
 */
export function createMailer(config: Pick<Config, 'smtp' | 'mailFrom'>, log: Log): Mailer {
  if (!config.smtp) {
    return {
      delivery: 'log',
      async send(msg) {
        log.info({ to: msg.to, subject: msg.subject }, `Email (SMTP not configured, logged instead):\n${msg.text}`);
      },
    };
  }
  const { host, port, secure, user, pass } = config.smtp;
  const transport = nodemailer.createTransport({
    host,
    port,
    secure,
    // Never fall back to plaintext SMTP: links in these emails are credentials.
    requireTLS: !secure,
    tls: { minVersion: 'TLSv1.2' },
    ...(user ? { auth: { user, pass } } : {}),
  });
  return {
    delivery: 'smtp',
    async send(msg) {
      await transport.sendMail({ from: config.mailFrom, to: msg.to, subject: msg.subject, text: msg.text });
    },
  };
}

/**
 * The app's mailer: rebuilt from the current settings whenever an admin changes them in the
 * web UI, so new SMTP details apply without a restart.
 */
export class ConfigurableMailer implements Mailer {
  private inner: Mailer;
  constructor(
    private readonly current: () => Pick<Config, 'smtp' | 'mailFrom'>,
    private readonly log: Log,
  ) {
    this.inner = createMailer(current(), log);
  }
  reload(): void {
    this.inner = createMailer(this.current(), this.log);
  }
  get delivery() {
    return this.inner.delivery;
  }
  send(msg: MailMessage): Promise<void> {
    return this.inner.send(msg);
  }
}

/** Collects messages instead of sending them. Used in tests. */
export class MemoryMailer implements Mailer {
  readonly delivery = 'smtp' as const;
  readonly sent: MailMessage[] = [];
  async send(msg: MailMessage): Promise<void> {
    this.sent.push(msg);
  }
}

// ---- Templates ----

const footer = '\n\nIf you weren’t expecting this email, contact your Any-SSH administrator.\n';

export const emails = {
  invite(p: { to: string; displayName: string; username: string; invitedBy: string; url: string; hours: number }): MailMessage {
    return {
      to: p.to,
      subject: 'You’re invited to join Any-SSH',
      text:
        `Hi ${p.displayName},\n\n${p.invitedBy} created an Any-SSH account for you.\n\n` +
        `Username: ${p.username}\n\nTo create your password, open this link. It can be used once and expires in ${p.hours} hours:\n${p.url}` +
        footer,
    };
  },
  passwordReset(p: { to: string; displayName: string; username: string; url: string; minutes: number }): MailMessage {
    return {
      to: p.to,
      subject: 'Reset your Any-SSH password',
      text:
        `Hi ${p.displayName},\n\nWe received a request to reset the password for the Any-SSH account "${p.username}".\n\n` +
        `To create a new password, open this link. It can be used once and expires in ${p.minutes} minutes:\n${p.url}\n\n` +
        'If you didn’t request this, you can ignore this email. Your password hasn’t changed.' +
        footer,
    };
  },
  ipChallenge(p: { to: string; displayName: string; code: string; ip: string; minutes: number }): MailMessage {
    return {
      to: p.to,
      subject: 'Your Any-SSH verification code',
      text:
        `Hi ${p.displayName},\n\nWe noticed a sign-in to your Any-SSH account from ${p.ip}, which isn’t one of your trusted IP addresses.\n\n` +
        `To verify it’s you, enter this code. It can be used once and expires in ${p.minutes} minutes:\n\n${p.code}\n\n` +
        'If this wasn’t you, don’t share this code and change your password right away.' +
        footer,
    };
  },
  test(p: { to: string; displayName: string; sentBy: string }): MailMessage {
    return {
      to: p.to,
      subject: 'Any-SSH test email',
      text: `Hi ${p.displayName},\n\n${p.sentBy} sent this test email from the Any-SSH settings. Email is working correctly.` + footer,
    };
  },
  backupFailed(p: { to: string; displayName: string; destination: string; error: string }): MailMessage {
    return {
      to: p.to,
      subject: 'Any-SSH backup failed',
      text:
        `Hi ${p.displayName},\n\nThe latest Any-SSH backup to ${p.destination} didn’t complete.\n\nWhat happened: ${p.error}\n\n` +
        'Until this is fixed, you may not have a recent backup. Go to Settings → Backups to review the history and test the destination. ' +
        'We won’t email you about further failures for 24 hours.' +
        footer,
    };
  },
  hostKeyChanged(p: {
    to: string; displayName: string; server: string; endpoint: string; attemptedBy: string;
    expected: string; presented: string; presentedType: string;
  }): MailMessage {
    return {
      to: p.to,
      subject: `Any-SSH: the fingerprint for ${p.server} has changed`,
      text:
        `Hi ${p.displayName},\n\nThe server "${p.server}" (${p.endpoint}) presented a different fingerprint from the one saved in ` +
        `Any-SSH, so the connection attempt by ${p.attemptedBy} was blocked.\n\n` +
        `Saved fingerprint:     ${p.expected}\nPresented fingerprint: ${p.presented} (${p.presentedType})\n\n` +
        'If you reinstalled that server or changed its keys, check the new fingerprint on the server itself ' +
        '(ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub) and accept it under Servers → Edit. ' +
        'If you didn’t, someone may be intercepting connections to it, so don’t accept the new fingerprint.' +
        footer,
    };
  },
  securityNotice(p: { to: string; displayName: string; what: string }): MailMessage {
    return {
      to: p.to,
      subject: `Any-SSH security alert: ${p.what}`,
      text: `Hi ${p.displayName},\n\nWe’re letting you know about a change to your Any-SSH account: ${p.what}.\n\nIf this was you, you don’t need to do anything.` + footer,
    };
  },
};
