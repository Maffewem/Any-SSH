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

const footer = '\n\nIf you did not expect this email, contact your Any-SSH administrator.\n';

export const emails = {
  invite(p: { to: string; displayName: string; username: string; invitedBy: string; url: string; hours: number }): MailMessage {
    return {
      to: p.to,
      subject: 'You have been invited to Any-SSH',
      text:
        `Hi ${p.displayName},\n\n${p.invitedBy} has created an Any-SSH account for you.\n\n` +
        `Username: ${p.username}\n\nChoose your password here (the link works once and expires in ${p.hours} hours):\n${p.url}` +
        footer,
    };
  },
  passwordReset(p: { to: string; displayName: string; username: string; url: string; minutes: number }): MailMessage {
    return {
      to: p.to,
      subject: 'Reset your Any-SSH password',
      text:
        `Hi ${p.displayName},\n\nSomeone asked to reset the password for the Any-SSH account "${p.username}".\n\n` +
        `To choose a new password, open this link (it works once and expires in ${p.minutes} minutes):\n${p.url}\n\n` +
        'If this was not you, ignore this email; your password has not changed.' +
        footer,
    };
  },
  ipChallenge(p: { to: string; displayName: string; code: string; ip: string; minutes: number }): MailMessage {
    return {
      to: p.to,
      subject: 'Any-SSH sign-in verification code',
      text:
        `Hi ${p.displayName},\n\nA sign-in to your Any-SSH account came from ${p.ip}, which is not on your trusted IP list.\n\n` +
        `To let it in, enter this code (it works once and expires in ${p.minutes} minutes):\n\n${p.code}\n\n` +
        'If this was not you, do not share the code. Change your password.' +
        footer,
    };
  },
  test(p: { to: string; displayName: string; sentBy: string }): MailMessage {
    return {
      to: p.to,
      subject: 'Any-SSH test email',
      text: `Hi ${p.displayName},\n\n${p.sentBy} sent this test from the Any-SSH settings page. Email delivery is working.` + footer,
    };
  },
  backupFailed(p: { to: string; displayName: string; destination: string; error: string }): MailMessage {
    return {
      to: p.to,
      subject: 'Any-SSH backup failed',
      text:
        `Hi ${p.displayName},\n\nThe latest Any-SSH backup to ${p.destination} did not complete.\n\nWhat went wrong: ${p.error}\n\n` +
        'Until this is fixed there may be no recent backup. Open Settings → Backups to see the history and run a test. ' +
        'Further failures are not emailed again for 24 hours.' +
        footer,
    };
  },
  hostKeyChanged(p: {
    to: string; displayName: string; server: string; endpoint: string; attemptedBy: string;
    expected: string; presented: string; presentedType: string;
  }): MailMessage {
    return {
      to: p.to,
      subject: `Any-SSH: host key CHANGED for ${p.server}`,
      text:
        `Hi ${p.displayName},\n\nThe server "${p.server}" (${p.endpoint}) presented a different host key from the one pinned in ` +
        `Any-SSH, so the connection by ${p.attemptedBy} was refused.\n\n` +
        `Pinned:    ${p.expected}\nPresented: ${p.presented} (${p.presentedType})\n\n` +
        'If you reinstalled or re-keyed that server, check the new fingerprint on the server itself ' +
        '(ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub) and accept it under Servers > Edit. ' +
        'If not, someone may be intercepting connections to it: do not accept the new key.' +
        footer,
    };
  },
  securityNotice(p: { to: string; displayName: string; what: string }): MailMessage {
    return {
      to: p.to,
      subject: `Any-SSH security notice: ${p.what}`,
      text: `Hi ${p.displayName},\n\nThis is a notice that on your Any-SSH account: ${p.what}.\n\nIf this was you, no action is needed.` + footer,
    };
  },
};
