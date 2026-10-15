import { useState } from 'react';
import { del, errorMessage, formatTime, get, post, put, type SettingsView } from '../api';
import { Field, Form, useAsync } from '../ui';
import { BackupSection } from './Backups';
import { JumpHostsSection } from './JumpHosts';
import { VersionCard } from './Version';

function SourceBadge({ source }: { source: 'environment' | 'web' }) {
  return source === 'web' ? <span className="badge accent">Set here</span> : <span className="badge">Server default</span>;
}

function ResetButton({ group, source, onDone }: { group: string; source: 'environment' | 'web'; onDone: (s: SettingsView, reset: true) => void }) {
  if (source !== 'web') return null;
  return (
    <button className="ghost small" onClick={async () => onDone(await del<SettingsView>(`/api/admin/settings/${group}`), true)}>
      Reset to server default
    </button>
  );
}

export function SettingsPage() {
  const { data, error } = useAsync(() => get<SettingsView>('/api/admin/settings'), []);
  const [view, setView] = useState<SettingsView | null>(null);
  // Bumped on reset so the forms reload the defaults; a normal save keeps what was typed.
  const [resets, setResets] = useState(0);
  const current = view ?? data;
  const onSaved = (s: SettingsView, reset?: true) => {
    setView(s);
    if (reset) setResets((n) => n + 1);
  };

  return (
    <section>
      <div className="page-head">
        <h1>Settings</h1>
      </div>
      <p className="muted small">
        Changes apply straight away and are recorded in the audit log. “Server default” means the value comes from the server’s
        environment file; resetting returns to it. The domain, master key and other startup settings can only be changed on the server.
      </p>
      {error && <p className="error">{error}</p>}
      {current && (
        <>
          <MailSection key={`mail-${resets}`} view={current} onSaved={onSaved} />
          <SessionSection key={`sessions-${resets}`} view={current} onSaved={onSaved} />
          <LimitsSection key={`limits-${resets}`} view={current} onSaved={onSaved} />
          <JumpHostsSection />
          <SecuritySection key={`security-${resets}`} view={current} onSaved={onSaved} />
          <BackupSection key={`backup-${resets}`} view={current} onSaved={onSaved} />
          <VersionCard />
        </>
      )}
    </section>
  );
}

function MailSection({ view, onSaved }: { view: SettingsView; onSaved: (s: SettingsView, reset?: true) => void }) {
  const m = view.mail;
  const [enabled, setEnabled] = useState(m.enabled);
  const [host, setHost] = useState(m.host);
  const [port, setPort] = useState(String(m.port));
  const [security, setSecurity] = useState(m.security);
  const [username, setUsername] = useState(m.username);
  const [password, setPassword] = useState('');
  const [clearPassword, setClearPassword] = useState(false);
  const [from, setFrom] = useState(m.from);
  const [testTo, setTestTo] = useState('');
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [saved, setSaved] = useState(false);
  const destinationChanged = host !== m.host || username !== m.username;

  return (
    <div className="card settings-section">
      <div className="page-head">
        <h2>
          Email (SMTP) <SourceBadge source={m.source} />
        </h2>
        <ResetButton group="mail" source={m.source} onDone={onSaved} />
      </div>
      <p className="muted small">Used for invites, password resets and security notices. Without it, emails are written to the server log.</p>
      <Form
        submit="Save email settings"
        onSubmit={async () => {
          setSaved(false);
          const body = {
            enabled,
            ...(host.trim() ? { host: host.trim() } : {}),
            port: Number(port),
            security,
            ...(username.trim() ? { username: username.trim() } : {}),
            ...(password ? { password } : clearPassword ? { password: '' } : {}),
            from,
          };
          onSaved(await put<SettingsView>('/api/admin/settings/mail', body));
          setPassword('');
          setClearPassword(false);
          setSaved(true);
        }}
      >
        <label className="check">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Send email over SMTP
        </label>
        {enabled && (
          <>
            <div className="row2">
              <Field label="SMTP server">
                <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="smtp.example.com" autoComplete="off" required />
              </Field>
              <Field label="Port">
                <input
                  value={port}
                  onChange={(e) => {
                    setPort(e.target.value);
                    if (e.target.value === '465') setSecurity('tls');
                    if (e.target.value === '587') setSecurity('starttls');
                  }}
                  inputMode="numeric"
                  required
                />
              </Field>
            </div>
            <Field label="Encryption" hint="Plain, unencrypted SMTP is not offered: email links are credentials.">
              <select value={security} onChange={(e) => setSecurity(e.target.value as 'tls' | 'starttls')}>
                <option value="starttls">STARTTLS (usually port 587)</option>
                <option value="tls">TLS (usually port 465)</option>
              </select>
            </Field>
            <Field label="Username" hint="Leave empty if the server needs no login.">
              <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
            </Field>
            <Field
              label="Password"
              hint={
                m.hasPassword && !destinationChanged
                  ? 'A password is saved. Leave empty to keep it.'
                  : m.hasPassword
                    ? 'Changing the server or username removes the saved password, so enter it again.'
                    : 'Stored encrypted; never shown again.'
              }
            >
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                placeholder={m.hasPassword && !destinationChanged ? '••••••••' : ''}
              />
            </Field>
            {m.hasPassword && !destinationChanged && !password && (
              <label className="check">
                <input type="checkbox" checked={clearPassword} onChange={(e) => setClearPassword(e.target.checked)} /> Remove the saved password
              </label>
            )}
          </>
        )}
        <Field label="Send from" hint='For example: Any-SSH <any-ssh@example.com>'>
          <input value={from} onChange={(e) => setFrom(e.target.value)} required />
        </Field>
        {saved && <p className="ok">Saved.</p>}
      </Form>

      <div className="subsection">
        <h3>Send a test email</h3>
        <p className="muted small">Uses the saved settings. Leave the address empty to send it to yourself.</p>
        <div className="row wrap">
          <input type="email" value={testTo} onChange={(e) => setTestTo(e.target.value)} placeholder="you@example.com" style={{ maxWidth: 320 }} />
          <button
            onClick={async () => {
              setTestResult(null);
              try {
                const r = await post<{ sent: boolean; to: string }>('/api/admin/settings/mail/test', testTo ? { to: testTo } : {});
                setTestResult({
                  ok: true,
                  text: r.sent ? `Sent to ${r.to}. Check the inbox (and spam folder).` : 'SMTP is off, so the message was written to the server log.',
                });
              } catch (e) {
                setTestResult({ ok: false, text: errorMessage(e) });
              }
            }}
          >
            Send test
          </button>
        </div>
        {testResult && <p className={testResult.ok ? 'ok' : 'error'}>{testResult.text}</p>}
      </div>
    </div>
  );
}

function SessionSection({ view, onSaved }: { view: SettingsView; onSaved: (s: SettingsView, reset?: true) => void }) {
  const s = view.sessions;
  const [lockMinutes, setLock] = useState(String(s.lockMinutes));
  const [idleMinutes, setIdle] = useState(String(s.idleMinutes));
  const [maxHours, setMax] = useState(String(s.maxHours));
  const [saved, setSaved] = useState(false);
  return (
    <div className="card settings-section">
      <div className="page-head">
        <h2>
          Sessions <SourceBadge source={s.source} />
        </h2>
        <ResetButton group="sessions" source={s.source} onDone={onSaved} />
      </div>
      <Form
        submit="Save session settings"
        onSubmit={async () => {
          setSaved(false);
          onSaved(
            await put<SettingsView>('/api/admin/settings/sessions', {
              lockMinutes: Number(lockMinutes),
              idleMinutes: Number(idleMinutes),
              maxHours: Number(maxHours),
            }),
          );
          setSaved(true);
        }}
      >
        <Field
          label="Lock after (minutes idle)"
          hint="The screen is hidden and terminals pause until the user re-enters their password. No 2FA code is needed. 0 turns locking off."
        >
          <input value={lockMinutes} onChange={(e) => setLock(e.target.value)} inputMode="numeric" required />
        </Field>
        <Field label="Sign out after (minutes idle)" hint="Ends the session entirely, closing its terminals. Must be longer than the lock.">
          <input value={idleMinutes} onChange={(e) => setIdle(e.target.value)} inputMode="numeric" required />
        </Field>
        <Field label="Maximum session length (hours)" hint="Sign-in, with 2FA, is needed again after this however active the user is. Applies to new sign-ins.">
          <input value={maxHours} onChange={(e) => setMax(e.target.value)} inputMode="numeric" required />
        </Field>
        {saved && <p className="ok">Saved.</p>}
      </Form>
    </div>
  );
}

function LimitsSection({ view, onSaved }: { view: SettingsView; onSaved: (s: SettingsView, reset?: true) => void }) {
  const l = view.limits;
  const [max, setMax] = useState(String(l.maxTerminalsPerUser));
  const [detach, setDetach] = useState(String(l.detachMinutes));
  const [saved, setSaved] = useState(false);
  return (
    <div className="card settings-section">
      <div className="page-head">
        <h2>
          Limits <SourceBadge source={l.source} />
        </h2>
        <ResetButton group="limits" source={l.source} onDone={onSaved} />
      </div>
      <Form
        submit="Save limits"
        onSubmit={async () => {
          setSaved(false);
          onSaved(await put<SettingsView>('/api/admin/settings/limits', { maxTerminalsPerUser: Number(max), detachMinutes: Number(detach) }));
          setSaved(true);
        }}
      >
        <Field label="Open terminals per user">
          <input value={max} onChange={(e) => setMax(e.target.value)} inputMode="numeric" required />
        </Field>
        <Field
          label="Keep a terminal after the browser drops (minutes)"
          hint="The SSH session stays open this long so the browser can pick up where it left off. 0 closes it straight away. Logging out, expiry and removed access still end it at once."
        >
          <input value={detach} onChange={(e) => setDetach(e.target.value)} inputMode="numeric" required />
        </Field>
        {saved && <p className="ok">Saved.</p>}
      </Form>
    </div>
  );
}

function SecuritySection({ view, onSaved }: { view: SettingsView; onSaved: (s: SettingsView, reset?: true) => void }) {
  const b = view.security;
  const [accountThreshold, setAccount] = useState(String(b.accountThreshold));
  const [ipThreshold, setIp] = useState(String(b.ipThreshold));
  const [windowMinutes, setWindow] = useState(String(b.windowMinutes));
  const [lockoutMinutes, setLockout] = useState(String(b.lockoutMinutes));
  const [notifyOwner, setNotify] = useState(b.notifyOwner);
  const [saved, setSaved] = useState(false);
  const lockouts = useAsync(() => get<{ ips: { ip: string; lockedUntil: number; failures: number }[] }>('/api/admin/lockouts'), [view]);
  const [unlocked, setUnlocked] = useState<string[]>([]);
  const ips = (lockouts.data?.ips ?? []).filter((l) => !unlocked.includes(l.ip));
  return (
    <div className="card settings-section">
      <div className="page-head">
        <h2>
          Brute-force protection <SourceBadge source={b.source} />
        </h2>
        <ResetButton group="security" source={b.source} onDone={onSaved} />
      </div>
      <p className="muted small">
        Wrong passwords, 2FA codes, unlock passwords, reset links and re-entered passwords are counted. Too many on one account locks that
        account; too many from one address blocks that address from signing in. Counters restart after each lockout.
      </p>
      <Form
        submit="Save protection settings"
        onSubmit={async () => {
          setSaved(false);
          onSaved(
            await put<SettingsView>('/api/admin/settings/security', {
              accountThreshold: Number(accountThreshold),
              ipThreshold: Number(ipThreshold),
              windowMinutes: Number(windowMinutes),
              lockoutMinutes: Number(lockoutMinutes),
              notifyOwner,
            }),
          );
          setSaved(true);
        }}
      >
        <Field label="Lock an account after (failed attempts)" hint="Counted within the window below. Minimum 3.">
          <input value={accountThreshold} onChange={(e) => setAccount(e.target.value)} inputMode="numeric" required />
        </Field>
        <Field label="Block an address after (failed attempts)" hint="Across all accounts, so password spraying is caught too. Keep this above the account value.">
          <input value={ipThreshold} onChange={(e) => setIp(e.target.value)} inputMode="numeric" required />
        </Field>
        <Field label="Counting window (minutes)">
          <input value={windowMinutes} onChange={(e) => setWindow(e.target.value)} inputMode="numeric" required />
        </Field>
        <Field label="Lockout length (minutes)" hint="Admins can unlock an account or address sooner.">
          <input value={lockoutMinutes} onChange={(e) => setLockout(e.target.value)} inputMode="numeric" required />
        </Field>
        <label className="check">
          <input type="checkbox" checked={notifyOwner} onChange={(e) => setNotify(e.target.checked)} /> Email the account owner when their account is locked
        </label>
        {saved && <p className="ok">Saved.</p>}
      </Form>
      <div className="subsection">
        <h3>Blocked addresses</h3>
        {ips.length === 0 ? (
          <p className="muted small">None right now. Locked accounts are unlocked from the Users page.</p>
        ) : (
          <ul style={{ listStyle: "none", padding: 0 }}>
            {ips.map((l) => (
              <li key={l.ip} className="row wrap">
                <span className="mono">{l.ip}</span>
                <span className="muted small">until {formatTime(l.lockedUntil)} after {l.failures} failures</span>
                <button
                  className="small"
                  onClick={async () => {
                    await del(`/api/admin/lockouts/ip/${encodeURIComponent(l.ip)}`);
                    setUnlocked((u) => [...u, l.ip]);
                  }}
                >
                  Unblock
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
