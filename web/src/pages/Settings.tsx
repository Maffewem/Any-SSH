import { useState } from 'react';
import { del, errorMessage, formatTime, get, post, put, type SettingsView } from '../api';
import { Field, Form, SubTabs, useAsync, useConfirm, useRememberedTab, useToast } from '../ui';
import { BackupSection } from './Backups';
import { JumpHostsSection } from './JumpHosts';
import { VersionCard } from './Version';

function SourceBadge({ source }: { source: 'environment' | 'web' }) {
  return source === 'web' ? <span className="badge accent">Customized</span> : <span className="badge">Default</span>;
}

function ResetButton({ group, source, onDone }: { group: string; source: 'environment' | 'web'; onDone: (s: SettingsView, reset: true) => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  if (source !== 'web') return null;
  return (
    <button
      className="ghost small"
      onClick={async () => {
        const ok = await confirm({
          title: 'Restore default settings?',
          message: 'Your changes to these settings will be discarded and the defaults will be used again.',
          confirmLabel: 'Restore defaults',
          danger: true,
        });
        if (!ok) return;
        onDone(await del<SettingsView>(`/api/admin/settings/${group}`), true);
        toast.success('Default settings restored.');
      }}
    >
      Restore defaults
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

  const [tab, choose] = useRememberedTab<TabId>('settings-tab', TABS.map((t) => t.id), 'security');

  return (
    <section>
      <div className="page-head">
        <h1>Settings</h1>
      </div>
      <SubTabs label="Settings sections" tabs={TABS} current={tab} onChoose={choose} />
      <p className="muted small">{TABS.find((t) => t.id === tab)?.blurb} Changes take effect as soon as you save them.</p>
      {error && <p className="error">{error}</p>}
      {current && (
        <>
          {tab === 'security' && (
            <>
              <SessionSection key={`sessions-${resets}`} view={current} onSaved={onSaved} />
              <SecuritySection key={`security-${resets}`} view={current} onSaved={onSaved} />
            </>
          )}
          {tab === 'access' && <JumpHostsSection />}
          {tab === 'limits' && <LimitsSection key={`limits-${resets}`} view={current} onSaved={onSaved} />}
          {tab === 'backups' && <BackupSection key={`backup-${resets}`} view={current} onSaved={onSaved} />}
          {tab === 'updates' && (
            <>
              <VersionCard />
              <MaintenanceSection key={`maintenance-${resets}`} view={current} onSaved={onSaved} />
            </>
          )}
          {tab === 'notifications' && <MailSection key={`mail-${resets}`} view={current} onSaved={onSaved} />}
        </>
      )}
    </section>
  );
}

const TABS = [
  { id: 'security', label: 'Security', blurb: 'Session timeouts and protection against repeated failed sign-in attempts.' },
  { id: 'access', label: 'Access', blurb: 'Jump hosts that servers can connect through.' },
  { id: 'limits', label: 'Limits', blurb: 'Usage limits for each type of account.' },
  { id: 'backups', label: 'Backups', blurb: 'Where Any-SSH backups are stored, how often they run and how they’re encrypted.' },
  { id: 'updates', label: 'Updates', blurb: 'The installed version, update checks and the maintenance window.' },
  { id: 'notifications', label: 'Email', blurb: 'Email settings for invitations, password resets and security alerts.' },
] as const;
type TabId = (typeof TABS)[number]['id'];

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
  const toast = useToast();
  const destinationChanged = host !== m.host || username !== m.username;

  return (
    <div className="card settings-section">
      <div className="page-head">
        <h2>
          Email (SMTP) <SourceBadge source={m.source} />
        </h2>
        <ResetButton group="mail" source={m.source} onDone={onSaved} />
      </div>
      <p className="muted small">If email isn’t set up, messages are written to the server log instead.</p>
      <Form
        submit="Save email settings"
        success="Email settings saved."
        onSubmit={async () => {
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
        }}
      >
        <label className="check">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Send email using an SMTP server
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
            <Field label="Encryption" hint="Unencrypted SMTP isn’t supported because emailed links can be used to sign in.">
              <select value={security} onChange={(e) => setSecurity(e.target.value as 'tls' | 'starttls')}>
                <option value="starttls">STARTTLS (usually port 587)</option>
                <option value="tls">TLS (usually port 465)</option>
              </select>
            </Field>
            <Field label="Username" hint="Leave blank if the server doesn’t require sign-in.">
              <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
            </Field>
            <Field
              label="Password"
              hint={
                m.hasPassword && !destinationChanged
                  ? 'A password is saved. Leave blank to keep it.'
                  : m.hasPassword
                    ? 'If you change the server or username, you’ll need to enter the password again.'
                    : 'Stored encrypted and never shown again.'
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
        <Field label="Sender address" hint='For example: Any-SSH <any-ssh@example.com>'>
          <input value={from} onChange={(e) => setFrom(e.target.value)} required />
        </Field>
      </Form>

      <div className="subsection">
        <h3>Send a test email</h3>
        <p className="muted small">Leave blank to send it to yourself.</p>
        <div className="row wrap">
          <input type="email" value={testTo} onChange={(e) => setTestTo(e.target.value)} placeholder="you@example.com" style={{ maxWidth: 320 }} />
          <button
            onClick={async () => {
              try {
                const r = await post<{ sent: boolean; to: string }>('/api/admin/settings/mail/test', testTo ? { to: testTo } : {});
                toast.success(r.sent ? `Test email sent to ${r.to}. Check your inbox and spam folder.` : 'Email isn’t turned on, so the message was written to the server log.');
              } catch (e) {
                toast.error(errorMessage(e));
              }
            }}
          >
            Send test email
          </button>
        </div>
      </div>
    </div>
  );
}

function SessionSection({ view, onSaved }: { view: SettingsView; onSaved: (s: SettingsView, reset?: true) => void }) {
  const s = view.sessions;
  const [lockMinutes, setLock] = useState(String(s.lockMinutes));
  const [idleMinutes, setIdle] = useState(String(s.idleMinutes));
  const [maxHours, setMax] = useState(String(s.maxHours));
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
        success="Session settings saved."
        onSubmit={async () => {
          onSaved(
            await put<SettingsView>('/api/admin/settings/sessions', {
              lockMinutes: Number(lockMinutes),
              idleMinutes: Number(idleMinutes),
              maxHours: Number(maxHours),
            }),
          );
        }}
      >
        <Field
          label="Lock after (minutes of inactivity)"
          hint="The screen is hidden and terminals pause until the user enters their password again. A 2-step verification code isn’t required. Enter 0 to turn off locking."
        >
          <input value={lockMinutes} onChange={(e) => setLock(e.target.value)} inputMode="numeric" required />
        </Field>
        <Field label="Sign out after (minutes of inactivity)" hint="Ends the session and closes its terminals. This must be longer than the lock time.">
          <input value={idleMinutes} onChange={(e) => setIdle(e.target.value)} inputMode="numeric" required />
        </Field>
        <Field label="Maximum session length (hours)" hint="Users must sign in again, including 2-step verification, after this time even if they’re active. Applies to new sign-ins.">
          <input value={maxHours} onChange={(e) => setMax(e.target.value)} inputMode="numeric" required />
        </Field>
      </Form>
    </div>
  );
}

function LimitsSection({ view, onSaved }: { view: SettingsView; onSaved: (s: SettingsView, reset?: true) => void }) {
  const l = view.limits;
  const d = l.defaults;
  const [max, setMax] = useState(String(l.maxTerminalsPerUser));
  const [adminSame, setAdminSame] = useState(l.maxTerminalsPerAdmin === null);
  const [adminMax, setAdminMax] = useState(String(l.maxTerminalsPerAdmin ?? l.maxTerminalsPerUser));
  const [detach, setDetach] = useState(String(l.detachMinutes));
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
  return (
    <div className="card settings-section">
      <div className="page-head">
        <h2>
          Usage limits <SourceBadge source={l.source} />
        </h2>
        <ResetButton group="limits" source={l.source} onDone={onSaved} />
      </div>
      <p className="muted small">
        Limits apply to each person. Administrators can have their own terminal limit. The reconnect window is the same for all accounts. Changes apply to terminals opened or disconnected from now on. Terminals that are already open aren’t closed.
      </p>
      <Form
        submit="Save limits"
        success="Limits saved."
        onSubmit={async () => {
          onSaved(
            await put<SettingsView>('/api/admin/settings/limits', {
              maxTerminalsPerUser: Number(max),
              maxTerminalsPerAdmin: adminSame ? null : Number(adminMax),
              detachMinutes: Number(detach),
            }),
          );
        }}
      >
        <div className="table-wrap">
          <table className="limits-table">
            <thead>
              <tr>
                <th scope="col">Limit</th>
                <th scope="col">Standard users</th>
                <th scope="col">Administrators</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <th scope="row">
                  <strong>Open terminals at once</strong>
                  <small>
                    The most terminals one person can have open at the same time across all their devices, including terminals waiting to reconnect. When the limit is reached, they can’t open another until they close one. Enter a number from 1 to 100.
                  </small>
                </th>
                <td data-label="Standard users">
                  <label className="limit-input">
                    <input
                      value={max}
                      onChange={(e) => setMax(e.target.value)}
                      inputMode="numeric"
                      required
                      aria-label="Open terminals at once, standard users"
                    />
                    <span>terminals</span>
                  </label>
                  <small>Default: {plural(d.maxTerminalsPerUser, 'terminal', 'terminals')}</small>
                </td>
                <td data-label="Administrators">
                  <select
                    value={adminSame ? 'same' : 'custom'}
                    onChange={(e) => setAdminSame(e.target.value === 'same')}
                    aria-label="Administrator terminal limit"
                  >
                    <option value="same">Same as standard users</option>
                    <option value="custom">Set a separate limit</option>
                  </select>
                  {adminSame ? (
                    <small>Currently {plural(Number(max) || 0, 'terminal', 'terminals')}</small>
                  ) : (
                    <label className="limit-input">
                      <input
                        value={adminMax}
                        onChange={(e) => setAdminMax(e.target.value)}
                        inputMode="numeric"
                        required
                        aria-label="Open terminals at once, administrators"
                      />
                      <span>terminals</span>
                    </label>
                  )}
                  <small>Default: same as standard users</small>
                </td>
              </tr>
              <tr>
                <th scope="row">
                  <strong>Reconnect window</strong>
                  <small>
                    If the browser loses its connection, for example when a laptop is closed or a mobile signal drops, the SSH session stays open for this long so you can pick up where you left off. After that, it’s closed. Enter 0 to close it immediately. Signing out, session expiry and removed access always close it immediately.
                  </small>
                </th>
                <td data-label="All accounts" colSpan={2}>
                  <label className="limit-input">
                    <input value={detach} onChange={(e) => setDetach(e.target.value)} inputMode="numeric" required aria-label="Reconnect window in minutes" />
                    <span>minutes</span>
                  </label>
                  <small>Applies to all accounts. Default: {plural(d.detachMinutes, 'minute', 'minutes')}. Maximum: 1440 (24 hours).</small>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </Form>
    </div>
  );
}

function SecuritySection({ view, onSaved }: { view: SettingsView; onSaved: (s: SettingsView, reset?: true) => void }) {
  const toast = useToast();
  const b = view.security;
  const [accountThreshold, setAccount] = useState(String(b.accountThreshold));
  const [ipThreshold, setIp] = useState(String(b.ipThreshold));
  const [windowMinutes, setWindow] = useState(String(b.windowMinutes));
  const [lockoutMinutes, setLockout] = useState(String(b.lockoutMinutes));
  const [notifyOwner, setNotify] = useState(b.notifyOwner);
  const lockouts = useAsync(() => get<{ ips: { ip: string; lockedUntil: number; failures: number }[] }>('/api/admin/lockouts'), [view]);
  const [unlocked, setUnlocked] = useState<string[]>([]);
  const ips = (lockouts.data?.ips ?? []).filter((l) => !unlocked.includes(l.ip));
  return (
    <div className="card settings-section">
      <div className="page-head">
        <h2>
          Protection against failed sign-ins <SourceBadge source={b.source} />
        </h2>
        <ResetButton group="security" source={b.source} onDone={onSaved} />
      </div>
      <p className="muted small">
        Incorrect passwords, 2-step verification codes, unlock passwords and reset links are counted. Too many failed attempts on one account locks that account. Too many from one IP address blocks that address from signing in. The count starts again after each lockout.
      </p>
      <Form
        submit="Save changes"
        success="Settings saved."
        onSubmit={async () => {
          onSaved(
            await put<SettingsView>('/api/admin/settings/security', {
              accountThreshold: Number(accountThreshold),
              ipThreshold: Number(ipThreshold),
              windowMinutes: Number(windowMinutes),
              lockoutMinutes: Number(lockoutMinutes),
              notifyOwner,
            }),
          );
        }}
      >
        <Field label="Lock an account after (failed attempts)" hint="Attempts are counted within the time period below. Minimum: 3.">
          <input value={accountThreshold} onChange={(e) => setAccount(e.target.value)} inputMode="numeric" required />
        </Field>
        <Field label="Block an IP address after (failed attempts)" hint="Counted across all accounts, which also catches password spraying. Set this higher than the account limit.">
          <input value={ipThreshold} onChange={(e) => setIp(e.target.value)} inputMode="numeric" required />
        </Field>
        <Field label="Time period for counting attempts (minutes)">
          <input value={windowMinutes} onChange={(e) => setWindow(e.target.value)} inputMode="numeric" required />
        </Field>
        <Field label="Lockout duration (minutes)" hint="Administrators can unlock an account or IP address sooner.">
          <input value={lockoutMinutes} onChange={(e) => setLockout(e.target.value)} inputMode="numeric" required />
        </Field>
        <label className="check">
          <input type="checkbox" checked={notifyOwner} onChange={(e) => setNotify(e.target.checked)} /> Email users when their account is locked
        </label>
      </Form>
      <div className="subsection">
        <h3>Blocked IP addresses</h3>
        {ips.length === 0 ? (
          <p className="muted small">No IP addresses are blocked right now. To unlock an account, go to the Users page.</p>
        ) : (
          <ul style={{ listStyle: "none", padding: 0 }}>
            {ips.map((l) => (
              <li key={l.ip} className="row wrap">
                <span className="mono">{l.ip}</span>
                <span className="muted small">Blocked until {formatTime(l.lockedUntil)} after {l.failures} failed attempts</span>
                <button
                  className="small"
                  onClick={async () => {
                    await del(`/api/admin/lockouts/ip/${encodeURIComponent(l.ip)}`);
                    setUnlocked((u) => [...u, l.ip]);
                    toast.success(`${l.ip} unblocked.`);
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

const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

function MaintenanceSection({ view, onSaved }: { view: SettingsView; onSaved: (s: SettingsView, reset?: true) => void }) {
  const m = view.maintenance;
  const [enabled, setEnabled] = useState(m.enabled);
  const [days, setDays] = useState<number[]>(m.days);
  const [start, setStart] = useState(m.start);
  const [duration, setDuration] = useState(String(m.durationMinutes));
  const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const [timezone, setTimezone] = useState(m.source === 'web' ? m.timezone : browserZone || m.timezone);
  return (
    <div className="card settings-section">
      <div className="page-head">
        <h2>
          Maintenance window <SourceBadge source={m.source} />
        </h2>
        <ResetButton group="maintenance" source={m.source} onDone={onSaved} />
      </div>
      <p className="muted small">
        Choose when automatic updates can be installed. Outside this window, new versions are only flagged as available. “Update now” ignores the window.
      </p>
      <Form
        submit="Save changes"
        success="Maintenance window saved."
        onSubmit={async () => {
          onSaved(await put<SettingsView>('/api/admin/settings/maintenance', { enabled, days, start, durationMinutes: Number(duration), timezone: timezone.trim() }));
        }}
      >
        <label className="check">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Only install automatic updates during this window
        </label>
        <Field label="Days of the week">
          <div>
            {DAY_NAMES.map((name, i) => (
              <label key={name} className="check" style={{ marginRight: 12 }}>
                <input type="checkbox" checked={days.includes(i)} onChange={(e) => setDays(e.target.checked ? [...days, i] : days.filter((d) => d !== i))} />{' '}
                {name.slice(0, 3)}
              </label>
            ))}
          </div>
        </Field>
        <Field label="Start time (24-hour)">
          <input value={start} onChange={(e) => setStart(e.target.value)} placeholder="04:00" required />
        </Field>
        <Field label="Duration (minutes)">
          <input value={duration} onChange={(e) => setDuration(e.target.value)} inputMode="numeric" required />
        </Field>
        <Field label="Time zone" hint="For example, Europe/London or America/New_York. Daylight saving time is applied automatically.">
          <input value={timezone} onChange={(e) => setTimezone(e.target.value)} required />
        </Field>
      </Form>
    </div>
  );
}
