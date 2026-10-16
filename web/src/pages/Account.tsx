import QRCode from 'qrcode';
import { useState } from 'react';
import { del, errorMessage, formatTime, get, patch, post, put, type User } from '../api';
import { Field, Form, SecretOnce, SubTabs, useAsync, useConfirm, useRememberedTab, useToast } from '../ui';
import { ChangePasswordForm } from './Auth';
import { DeleteAccountForm } from './DeleteAccount';

interface SessionInfo {
  id: string;
  current: boolean;
  createdAt: number;
  lastSeenAt: number;
  ip: string | null;
  userAgent: string | null;
}

const TABS = [
  { id: 'profile', label: 'Profile', blurb: 'Your name, email address and role.' },
  { id: 'security', label: 'Security', blurb: 'Password, two-factor authentication and trusted networks.' },
  { id: 'devices', label: 'Devices', blurb: 'Browsers and apps currently signed in to your account.' },
  { id: 'delete', label: 'Delete account', blurb: 'Permanently remove your account and the data it owns.' },
] as const;
type TabId = (typeof TABS)[number]['id'];

export function AccountPage({ user, onUserChange }: { user: User; onUserChange: (u: User) => void }) {
  const [passwordDone, setPasswordDone] = useState<number | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [tab, choose] = useRememberedTab<TabId>('account-tab', TABS.map((t) => t.id), 'profile');
  return (
    <section>
      <div className="page-head">
        <h1>Account</h1>
      </div>
      <SubTabs label="Account sections" tabs={TABS} current={tab} onChoose={choose} />
      <p className="muted small">{TABS.find((t) => t.id === tab)?.blurb}</p>
      {tab === 'profile' && (
        <div className="card settings-section">
          <h2>Profile</h2>
          <p className="muted">
            @{user.username} · {user.role === 'admin' ? 'Administrator' : 'User'}
          </p>
          <ProfileForm user={user} onUserChange={onUserChange} />
        </div>
      )}
      {tab === 'security' && (
        <>
          <div className="card settings-section">
            <h2>Password</h2>
            {passwordDone !== null && (
              <p className="ok">
                Password changed. {passwordDone > 0 ? `${passwordDone} other ${passwordDone === 1 ? 'device was' : 'devices were'} signed out.` : 'No other devices were signed in.'}
              </p>
            )}
            <ChangePasswordForm onDone={(u, n) => (setPasswordDone(n ?? 0), onUserChange(u))} />
          </div>
          <div className="card settings-section">
            <h2>Two-factor authentication</h2>
            <MfaSection user={user} onChange={async () => onUserChange((await get<{ user: User }>('/api/auth/me')).user)} />
          </div>
          <div className="card settings-section">
            <h2>Trusted IP addresses</h2>
            <TrustedIps user={user} />
          </div>
        </>
      )}
      {tab === 'devices' && (
        <div className="card settings-section">
          <h2>Signed-in devices</h2>
          <Sessions />
        </div>
      )}
      {tab === 'delete' && (
        <div className="card settings-section">
          <h2>Delete account</h2>
          {deleting ? (
            <DeleteAccountForm self username={user.username} mfaEnabled={user.mfaEnabled} onDeleted={() => window.location.reload()} />
          ) : (
            <>
              <p className="muted">Permanently removes your account, SSH keys and servers. You will be asked how to handle servers shared with other people.</p>
              <button className="danger-outline" onClick={() => setDeleting(true)}>
                Delete my account…
              </button>
            </>
          )}
        </div>
      )}
    </section>
  );
}

function ProfileForm({ user, onUserChange }: { user: User; onUserChange: (u: User) => void }) {
  const [displayName, setDisplayName] = useState(user.displayName);
  const [email, setEmail] = useState(user.email ?? '');
  const [password, setPassword] = useState('');
  const emailChanging = email.trim().toLowerCase() !== (user.email ?? '').toLowerCase();
  return (
    <Form
      submit="Save profile"
      success="Profile saved."
      onSubmit={async () => {
        const res = await patch<{ user: User }>('/api/auth/profile', {
          displayName,
          ...(emailChanging ? { email: email.trim() || null, password } : {}),
        });
        setPassword('');
        onUserChange(res.user);
      }}
    >
      <Field label="Display name">
        <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} required />
      </Field>
      <Field label="Email" hint="Used for password reset links and security notices.">
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
      </Field>
      {emailChanging && (
        <Field label="Current password" hint="Needed to change where reset links are sent.">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </Field>
      )}
    </Form>
  );
}

function MfaSection({ user, onChange }: { user: User; onChange: () => Promise<void> }) {
  const [stage, setStage] = useState<'idle' | 'password' | 'scan' | 'disable' | 'regenerate'>('idle');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [enrol, setEnrol] = useState<{ secret: string; qr: string } | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const toast = useToast();

  const reset = () => (setStage('idle'), setPassword(''), setCode(''), setEnrol(null));

  if (recoveryCodes) {
    return (
      <div>
        <SecretOnce label="Save these recovery codes somewhere safe. Each works once if you lose your phone." value={recoveryCodes.join('\n')} />
        <button onClick={() => setRecoveryCodes(null)}>I have saved them</button>
      </div>
    );
  }

  if (user.mfaEnabled) {
    if (stage === 'disable' || stage === 'regenerate') {
      return (
        <Form
          submit={stage === 'disable' ? 'Turn off two-factor' : 'Generate new codes'}
          danger={stage === 'disable'}
          onSubmit={async () => {
            if (stage === 'disable') {
              await post('/api/auth/mfa/disable', { password, code });
              toast.success('Two-factor authentication turned off.');
              reset();
              await onChange();
            } else {
              const res = await post<{ recoveryCodes: string[] }>('/api/auth/mfa/recovery-codes', { password, code });
              toast.success('New recovery codes generated. The old ones no longer work.');
              reset();
              setRecoveryCodes(res.recoveryCodes);
            }
          }}
        >
          <Field label="Password">
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
          </Field>
          <Field label="Current 6-digit code">
            <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required />
          </Field>
          <button type="button" className="ghost" onClick={reset}>
            Cancel
          </button>
        </Form>
      );
    }
    return (
      <div>
        <p className="ok">On. You’ll be asked for a code from your authenticator app when you sign in.</p>
        <div className="row">
          <button onClick={() => setStage('regenerate')}>New recovery codes</button>
          <button className="danger-outline" onClick={() => setStage('disable')}>
            Turn off
          </button>
        </div>
      </div>
    );
  }

  if (stage === 'idle') {
    return (
      <div>
        <p className="muted">Protect your account with an authenticator app (1Password, Authy, Google Authenticator, iOS Passwords…).</p>
        <button className="primary" onClick={() => setStage('password')}>
          Set up two-factor
        </button>
      </div>
    );
  }

  if (stage === 'password') {
    return (
      <Form
        submit="Continue"
        onSubmit={async () => {
          const res = await post<{ secret: string; uri: string }>('/api/auth/mfa/setup', { password });
          setPassword('');
          setEnrol({ secret: res.secret, qr: await QRCode.toDataURL(res.uri, { margin: 1, width: 220 }) });
          setStage('scan');
        }}
      >
        <Field label="Confirm your password">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required autoFocus />
        </Field>
      </Form>
    );
  }

  return (
    <div>
      <p>Scan this with your authenticator app, then enter the code it shows.</p>
      {enrol && (
        <div className="mfa-enrol">
          <img src={enrol.qr} alt="Authenticator QR code" width={220} height={220} />
          <p className="small muted">
            Can’t scan? Enter this key: <code className="mono">{enrol.secret}</code>
          </p>
        </div>
      )}
      <Form
        submit="Turn on"
        onSubmit={async () => {
          const res = await post<{ recoveryCodes: string[] }>('/api/auth/mfa/enable', { code });
          toast.success('Two-factor authentication turned on.');
          reset();
          setRecoveryCodes(res.recoveryCodes);
          await onChange();
        }}
      >
        <Field label="6-digit code">
          <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required />
        </Field>
      </Form>
    </div>
  );
}

interface TrustedIpState {
  enabled: boolean;
  policy: 'notify' | 'challenge';
  currentIp: string | null;
  currentIpTrusted: boolean;
  canChallenge: boolean;
  entries: { id: string; cidr: string; label: string; createdAt: number }[];
}

function TrustedIps({ user }: { user: User }) {
  const { data, reload } = useAsync(() => get<TrustedIpState>('/api/account/trusted-ips'), [user.email, user.mfaEnabled]);
  const [cidr, setCidr] = useState('');
  const [label, setLabel] = useState('');
  const [policy, setPolicy] = useState<'notify' | 'challenge' | null>(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();
  if (!data) return <p className="muted">Loading…</p>;
  const chosen = policy ?? data.policy;
  const run = async (fn: () => Promise<unknown>, done: string) => {
    setError(null);
    try {
      await fn();
      toast.success(done);
      setCidr('');
      setLabel('');
      reload();
    } catch (err) {
      setError(errorMessage(err));
    }
  };
  return (
    <div className="stack">
      <p className="muted">
        List the networks you normally sign in from. When this is on, a sign-in or an active session from any other address is
        either allowed with a notification or held until it is verified. Your address as the server sees it:{' '}
        <code className="mono">{data.currentIp ?? 'unknown'}</code> {data.currentIpTrusted ? <span className="badge accent">trusted</span> : <span className="badge warn">not listed</span>}
      </p>
      <ul className="list">
        {data.entries.map((e) => (
          <li key={e.id}>
            <span>
              <code className="mono">{e.cidr}</code>
              {e.label && <span className="muted small"> · {e.label}</span>}
            </span>
            <button className="ghost" onClick={() => void run(() => del(`/api/account/trusted-ips/${e.id}`), `${e.cidr} removed.`)}>
              Remove
            </button>
          </li>
        ))}
        {data.entries.length === 0 && <li className="muted">No addresses yet.</li>}
      </ul>
      <Field label="Password" hint="Needed to add addresses or change this setting.">
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
      </Field>
      <div className="row wrap">
        <input value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="203.0.113.7 or 203.0.113.0/24" aria-label="IP address or range" />
        <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Label (optional)" aria-label="Label" />
        <button disabled={!cidr || !password} onClick={() => void run(() => post('/api/account/trusted-ips', { cidr, label, password }), `${cidr} added.`)}>
          Add
        </button>
        <button
          disabled={!password || !data.currentIp || data.currentIpTrusted}
          onClick={() => void run(() => post('/api/account/trusted-ips', { current: true, label: label || 'Added from this device', password }), 'Current address added.')}
        >
          Add current IP address
        </button>
      </div>
      <Field label="Sign-ins from unlisted addresses">
        <select value={chosen} onChange={(e) => setPolicy(e.target.value as 'notify' | 'challenge')}>
          <option value="notify">Allow and notify me by email</option>
          <option value="challenge" disabled={!data.canChallenge}>
            Require verification with a code
          </option>
        </select>
        {!data.canChallenge && <small>Requires an email address or two-factor authentication on your account.</small>}
      </Field>
      <div className="row wrap">
        <button className="primary" disabled={!password} onClick={() => void run(() => put('/api/account/trusted-ips/settings', { password, enabled: true, policy: chosen }), 'Trusted address list saved.')}>
          {data.enabled ? 'Save' : 'Turn on'}
        </button>
        {data.enabled && (
          <button className="danger-outline" disabled={!password} onClick={() => void run(() => put('/api/account/trusted-ips/settings', { password, enabled: false, policy: chosen }), 'Trusted address list turned off.')}>
            Turn off
          </button>
        )}
        {data.enabled && <span className="ok">On</span>}
      </div>
      {error && <p className="error">{error}</p>}
      <p className="muted small">
        If you lose access (for example, after your network address changes), an administrator can turn this off for your account.
      </p>
    </div>
  );
}

function Sessions() {
  const { data, reload } = useAsync(() => get<{ sessions: SessionInfo[] }>('/api/auth/sessions'), []);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();
  const confirm = useConfirm();
  return (
    <>
    <ul className="list">
      {data?.sessions.map((s) => (
        <li key={s.id}>
          <span>
            <span className="small">{describeAgent(s.userAgent)}</span>
            <br />
            <span className="muted small">
              {s.ip ?? 'unknown IP'} · last active {formatTime(s.lastSeenAt)}
            </span>
          </span>
          {s.current ? (
            <span className="badge accent">This device</span>
          ) : (
            <button className="ghost" onClick={async () => (await del(`/api/auth/sessions/${s.id}`), toast.success('Device signed out.'), reload())}>
              Sign out
            </button>
          )}
        </li>
      ))}
    </ul>
    {error && <p className="error">{error}</p>}
    <button
      className="danger-outline"
      onClick={async () => {
        const ok = await confirm({
          title: 'Sign out of all devices',
          message: 'This includes the device you are using. All open terminals will close.',
          confirmLabel: 'Sign out everywhere',
          danger: true,
        });
        if (!ok) return;
        try {
          await post('/api/auth/sessions/revoke-all');
          window.location.reload();
        } catch (e) {
          setError(errorMessage(e));
        }
      }}
    >
      Sign out of all devices
    </button>
    </>
  );
}

function describeAgent(ua: string | null): string {
  if (!ua) return 'Unknown device';
  const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS X/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '';
  const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  return os ? `${browser} on ${os}` : browser;
}
