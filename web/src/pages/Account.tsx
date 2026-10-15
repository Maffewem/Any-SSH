import QRCode from 'qrcode';
import { useState } from 'react';
import { del, errorMessage, formatTime, get, patch, post, put, type User } from '../api';
import { Field, Form, SecretOnce, useAsync } from '../ui';
import { ChangePasswordForm } from './Auth';

interface SessionInfo {
  id: string;
  current: boolean;
  createdAt: number;
  lastSeenAt: number;
  ip: string | null;
  userAgent: string | null;
}

export function AccountPage({ user, onUserChange }: { user: User; onUserChange: (u: User) => void }) {
  const [passwordDone, setPasswordDone] = useState(false);
  return (
    <section className="stack">
      <h1>Account</h1>
      <div className="card">
        <h2>Profile</h2>
        <p className="muted">
          @{user.username} · {user.role === 'admin' ? 'Administrator' : 'User'}
        </p>
        <ProfileForm user={user} onUserChange={onUserChange} />
      </div>
      <div className="card">
        <h2>Two-factor authentication</h2>
        <MfaSection user={user} onChange={async () => onUserChange((await get<{ user: User }>('/api/auth/me')).user)} />
      </div>
      <div className="card">
        <h2>Password</h2>
        {passwordDone && <p className="ok">Password changed. Your other devices were signed out.</p>}
        <ChangePasswordForm onDone={(u) => (setPasswordDone(true), onUserChange(u))} />
      </div>
      <div className="card">
        <h2>Trusted IP addresses</h2>
        <TrustedIps user={user} />
      </div>
      <div className="card">
        <h2>Signed-in devices</h2>
        <Sessions />
      </div>
    </section>
  );
}

function ProfileForm({ user, onUserChange }: { user: User; onUserChange: (u: User) => void }) {
  const [displayName, setDisplayName] = useState(user.displayName);
  const [email, setEmail] = useState(user.email ?? '');
  const [password, setPassword] = useState('');
  const [saved, setSaved] = useState(false);
  const emailChanging = email.trim().toLowerCase() !== (user.email ?? '').toLowerCase();
  return (
    <Form
      submit="Save profile"
      onSubmit={async () => {
        setSaved(false);
        const res = await patch<{ user: User }>('/api/auth/profile', {
          displayName,
          ...(emailChanging ? { email: email.trim() || null, password } : {}),
        });
        setPassword('');
        setSaved(true);
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
      {saved && <p className="ok">Saved.</p>}
    </Form>
  );
}

function MfaSection({ user, onChange }: { user: User; onChange: () => Promise<void> }) {
  const [stage, setStage] = useState<'idle' | 'password' | 'scan' | 'disable' | 'regenerate'>('idle');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [enrol, setEnrol] = useState<{ secret: string; qr: string } | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

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
              reset();
              await onChange();
            } else {
              const res = await post<{ recoveryCodes: string[] }>('/api/auth/mfa/recovery-codes', { password, code });
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
  if (!data) return <p className="muted">Loading…</p>;
  const chosen = policy ?? data.policy;
  const run = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
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
        either reported to you or held until you verify it. Your address as the server sees it:{' '}
        <code className="mono">{data.currentIp ?? 'unknown'}</code> {data.currentIpTrusted ? <span className="badge accent">trusted</span> : <span className="badge warn">not listed</span>}
      </p>
      <ul className="list">
        {data.entries.map((e) => (
          <li key={e.id}>
            <span>
              <code className="mono">{e.cidr}</code>
              {e.label && <span className="muted small"> · {e.label}</span>}
            </span>
            <button className="ghost" onClick={() => void run(() => del(`/api/account/trusted-ips/${e.id}`))}>
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
        <button disabled={!cidr || !password} onClick={() => void run(() => post('/api/account/trusted-ips', { cidr, label, password }))}>
          Add
        </button>
        <button
          disabled={!password || !data.currentIp || data.currentIpTrusted}
          onClick={() => void run(() => post('/api/account/trusted-ips', { current: true, label: label || 'Added from this device', password }))}
        >
          Trust my current IP
        </button>
      </div>
      <Field label="When a sign-in comes from an unlisted address">
        <select value={chosen} onChange={(e) => setPolicy(e.target.value as 'notify' | 'challenge')}>
          <option value="notify">Let it in, but email me and record it</option>
          <option value="challenge" disabled={!data.canChallenge}>
            Hold it until I verify with a code
          </option>
        </select>
        {!data.canChallenge && <small>Add an email address or turn on two-factor to use this.</small>}
      </Field>
      <div className="row wrap">
        <button className="primary" disabled={!password} onClick={() => void run(() => put('/api/account/trusted-ips/settings', { password, enabled: true, policy: chosen }))}>
          {data.enabled ? 'Save' : 'Turn on'}
        </button>
        {data.enabled && (
          <button className="danger-outline" disabled={!password} onClick={() => void run(() => put('/api/account/trusted-ips/settings', { password, enabled: false, policy: chosen }))}>
            Turn off
          </button>
        )}
        {data.enabled && <span className="ok">On</span>}
      </div>
      {error && <p className="error">{error}</p>}
      <p className="muted small">
        If you ever lock yourself out (for example after moving), an administrator can switch this off for your account.
      </p>
    </div>
  );
}

function Sessions() {
  const { data, reload } = useAsync(() => get<{ sessions: SessionInfo[] }>('/api/auth/sessions'), []);
  return (
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
            <button className="ghost" onClick={async () => (await del(`/api/auth/sessions/${s.id}`), reload())}>
              Sign out
            </button>
          )}
        </li>
      ))}
    </ul>
  );
}

function describeAgent(ua: string | null): string {
  if (!ua) return 'Unknown device';
  const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS X/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '';
  const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  return os ? `${browser} on ${os}` : browser;
}
