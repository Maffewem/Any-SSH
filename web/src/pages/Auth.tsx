import { useEffect, useState } from 'react';
import { errorMessage, get, post, type User } from '../api';
import { Field, Form } from '../ui';

function Shell({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <main className="auth-shell">
      <div className="card auth-card">
        <div className="brand">
          <img src="/icon.svg" alt="" width={36} height={36} />
          <span>Any-SSH</span>
        </div>
        <h1>{title}</h1>
        {children}
      </div>
    </main>
  );
}

export function SetupPage({ onDone }: { onDone: () => void }) {
  const [setupToken, setToken] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  return (
    <Shell title="Create the administrator">
      <p className="muted">
        This is a fresh install. Paste the one-time setup token printed in the server log, then choose the first administrator account.
      </p>
      <Form
        submit="Create administrator"
        onSubmit={async () => {
          if (password !== confirm) throw new Error('Passwords do not match.');
          await post('/api/setup', { setupToken, username, password, ...(email ? { email } : {}) });
          onDone();
        }}
      >
        <Field label="Setup token">
          <input value={setupToken} onChange={(e) => setToken(e.target.value)} autoComplete="off" required />
        </Field>
        <Field label="Username">
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        </Field>
        <Field label="Email" hint="Optional. Used for password resets and security notices.">
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
        </Field>
        <Field label="Password" hint="At least 12 characters. A passphrase of several words works well.">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required />
        </Field>
        <Field label="Confirm password">
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required />
        </Field>
      </Form>
    </Shell>
  );
}

interface ChallengeInfo {
  ip: string | null;
  methods: ('totp' | 'email')[];
}

/** Shown when the server holds a sign-in from an address that is not on the user's trusted IP list. */
export function IpChallengePage({ onDone, onLogout }: { onDone: (u: User) => void; onLogout: () => void }) {
  const [info, setInfo] = useState<ChallengeInfo | null>(null);
  const [code, setCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [emailed, setEmailed] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  useEffect(() => {
    get<ChallengeInfo>('/api/auth/ip-challenge').then(setInfo, () => onLogout());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  if (!info) return <div className="loading">Loading…</div>;
  const hasTotp = info.methods.includes('totp');
  const hasEmail = info.methods.includes('email');
  const sendEmail = async () => {
    const res = await post<{ sent: boolean }>('/api/auth/ip-challenge/send');
    setEmailed(true);
    setNote(res.sent ? 'We emailed you an 8-digit code.' : 'A code was sent a moment ago. Check your inbox, or wait a minute to ask again.');
  };
  return (
    <Shell title="Verify this sign-in">
      <p>
        You are signing in from <code className="mono">{info.ip ?? 'an unknown address'}</code>, which is not on your trusted IP list.
        Confirm it is you to continue.
      </p>
      {info.methods.length === 0 && <p className="error">There is no way to verify you on this account. Ask an administrator to reset your trusted IP list.</p>}
      {hasEmail && !emailed && !(hasTotp && !useRecovery) && (
        <button className="primary" onClick={() => void sendEmail().catch((e: unknown) => setNote(errorMessage(e)))}>
          Email me a code
        </button>
      )}
      {(emailed || hasTotp) && (
        <Form
          submit="Verify"
          onSubmit={async () => {
            const res = await post<{ user: User }>('/api/auth/ip-challenge/verify', useRecovery ? { recoveryCode: code } : { code });
            onDone(res.user);
          }}
        >
          <Field
            label={useRecovery ? 'Recovery code' : hasTotp ? 'Code from your authenticator app' + (hasEmail ? ' (or the emailed code)' : '') : 'Emailed code'}
            hint={note ?? undefined}
          >
            <input value={code} onChange={(e) => setCode(e.target.value)} inputMode={useRecovery ? 'text' : 'numeric'} autoComplete="one-time-code" autoFocus required />
          </Field>
        </Form>
      )}
      <div className="row wrap">
        {hasEmail && hasTotp && !emailed && (
          <button className="link" onClick={() => void sendEmail().catch((e: unknown) => setNote(errorMessage(e)))}>
            Email me a code instead
          </button>
        )}
        {hasTotp && (
          <button className="link" onClick={() => (setUseRecovery(!useRecovery), setCode(''))}>
            {useRecovery ? 'Use a code instead' : 'Use a recovery code'}
          </button>
        )}
        <button className="link" onClick={onLogout}>
          Sign out
        </button>
      </div>
    </Shell>
  );
}

export function LoginPage({ mfaPending, onLoggedIn }: { mfaPending: boolean; onLoggedIn: (u: User) => void }) {
  const [stage, setStage] = useState<'password' | 'mfa' | 'forgot'>(mfaPending ? 'mfa' : 'password');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);

  if (stage === 'forgot') return <ForgotForm onBack={() => setStage('password')} />;

  if (stage === 'mfa') {
    return (
      <Shell title="Two-factor authentication">
        <Form
          submit="Verify"
          onSubmit={async () => {
            const res = await post<{ user: User }>('/api/auth/mfa', useRecovery ? { recoveryCode: code } : { code });
            onLoggedIn(res.user);
          }}
        >
          <Field label={useRecovery ? 'Recovery code' : '6-digit code from your authenticator app'}>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode={useRecovery ? 'text' : 'numeric'}
              autoComplete="one-time-code"
              autoFocus
              required
            />
          </Field>
        </Form>
        <button className="link" onClick={() => (setUseRecovery(!useRecovery), setCode(''))}>
          {useRecovery ? 'Use authenticator code instead' : 'Use a recovery code'}
        </button>
      </Shell>
    );
  }

  return (
    <Shell title="Sign in">
      <Form
        submit="Sign in"
        onSubmit={async () => {
          const res = await post<{ mfaRequired: boolean; user?: User }>('/api/auth/login', { username, password });
          setPassword('');
          if (res.mfaRequired) setStage('mfa');
          else if (res.user) onLoggedIn(res.user); // a held sign-in is picked up by the app's challenge handler
        }}
      >
        <Field label="Username">
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" autoFocus required />
        </Field>
        <Field label="Password">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </Field>
      </Form>
      <button className="link" onClick={() => setStage('forgot')}>
        Forgot your password?
      </button>
    </Shell>
  );
}

function ForgotForm({ onBack }: { onBack: () => void }) {
  const [identifier, setIdentifier] = useState('');
  const [sent, setSent] = useState(false);
  return (
    <Shell title="Reset your password">
      {sent ? (
        <p>If that account exists and has an email address, we’ve sent it a link to reset the password. The link expires in 30 minutes.</p>
      ) : (
        <Form
          submit="Email me a reset link"
          onSubmit={async () => {
            await post('/api/auth/forgot', { identifier });
            setSent(true);
          }}
        >
          <Field label="Username or email">
            <input value={identifier} onChange={(e) => setIdentifier(e.target.value)} autoCapitalize="none" autoComplete="username" autoFocus required />
          </Field>
        </Form>
      )}
      <button className="link" onClick={onBack}>
        Back to sign in
      </button>
    </Shell>
  );
}

/** Landing page for emailed links: #/welcome?token=… (invite) and #/reset?token=… (reset). */
export function TokenPage({ token, onDone }: { token: string; onDone: () => void }) {
  const [info, setInfo] = useState<{ purpose: 'invite' | 'reset'; username: string; displayName: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [done, setDone] = useState(false);

  useEffect(() => {
    post<{ purpose: 'invite' | 'reset'; username: string; displayName: string }>('/api/auth/token/check', { token }).then(setInfo, (e) =>
      setError(e instanceof Error ? e.message : String(e)),
    );
  }, [token]);

  if (error) {
    return (
      <Shell title="Link not valid">
        <p className="error">{error}</p>
        <button className="link" onClick={onDone}>
          Go to sign in
        </button>
      </Shell>
    );
  }
  if (!info) return <div className="loading">Checking link…</div>;
  if (done) {
    return (
      <Shell title="Password saved">
        <p>You can now sign in as <strong>{info.username}</strong>.</p>
        <button className="primary" onClick={onDone}>
          Sign in
        </button>
      </Shell>
    );
  }
  return (
    <Shell title={info.purpose === 'invite' ? `Welcome, ${info.displayName}` : 'Choose a new password'}>
      <p className="muted">
        {info.purpose === 'invite' ? 'Set a password for your new account' : 'Set a new password for'} <strong>{info.username}</strong>.
        {info.purpose === 'reset' && ' This signs you out on every device.'}
      </p>
      <Form
        submit="Save password"
        onSubmit={async () => {
          if (password !== confirm) throw new Error('Passwords do not match.');
          await post('/api/auth/token/complete', { token, newPassword: password });
          setDone(true);
        }}
      >
        <input type="text" value={info.username} autoComplete="username" readOnly hidden />
        <Field label="New password" hint="At least 12 characters. A passphrase of several words works well.">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" autoFocus required />
        </Field>
        <Field label="Confirm password">
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required />
        </Field>
      </Form>
    </Shell>
  );
}

export function ChangePasswordForm({ onDone, submit = 'Change password' }: { onDone: (u: User) => void; submit?: string }) {
  const [currentPassword, setCurrent] = useState('');
  const [newPassword, setNew] = useState('');
  const [confirm, setConfirm] = useState('');
  return (
    <Form
      submit={submit}
      onSubmit={async () => {
        if (newPassword !== confirm) throw new Error('New passwords do not match.');
        const res = await post<{ user: User }>('/api/auth/password', { currentPassword, newPassword });
        setCurrent('');
        setNew('');
        setConfirm('');
        onDone(res.user);
      }}
    >
      <Field label="Current password">
        <input type="password" value={currentPassword} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required />
      </Field>
      <Field label="New password" hint="At least 12 characters. Changing it signs out your other devices.">
        <input type="password" value={newPassword} onChange={(e) => setNew(e.target.value)} autoComplete="new-password" required />
      </Field>
      <Field label="Confirm new password">
        <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required />
      </Field>
    </Form>
  );
}

export function ForcePasswordChangePage({ onDone, onLogout }: { onDone: (u: User) => void; onLogout: () => void }) {
  return (
    <Shell title="Choose a new password">
      <p className="muted">Your administrator gave you a temporary password. Replace it with your own to continue.</p>
      <ChangePasswordForm onDone={onDone} submit="Save and continue" />
      <button className="link" onClick={onLogout}>
        Sign out
      </button>
    </Shell>
  );
}
