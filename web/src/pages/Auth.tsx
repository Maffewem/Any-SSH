import { useEffect, useState } from 'react';
import { errorMessage, get, post, type AuthConfig, type User } from '../api';
import { TurnstileWidget } from '../turnstile';
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
    <Shell title="Set up Any-SSH">
      <p className="muted">
        Create the first administrator account. Paste the one-time setup token from the server log to confirm you own this server.
      </p>
      <Form
        submit="Create account"
        onSubmit={async () => {
          if (password !== confirm) throw new Error('The passwords don’t match.');
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
        <Field label="Email" hint="Optional. Used to reset your password and send you security alerts.">
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
        </Field>
        <Field label="Password" hint="Use at least 12 characters. A passphrase of several words works well.">
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
    setNote(res.sent ? 'We’ve emailed you an 8-digit code.' : 'We sent a code a moment ago. Check your inbox, or wait a minute and request another.');
  };
  return (
    <Shell title="Verify it’s you">
      <p>
        We noticed a sign-in from <code className="mono">{info.ip ?? 'an unknown IP address'}</code>, which isn’t one of your trusted IP addresses.
        Verify that it’s you to continue.
      </p>
      {info.methods.length === 0 && <p className="error">We can’t verify you on this account. Ask an administrator to reset your trusted IP addresses.</p>}
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
            {useRecovery ? 'Use an authentication code instead' : 'Use a recovery code'}
          </button>
        )}
        <button className="link" onClick={onLogout}>
          Sign out
        </button>
      </div>
    </Shell>
  );
}

/** Public sign-in options (registration mode, browser check). Falls back to the closed defaults if it can’t be loaded. */
function useAuthConfig(): AuthConfig | null {
  const [config, setConfig] = useState<AuthConfig | null>(null);
  useEffect(() => {
    get<AuthConfig>('/api/auth/config').then(setConfig, () => setConfig({ registration: 'invite', turnstile: null }));
  }, []);
  return config;
}

/**
 * A browser check for one form. `guard` wraps the submit: it refuses to send until the check has passed, adds the
 * token to the request, and asks for a fresh challenge when the server turns the request down (tokens work once).
 */
function useBrowserCheck(siteKey: string | null) {
  const [token, setToken] = useState<string | null>(null);
  const [resetKey, setResetKey] = useState(0);
  return {
    widget: siteKey ? <TurnstileWidget siteKey={siteKey} onToken={setToken} resetKey={resetKey} /> : null,
    async guard<T>(send: (captchaToken?: string) => Promise<T>): Promise<T> {
      if (siteKey && !token) throw new Error('Wait for the browser check to finish, then try again.');
      try {
        return await send(siteKey ? token! : undefined);
      } catch (err) {
        if (siteKey) setResetKey((n) => n + 1);
        throw err;
      }
    },
  };
}

export function LoginPage({ mfaPending, onLoggedIn }: { mfaPending: boolean; onLoggedIn: (u: User) => void }) {
  const [stage, setStage] = useState<'password' | 'mfa' | 'forgot' | 'register'>(mfaPending ? 'mfa' : 'password');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const config = useAuthConfig();
  const loginCheck = useBrowserCheck(config?.turnstile?.login ? config.turnstile.siteKey : null);

  if (stage === 'forgot') return <ForgotForm config={config} onBack={() => setStage('password')} />;
  if (stage === 'register' && config) return <RegisterPage config={config} onBack={() => setStage('password')} />;

  if (stage === 'mfa') {
    return (
      <Shell title="2-step verification">
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
          {useRecovery ? 'Use an authentication code instead' : 'Use a recovery code'}
        </button>
      </Shell>
    );
  }

  return (
    <Shell title="Sign in">
      <Form
        submit="Sign in"
        onSubmit={async () => {
          const res = await loginCheck.guard((captchaToken) =>
            post<{ mfaRequired: boolean; user?: User }>('/api/auth/login', { username, password, ...(captchaToken ? { captchaToken } : {}) }),
          );
          setPassword('');
          if (res.mfaRequired) setStage('mfa');
          else if (res.user) onLoggedIn(res.user); // a held sign-in is picked up by the app's challenge handler
        }}
      >
        <Field label={config && config.registration !== 'invite' ? 'Username or email' : 'Username'}>
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" autoFocus required />
        </Field>
        <Field label="Password">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </Field>
        {loginCheck.widget}
      </Form>
      <div className="row wrap">
        <button className="link" onClick={() => setStage('forgot')}>
          Forgot your password?
        </button>
        {config && config.registration !== 'invite' && (
          <button className="link" onClick={() => setStage('register')}>
            Create account
          </button>
        )}
      </div>
    </Shell>
  );
}

function ForgotForm({ config, onBack }: { config: AuthConfig | null; onBack: () => void }) {
  const [identifier, setIdentifier] = useState('');
  const [sent, setSent] = useState(false);
  const check = useBrowserCheck(config?.turnstile?.reset ? config.turnstile.siteKey : null);
  return (
    <Shell title="Reset your password">
      {sent ? (
        <p>If an account matches and has an email address, we’ve sent a link to reset the password. The link expires in 30 minutes.</p>
      ) : (
        <Form
          submit="Email me a reset link"
          onSubmit={async () => {
            await check.guard((captchaToken) => post('/api/auth/forgot', { identifier, ...(captchaToken ? { captchaToken } : {}) }));
            setSent(true);
          }}
        >
          <Field label="Username or email">
            <input value={identifier} onChange={(e) => setIdentifier(e.target.value)} autoCapitalize="none" autoComplete="username" autoFocus required />
          </Field>
          {check.widget}
        </Form>
      )}
      <button className="link" onClick={onBack}>
        Back to sign in
      </button>
    </Shell>
  );
}

/** Create account page. Shown from the Sign in page when an administrator has opened registration. */
function RegisterPage({ config, onBack }: { config: AuthConfig; onBack: () => void }) {
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [sent, setSent] = useState(false);
  const check = useBrowserCheck(config.turnstile?.signup ? config.turnstile.siteKey : null);

  if (sent) {
    return (
      <Shell title="Check your email">
        <p>
          We’ve sent a confirmation link to <strong>{email}</strong>. Open it to finish creating your account. The link expires in 24 hours.
        </p>
        <p className="muted small">If you don’t see the email, check your spam folder. If an account already exists for this address, we’ve emailed you about that instead.</p>
        <button className="link" onClick={onBack}>
          Back to sign in
        </button>
      </Shell>
    );
  }
  return (
    <Shell title="Create your account">
      <Form
        submit="Create account"
        onSubmit={async () => {
          if (password !== confirm) throw new Error('The passwords don’t match.');
          await check.guard((captchaToken) => post('/api/auth/register', { displayName, email, password, ...(captchaToken ? { captchaToken } : {}) }));
          setPassword('');
          setConfirm('');
          setSent(true);
        }}
      >
        <Field label="Full name">
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="name" autoFocus required maxLength={100} />
        </Field>
        <Field label="Email" hint="We’ll send a link to confirm this address. You can also use it to sign in.">
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" autoCapitalize="none" required />
        </Field>
        <Field label="Password" hint={passwordHint(password)}>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required />
        </Field>
        <Field label="Confirm password">
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required />
        </Field>
        {check.widget}
      </Form>
      {config.registration === 'approval' && <p className="muted small">After you confirm your email address, an administrator needs to approve your account before you can sign in.</p>}
      <button className="link" onClick={onBack}>
        Already have an account? Sign in
      </button>
    </Shell>
  );
}

function passwordHint(password: string): string {
  if (!password) return 'Use at least 12 characters. A passphrase of several words works well.';
  if (password.length < 12) return `${12 - password.length} more character${12 - password.length === 1 ? '' : 's'} needed.`;
  return 'Length is good. Avoid common passwords and repeated characters.';
}

const verifyRequests: Record<string, Promise<{ status: 'active' | 'pending_approval' }>> = {};

/** Landing page for the email confirmation link: #/verify?token=… */
export function VerifyEmailPage({ token, onDone }: { token: string; onDone: () => void }) {
  const [result, setResult] = useState<'active' | 'pending_approval' | string | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    // The link works once, so a repeated effect run (React strict mode) must reuse the first request.
    verifyRequests[token] ??= post<{ status: 'active' | 'pending_approval' }>('/api/auth/verify', { token });
    verifyRequests[token]!.then(
      (r) => setResult(r.status),
      (e) => (setFailed(true), setResult(errorMessage(e))),
    );
  }, [token]);
  if (result === null) return <div className="loading">Confirming your email address…</div>;
  return (
    <Shell title={failed ? 'This link doesn’t work' : result === 'active' ? 'Email confirmed' : 'Thanks for confirming'}>
      {failed ? (
        <p className="error">{result}</p>
      ) : result === 'active' ? (
        <p>Your account is ready. Sign in with your email address and password.</p>
      ) : (
        <p>Your email address is confirmed. An administrator needs to approve your account before you can sign in. We’ll email you when it’s ready.</p>
      )}
      <button className="primary" onClick={onDone}>
        Go to sign in
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
      <Shell title="This link doesn’t work">
        <p className="error">{error}</p>
        <button className="link" onClick={onDone}>
          Go to Sign in
        </button>
      </Shell>
    );
  }
  if (!info) return <div className="loading">Checking your link…</div>;
  if (done) {
    return (
      <Shell title="Password updated">
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
        {info.purpose === 'invite' ? 'Create a password for your new account' : 'Set a new password for'} <strong>{info.username}</strong>.
        {info.purpose === 'reset' && ' You’ll be signed out on all devices.'}
      </p>
      <Form
        submit="Save password"
        onSubmit={async () => {
          if (password !== confirm) throw new Error('The passwords don’t match.');
          await post('/api/auth/token/complete', { token, newPassword: password });
          setDone(true);
        }}
      >
        <input type="text" value={info.username} autoComplete="username" readOnly hidden />
        <Field label="New password" hint="Use at least 12 characters. A passphrase of several words works well.">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" autoFocus required />
        </Field>
        <Field label="Confirm password">
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required />
        </Field>
      </Form>
    </Shell>
  );
}

export function ChangePasswordForm({ onDone, submit = 'Change password' }: { onDone: (u: User, signedOutSessions?: number) => void; submit?: string }) {
  const [currentPassword, setCurrent] = useState('');
  const [newPassword, setNew] = useState('');
  const [confirm, setConfirm] = useState('');
  return (
    <Form
      submit={submit}
      onSubmit={async () => {
        if (newPassword !== confirm) throw new Error('The new passwords don’t match.');
        const res = await post<{ user: User; signedOutSessions?: number }>('/api/auth/password', { currentPassword, newPassword });
        setCurrent('');
        setNew('');
        setConfirm('');
        onDone(res.user, res.signedOutSessions);
      }}
    >
      <Field label="Current password">
        <input type="password" value={currentPassword} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required />
      </Field>
      <Field label="New password" hint="Use at least 12 characters. Changing it signs you out on your other devices.">
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
      <p className="muted">Your administrator gave you a temporary password. Create your own password to continue.</p>
      <ChangePasswordForm onDone={onDone} submit="Save and continue" />
      <button className="link" onClick={onLogout}>
        Sign out
      </button>
    </Shell>
  );
}
