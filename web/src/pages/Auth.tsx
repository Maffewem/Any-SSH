import { useState } from 'react';
import { post, type User } from '../api';
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
          await post('/api/setup', { setupToken, username, password });
          onDone();
        }}
      >
        <Field label="Setup token">
          <input value={setupToken} onChange={(e) => setToken(e.target.value)} autoComplete="off" required />
        </Field>
        <Field label="Username">
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
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

export function LoginPage({ mfaPending, onLoggedIn }: { mfaPending: boolean; onLoggedIn: (u: User) => void }) {
  const [stage, setStage] = useState<'password' | 'mfa'>(mfaPending ? 'mfa' : 'password');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);

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
          else if (res.user) onLoggedIn(res.user);
        }}
      >
        <Field label="Username">
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" autoFocus required />
        </Field>
        <Field label="Password">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
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
