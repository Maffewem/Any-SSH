import { useEffect, useRef, useState } from 'react';
import { ApiError, get, post, type User } from './api';
import { Field, Form } from './ui';

/** How often keyboard/pointer activity is reported to the server, at most. */
const HEARTBEAT_MS = 20_000;
const ACTIVITY_EVENTS = ['keydown', 'pointerdown', 'pointermove', 'wheel', 'touchstart'] as const;

/**
 * Keeps the server's idle clock in step with what the user is doing in this tab, and notices
 * when the server locks the session. The server decides: this hook only asks it, at the moment
 * it said the lock would be due, and reports activity that made no other request.
 */
export function useIdleLock(enabled: boolean, onLocked: () => void) {
  const lockedRef = useRef(onLocked);
  lockedRef.current = onLocked;

  useEffect(() => {
    if (!enabled) return;
    let lastBeat = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;

    const check = async () => {
      try {
        const s = await get<{ locked: boolean; msUntilLock?: number | null }>('/api/auth/state');
        if (stopped) return;
        if (s.locked) return lockedRef.current();
        // Locking off: look again now and then in case an admin turns it on.
        schedule(s.msUntilLock == null ? 10 * 60_000 : s.msUntilLock + 1000);
      } catch (e) {
        // 401s are handled globally (lock screen or sign-in); retry anything else later.
        if (!(e instanceof ApiError && e.status === 401)) schedule(60_000);
      }
    };
    const schedule = (ms: number) => {
      clearTimeout(timer);
      timer = setTimeout(() => void check(), Math.max(1000, ms));
    };
    const onActivity = () => {
      if (Date.now() - lastBeat < HEARTBEAT_MS) return;
      lastBeat = Date.now();
      void post('/api/auth/heartbeat').catch(() => {});
    };
    const onVisible = () => document.visibilityState === 'visible' && void check();

    void check();
    for (const ev of ACTIVITY_EVENTS) window.addEventListener(ev, onActivity, { passive: true, capture: true });
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      stopped = true;
      clearTimeout(timer);
      for (const ev of ACTIVITY_EVENTS) window.removeEventListener(ev, onActivity, { capture: true });
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [enabled]);
}

/** Full-screen lock. The app underneath stays mounted (terminals stay connected) but hidden and inert. */
export function LockScreen(props: { displayName: string; username: string; onUnlocked: (u: User) => void; onSignOut: () => void }) {
  const [password, setPassword] = useState('');
  const unlockedRef = useRef(props.onUnlocked);
  unlockedRef.current = props.onUnlocked;
  // Unlocked from another tab? Pick that up when this one comes back into view.
  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState !== 'visible') return;
      get<{ user?: User }>('/api/auth/me').then((me) => me.user && unlockedRef.current(me.user), () => {});
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => document.removeEventListener('visibilitychange', onVisible);
  }, []);
  return (
    <div className="lock-screen" role="dialog" aria-modal="true" aria-label="Session locked">
      <div className="card auth-card">
        <div className="brand">
          <img src="/icon.svg" alt="" width={36} height={36} />
          <span>Any-SSH</span>
        </div>
        <h1>Session locked</h1>
        <p className="muted">
          This session is locked. Enter the password for <strong>{props.displayName}</strong> (@{props.username}) to carry
          on where you left off.
        </p>
        <Form
          submit="Unlock"
          onSubmit={async () => {
            try {
              const res = await post<{ user: User }>('/api/auth/unlock', { password });
              setPassword('');
              props.onUnlocked(res.user);
            } catch (e) {
              setPassword('');
              if (e instanceof ApiError && e.code === 'unauthenticated') return props.onSignOut();
              throw e;
            }
          }}
        >
          {/* A hidden username lets password managers fill the right account. */}
          <input type="text" name="username" value={props.username} autoComplete="username" readOnly hidden />
          <Field label="Password">
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus required />
          </Field>
        </Form>
        <p className="small">
          <button className="link" onClick={props.onSignOut}>
            Sign out instead
          </button>
        </p>
      </div>
    </div>
  );
}
