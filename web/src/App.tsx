import { UpdateBanner } from './UpdateBanner';
import { useCallback, useEffect, useState } from 'react';
import { get, post, setIpChallengeHandler, setLockedHandler, setUnauthenticatedHandler, type ConnectChoice, type Server, type User } from './api';
import { LockScreen, useIdleLock } from './lock';
import { AccountPage } from './pages/Account';
import { AdminUsersPage, AuditPage, HostKeysPage } from './pages/Admin';
import { SettingsPage } from './pages/Settings';
import { ForcePasswordChangePage, IpChallengePage, LoginPage, SetupPage, TokenPage } from './pages/Auth';
import { KeysPage } from './pages/Keys';
import { ServersPage } from './pages/Servers';
import { remove, split, leaves, type Layout } from './terminal/layout';
import type { TerminalState } from './terminal/TerminalSession';
import { TerminalTab, tabState, type TabModel } from './terminal/TerminalTab';

type Page = 'servers' | 'keys' | 'account' | 'users' | 'audit' | 'hostkeys' | 'settings';
type Boot =
  | { kind: 'loading' }
  | { kind: 'setup' }
  | { kind: 'login'; mfaPending: boolean }
  /** Signed in but locked when the page loaded, so there is no app state to keep behind the lock. */
  | { kind: 'locked'; username: string; displayName: string }
  | { kind: 'ipchallenge' }
  | { kind: 'app'; user: User };

type OpenTerminal = TabModel;

/** Token from an emailed link (#/reset?token=… or #/welcome?token=…), if this is one. */
function linkTokenFromHash(): string | null {
  const m = /^#\/(reset|welcome)\?token=([A-Za-z0-9_-]{20,100})$/.exec(location.hash);
  return m ? m[2]! : null;
}

function pageFromHash(): Page {
  const h = location.hash.replace(/^#\/?/, '');
  return (['servers', 'keys', 'account', 'users', 'audit', 'hostkeys', 'settings'] as const).find((p) => p === h) ?? 'servers';
}

export function App() {
  const [boot, setBoot] = useState<Boot>({ kind: 'loading' });
  const [page, setPage] = useState<Page>(pageFromHash);
  const [terminals, setTerminals] = useState<OpenTerminal[]>([]);
  const [activeTab, setActiveTab] = useState<string | null>(null);
  const [linkToken, setLinkToken] = useState<string | null>(linkTokenFromHash);
  /** Locked while the app is open: the app stays mounted underneath, hidden. */
  const [locked, setLocked] = useState(false);

  const refresh = useCallback(async () => {
    const setup = await get<{ needed: boolean }>('/api/setup');
    if (setup.needed) return setBoot({ kind: 'setup' });
    try {
      const me = await get<{ user?: User; mfaRequired?: boolean; locked?: boolean; ipChallenge?: boolean; username?: string; displayName?: string }>('/api/auth/me');
      if (me.user && me.ipChallenge) setBoot({ kind: 'ipchallenge' });
      else if (me.locked) setBoot({ kind: 'locked', username: me.username!, displayName: me.displayName! });
      else if (me.user) setBoot({ kind: 'app', user: me.user });
      else setBoot({ kind: 'login', mfaPending: !!me.mfaRequired });
    } catch {
      setBoot({ kind: 'login', mfaPending: false });
    }
  }, []);

  useEffect(() => {
    void refresh();
    setIpChallengeHandler(() => {
      setTerminals([]);
      setBoot({ kind: 'ipchallenge' });
    });
    setUnauthenticatedHandler(() => {
      setTerminals([]);
      setLocked(false);
      setBoot({ kind: 'login', mfaPending: false });
    });
    setLockedHandler(() => setLocked(true));
    const onHash = () => {
      setLinkToken(linkTokenFromHash());
      setPage(pageFromHash());
      setActiveTab(null);
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, [refresh]);

  useIdleLock(boot.kind === 'app' && !locked, () => setLocked(true));

  const logout = async () => {
    await post('/api/auth/logout').catch(() => {});
    setTerminals([]);
    setActiveTab(null);
    setLocked(false);
    setBoot({ kind: 'login', mfaPending: false });
  };
  const lockNow = async () => {
    await post('/api/auth/lock').catch(() => {});
    setLocked(true);
  };

  if (linkToken) {
    return (
      <TokenPage
        token={linkToken}
        onDone={() => {
          // Drop the token from the address bar and history.
          history.replaceState(null, '', '/');
          setLinkToken(null);
          void post('/api/auth/logout').catch(() => {});
          setBoot({ kind: 'login', mfaPending: false });
        }}
      />
    );
  }
  if (boot.kind === 'loading') return <div className="loading">Loading…</div>;
  if (boot.kind === 'setup') return <SetupPage onDone={() => setBoot({ kind: 'login', mfaPending: false })} />;
  if (boot.kind === 'locked') {
    return (
      <LockScreen
        username={boot.username}
        displayName={boot.displayName}
        onUnlocked={(u) => setBoot({ kind: 'app', user: u })}
        onSignOut={logout}
      />
    );
  }
  if (boot.kind === 'login') return <LoginPage mfaPending={boot.mfaPending} onLoggedIn={(user) => setBoot({ kind: 'app', user })} />;

  if (boot.kind === 'ipchallenge') return <IpChallengePage onDone={() => void refresh()} onLogout={logout} />;

  const user = boot.user;
  if (locked && user.mustChangePassword) {
    return <LockScreen username={user.username} displayName={user.displayName} onUnlocked={(u) => (setLocked(false), setBoot({ kind: 'app', user: u }))} onSignOut={logout} />;
  }
  if (user.mustChangePassword) {
    return <ForcePasswordChangePage onDone={(u) => setBoot({ kind: 'app', user: u })} onLogout={logout} />;
  }

  const connect = (server: Server, choice?: ConnectChoice) => {
    const tabId = crypto.randomUUID();
    const pane = crypto.randomUUID();
    setTerminals((ts) => [
      ...ts,
      { tabId, server, choice, layout: { kind: 'pane', id: pane }, panes: { [pane]: { attempt: 0, state: 'connecting' } }, focused: pane },
    ]);
    setActiveTab(tabId);
  };
  const closeTab = (tabId: string) => {
    setTerminals((ts) => ts.filter((t) => t.tabId !== tabId));
    if (activeTab === tabId) setActiveTab(null);
  };
  const updateTab = (tabId: string, change: (t: OpenTerminal) => Partial<OpenTerminal>) =>
    setTerminals((ts) => ts.map((t) => (t.tabId === tabId ? { ...t, ...change(t) } : t)));
  const setPane = (tabId: string, paneId: string, change: Partial<OpenTerminal['panes'][string]>) =>
    updateTab(tabId, (t) => (t.panes[paneId] ? { panes: { ...t.panes, [paneId]: { ...t.panes[paneId]!, ...change } } } : {}));
  /** Another terminal to the same server with the same credentials, next to the one in `paneId`. */
  const splitPane = (tabId: string, paneId: string, dir: 'row' | 'col') => {
    const fresh = crypto.randomUUID();
    updateTab(tabId, (t) => ({
      layout: split(t.layout, paneId, dir, fresh),
      panes: { ...t.panes, [fresh]: { attempt: 0, state: 'connecting' } },
      focused: fresh,
    }));
  };
  const closePane = (tabId: string, paneId: string) =>
    updateTab(tabId, (t) => {
      const layout: Layout = remove(t.layout, paneId);
      const { [paneId]: _gone, ...panes } = t.panes;
      return { layout, panes, focused: t.focused === paneId ? leaves(layout)[0]! : t.focused };
    });
  const reconnectTab = (tabId: string) =>
    updateTab(tabId, (t) => ({
      panes: Object.fromEntries(Object.entries(t.panes).map(([id, p]) => [id, p.state === 'closed' ? { attempt: p.attempt + 1, state: 'connecting' as TerminalState } : p])),
    }));

  const nav: { id: Page; label: string; admin?: boolean }[] = [
    { id: 'servers', label: 'Servers' },
    { id: 'keys', label: 'Keys' },
    { id: 'users', label: 'Users', admin: true },
    { id: 'audit', label: 'Audit', admin: true },
    { id: 'hostkeys', label: 'Host keys', admin: true },
    { id: 'settings', label: 'Settings', admin: true },
    { id: 'account', label: 'Account' },
  ];
  const showingTerminal = activeTab !== null;

  return (
    <>
    <div className={`app ${showingTerminal ? 'terminal-mode' : ''} ${locked ? 'locked' : ''}`} inert={locked} aria-hidden={locked}>
      <header className="topbar">
        <a className="brand" href="#/servers" onClick={() => setActiveTab(null)}>
          <img src="/icon.svg" alt="" width={24} height={24} />
          <span>Any-SSH</span>
        </a>
        <nav className="tabs">
          {nav
            .filter((n) => !n.admin || user.role === 'admin')
            .map((n) => (
              <a key={n.id} href={`#/${n.id}`} className={!showingTerminal && page === n.id ? 'current' : ''} onClick={() => setActiveTab(null)}>
                {n.label}
              </a>
            ))}
        </nav>
        <button className="ghost signout" onClick={lockNow} title="Lock this session; unlock with your password">
          Lock
        </button>
        <button className="ghost signout" onClick={logout}>
          Sign out
        </button>
      </header>

      <UpdateBanner />

      {terminals.length > 0 && (
        <div className="terminal-tabs" role="tablist">
          {showingTerminal && (
            <button className="ghost back" onClick={() => setActiveTab(null)} title="Back to the app">
              ← {page === 'servers' ? 'Servers' : 'Back'}
            </button>
          )}
          {terminals.map((t) => (
            <div key={t.tabId} className={`terminal-tab ${activeTab === t.tabId ? 'current' : ''}`} role="tab" aria-selected={activeTab === t.tabId}>
              <button className="tab-label" onClick={() => setActiveTab(t.tabId)}>
                <span className={`dot ${tabState(t)}`} />
                {t.server.name}
              </button>
              {Object.values(t.panes).some((p) => p.state === 'closed') && (
                <button className="ghost" title="Reconnect" onClick={() => (reconnectTab(t.tabId), setActiveTab(t.tabId))}>
                  ↻
                </button>
              )}
              <button className="ghost" title="Close" onClick={() => closeTab(t.tabId)}>
                ✕
              </button>
            </div>
          ))}
        </div>
      )}

      <main className={showingTerminal ? 'terminal-main' : 'content'}>
        {terminals.map((t) => (
          <TerminalTab
            key={t.tabId}
            tab={t}
            active={activeTab === t.tabId}
            onPaneState={(paneId, state) => setPane(t.tabId, paneId, { state })}
            onFocus={(paneId) => t.focused !== paneId && updateTab(t.tabId, () => ({ focused: paneId }))}
            onSplit={(paneId, dir) => splitPane(t.tabId, paneId, dir)}
            onClosePane={(paneId) => closePane(t.tabId, paneId)}
          />
        ))}
        {!showingTerminal && (
          <>
            {page === 'servers' && <ServersPage onConnect={connect} isAdmin={user.role === 'admin'} />}
            {page === 'keys' && <KeysPage />}
            {page === 'account' && <AccountPage user={user} onUserChange={(u) => setBoot({ kind: 'app', user: u })} />}
            {page === 'users' && user.role === 'admin' && <AdminUsersPage me={user} />}
            {page === 'audit' && user.role === 'admin' && <AuditPage />}
            {page === 'hostkeys' && user.role === 'admin' && <HostKeysPage />}
            {page === 'settings' && user.role === 'admin' && <SettingsPage />}
          </>
        )}
      </main>
    </div>
    {locked && (
      <LockScreen
        username={user.username}
        displayName={user.displayName}
        onUnlocked={(u) => (setLocked(false), setBoot({ kind: 'app', user: u }))}
        onSignOut={logout}
      />
    )}
    </>
  );
}
