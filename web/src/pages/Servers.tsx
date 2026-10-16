import { useState } from 'react';
import { del, formatTime, get, patch, post, put, type AuthMethod, type ConnectChoice, type ConnectCredential, type JumpHost, type JumpMode, type Server, type Share, type ShareCredentials, type SshKey } from '../api';
import { Field, Form, Modal, useAsync, useConfirm, useToast } from '../ui';

export function ServersPage({ onConnect, isAdmin }: { onConnect: (s: Server, choice?: ConnectChoice) => void; isAdmin: boolean }) {
  const { data, error, reload } = useAsync(() => get<{ servers: Server[] }>('/api/servers'), []);
  const [editing, setEditing] = useState<Server | 'new' | null>(null);
  const [sharing, setSharing] = useState<Server | null>(null);
  const [connecting, setConnecting] = useState<Server | null>(null);
  const [filter, setFilter] = useState('');

  const [activeTag, setActiveTag] = useState<string | null>(null);

  const all = data?.servers ?? [];
  // Every tag in use on a server you can see, most used first.
  const tagCounts = new Map<string, { label: string; n: number }>();
  for (const s of all) {
    for (const t of s.tags) {
      const hit = tagCounts.get(t.toLowerCase());
      if (hit) hit.n++;
      else tagCounts.set(t.toLowerCase(), { label: t, n: 1 });
    }
  }
  const knownTags = [...tagCounts.values()].sort((a, b) => b.n - a.n || a.label.localeCompare(b.label)).map((t) => t.label);
  // Each word must match somewhere: name, host, user, notes, tags or the jump host.
  const words = filter.toLowerCase().split(/\s+/).filter(Boolean);
  const servers = all.filter((s) => {
    if (activeTag && !s.tags.some((t) => t.toLowerCase() === activeTag.toLowerCase())) return false;
    const haystack = [s.name, s.host, s.username, s.notes, s.owner?.displayName ?? '', s.jump.host?.name ?? '', ...s.tags].join(' ').toLowerCase();
    return words.every((w) => haystack.includes(w));
  });

  return (
    <section>
      <div className="page-head">
        <h1>Servers</h1>
        <button className="primary" onClick={() => setEditing('new')}>
          Add server
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {all.length > 0 && (
        <div className="search-wrap" role="search">
          <svg className="search-icon" viewBox="0 0 20 20" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <circle cx="8.5" cy="8.5" r="5.5" />
            <path d="M13 13l4 4" />
          </svg>
          <input
            className="search"
            type="text"
            inputMode="search"
            enterKeyHint="search"
            placeholder="Search servers"
            title="Searches names, hosts, usernames, notes, owners and tags"
            aria-label="Search servers"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            onKeyDown={(e) => e.key === 'Escape' && setFilter('')}
          />
          {filter && (
            <button type="button" className="search-clear" aria-label="Clear search" onClick={() => setFilter('')}>
              ×
            </button>
          )}
        </div>
      )}
      {knownTags.length > 0 && (
        <div className="tag-filter" role="group" aria-label="Filter by tag">
          <span className="tag-filter-label muted small">Filter by tag</span>
          {knownTags.map((t) => (
            <button
              key={t}
              className={`tag ${activeTag?.toLowerCase() === t.toLowerCase() ? 'on' : ''}`}
              aria-pressed={activeTag?.toLowerCase() === t.toLowerCase()}
              onClick={() => setActiveTag(activeTag?.toLowerCase() === t.toLowerCase() ? null : t)}
            >
              {t}
            </button>
          ))}
        </div>
      )}
      {all.length > 0 && (filter || activeTag) && servers.length > 0 && (
        <p className="muted small result-count" role="status">
          Showing {servers.length} of {all.length} {all.length === 1 ? 'server' : 'servers'}
          {activeTag ? ` tagged “${activeTag}”` : ''}.{' '}
          <button className="link" onClick={() => (setFilter(''), setActiveTag(null))}>Clear filters</button>
        </p>
      )}
      {all.length > 0 && servers.length === 0 && (
        <div className="empty card" role="status">
          <p>
            No servers match{filter ? ` “${filter}”` : ''}{activeTag ? ` with the tag “${activeTag}”` : ''}.{' '}
            <button className="link" onClick={() => (setFilter(''), setActiveTag(null))}>Clear filters</button>
          </p>
        </div>
      )}
      {data && data.servers.length === 0 && (
        <div className="empty card">
          <p>You don’t have any servers yet. Add a server, or ask someone to share one with you.</p>
        </div>
      )}
      <div className="grid">
        {servers.map((s) => (
          <article key={s.id} className="card server-card">
            <div className="server-main">
              <h3>{s.name}</h3>
              <p className="mono muted">
                {s.username}@{s.host}
                {s.port !== 22 ? `:${s.port}` : ''}
              </p>
              <div className="badges">
                {s.access === 'owner' ? (
                  s.shareCount > 0 && <span className="badge">Shared with {s.shareCount}</span>
                ) : (
                  <span className="badge accent">
                        {s.access === 'manage' ? 'Manager' : 'Shared'} · from {s.owner?.displayName ?? 'unknown user'}
                  </span>
                )}
                <span className="badge">{s.credentials === 'own' ? 'Your own credentials' : authLabel(s.authMethod)}</span>
                {s.hostKeyChange ? (
                  <span className="badge warn">Server fingerprint changed</span>
                ) : (
                  !s.hostKeyFingerprint && <span className="badge warn">Server fingerprint not verified</span>
                )}
                {s.jump.mode !== 'none' && (
                  <span className="badge">{s.jump.mode === 'auto' ? 'Via the closest jump host' : `Via ${s.jump.host?.name ?? 'a jump host that was removed'}`}</span>
                )}
              </div>
              {s.tags.length > 0 && (
                <div className="tags">
                  {s.tags.map((t) => (
                    <button key={t} className="tag" title={`Show servers tagged ${t}`} onClick={() => setActiveTag(t)}>
                      {t}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div className="actions">
              <button className="primary" onClick={() => (s.credentials === 'own' ? setConnecting(s) : onConnect(s))}>
                Connect
              </button>
              <button className="connect-as" title="Connect with different credentials" aria-label="Connect with different credentials" onClick={() => setConnecting(s)}>
                Connect as…
              </button>
              {s.access !== 'use' && <button onClick={() => setEditing(s)}>Edit</button>}
              {(s.access === 'owner' || s.canShare) && <button onClick={() => setSharing(s)}>Share</button>}
            </div>
          </article>
        ))}
      </div>
      {editing && (
        <ServerForm
          server={editing === 'new' ? null : editing}
          knownTags={knownTags}
          isAdmin={isAdmin}
          onClose={() => setEditing(null)}
          onSaved={() => (setEditing(null), reload())}
        />
      )}
      {sharing && <ShareDialog server={sharing} onClose={() => (setSharing(null), reload())} />}
      {connecting && (
        <ConnectDialog
          server={connecting}
          onClose={() => setConnecting(null)}
          onConnect={(choice) => (setConnecting(null), onConnect(connecting, choice))}
        />
      )}
    </section>
  );
}

/** "prod, web" → ["prod", "web"]. The server tidies repeats and rejects anything unusable. */
function parseTags(text: string): string[] {
  return text.split(',').map((t) => t.trim()).filter(Boolean);
}

function authLabel(m: AuthMethod) {
  return m === 'key' ? 'SSH key' : m === 'password' ? 'Saved password' : 'Asks for password';
}

function ServerForm({ server, knownTags, isAdmin, onClose, onSaved }: { server: Server | null; knownTags: string[]; isAdmin: boolean; onClose: () => void; onSaved: () => void }) {
  const isOwner = !server || server.access === 'owner';
  const keys = useAsync(() => (isOwner ? get<{ keys: SshKey[] }>('/api/keys') : Promise.resolve({ keys: [] })), []);
  const [name, setName] = useState(server?.name ?? '');
  const [host, setHost] = useState(server?.host ?? '');
  const [port, setPort] = useState(String(server?.port ?? 22));
  const [username, setUsername] = useState(server?.username ?? '');
  const [authMethod, setAuthMethod] = useState<AuthMethod>(server?.authMethod ?? 'key');
  const [keyId, setKeyId] = useState(server?.key?.id ?? '');
  const [password, setPassword] = useState('');
  const [notes, setNotes] = useState(server?.notes ?? '');
  const [tags, setTags] = useState((server?.tags ?? []).join(', '));
  const [jumpMode, setJumpMode] = useState<JumpMode>(server?.jump.mode ?? 'none');
  const [jumpHostId, setJumpHostId] = useState(server?.jump.host?.id ?? '');
  const jumpHosts = useAsync(() => (isOwner && isAdmin ? get<{ jumpHosts: JumpHost[] }>('/api/admin/jump-hosts') : Promise.resolve({ jumpHosts: [] })), []);
  // A non-admin owner cannot move a server off a jump host an admin picked.
  const jumpLocked = !isAdmin && server?.jump.mode === 'fixed';
  const confirm = useConfirm();
  const toast = useToast();

  const save = async () => {
    if (!isOwner) {
      await patch(`/api/servers/${server!.id}`, { name, notes, tags: parseTags(tags) });
      return onSaved();
    }
    const body: Record<string, unknown> = { name, host, port: Number(port), username, authMethod, notes, tags: parseTags(tags) };
    if (!jumpLocked) Object.assign(body, { jumpMode, jumpHostId: jumpMode === 'fixed' ? jumpHostId : null });
    if (authMethod === 'key') body.keyId = keyId || null;
    if (authMethod === 'password' && password) body.password = password;
    if (server) await patch(`/api/servers/${server.id}`, body);
    else await post('/api/servers', body);
    onSaved();
  };

  return (
    <Modal title={server ? `Edit ${server.name}` : 'Add server'} onClose={onClose}>
      <Form submit="Save changes" success={server ? `${server.name} saved.` : 'Server added.'} onSubmit={save}>
        <Field label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
        </Field>
        {isOwner ? (
          <>
            <div className="row2">
              <Field label="Host">
                <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="server.example.com" autoCapitalize="none" required />
              </Field>
              <Field label="Port">
                <input value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" required />
              </Field>
            </div>
            <Field label="SSH username">
              <input value={username} onChange={(e) => setUsername(e.target.value)} autoCapitalize="none" required />
            </Field>
            <Field label="Authentication">
              <select value={authMethod} onChange={(e) => setAuthMethod(e.target.value as AuthMethod)}>
                <option value="key">SSH key (recommended)</option>
                <option value="prompt">Ask for the password each time</option>
                <option value="password">Save password (stored encrypted)</option>
              </select>
            </Field>
            {authMethod === 'key' && (
              <Field label="SSH key" hint={keys.data?.keys.length === 0 ? 'You don’t have any SSH keys yet. Create one on the SSH keys page.' : undefined}>
                <select value={keyId} onChange={(e) => setKeyId(e.target.value)} required>
                  <option value="">Select an SSH key…</option>
                  {keys.data?.keys.map((k) => (
                    <option key={k.id} value={k.id}>
                      {k.name} ({k.type})
                    </option>
                  ))}
                </select>
              </Field>
            )}
            {authMethod === 'password' && (
              <Field label="Password" hint={server?.hasStoredPassword ? 'Leave blank to keep the saved password.' : undefined}>
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" required={!server?.hasStoredPassword} />
              </Field>
            )}
            <Field
              label="Connection route"
              hint={
                jumpLocked
                  ? `An administrator set this server to connect through ${server?.jump.host?.name ?? 'a jump host'}. Only an administrator can change this.`
                  : 'With a jump host, Any-SSH reaches this server through a relay. Your sign-in stays end to end encrypted, so the jump host never sees your credentials.'
              }
            >
              <select value={jumpMode} onChange={(e) => setJumpMode(e.target.value as JumpMode)} disabled={jumpLocked}>
                <option value="none">Connect directly from Any-SSH</option>
                <option value="auto">Use the closest jump host</option>
                {(isAdmin || jumpMode === 'fixed') && <option value="fixed">Use a specific jump host (administrators only)</option>}
              </select>
            </Field>
            {jumpMode === 'fixed' && !jumpLocked && (
              <Field label="Jump host">
                <select value={jumpHostId} onChange={(e) => setJumpHostId(e.target.value)} required>
                  <option value="">Select a jump host…</option>
                  {jumpHosts.data?.jumpHosts.map((j) => (
                    <option key={j.id} value={j.id}>
                      {j.name}
                      {j.enabled ? '' : ' (turned off)'}
                    </option>
                  ))}
                </select>
              </Field>
            )}
          </>
        ) : (
          <p className="muted">Only the owner can change the connection details and credentials.</p>
        )}
        <Field label="Tags" hint="Separate tags with commas. You can add up to 10.">
          <input value={tags} onChange={(e) => setTags(e.target.value)} autoCapitalize="none" maxLength={400} />
        </Field>
        {knownTags.filter((t) => !parseTags(tags).some((x) => x.toLowerCase() === t.toLowerCase())).length > 0 && (
          <div className="tag-filter" aria-label="Existing tags">
            {knownTags
              .filter((t) => !parseTags(tags).some((x) => x.toLowerCase() === t.toLowerCase()))
              .slice(0, 12)
              .map((t) => (
                <button type="button" key={t} className="tag" onClick={() => setTags([...parseTags(tags), t].join(', '))}>
                  + {t}
                </button>
              ))}
          </div>
        )}
        <Field label="Notes">
          <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={2} />
        </Field>
      </Form>
      {server && (
        <div className="subsection">
          <HostKeyPanel server={server} isOwner={isOwner} onChanged={onSaved} />
          {isOwner && (
            <button
              className="danger-outline"
              onClick={async () => {
                const ok = await confirm({
                  title: `Delete ${server.name}?`,
                  message: 'The server is deleted for everyone it’s shared with, and open terminals are closed. This can’t be undone.',
                  confirmLabel: 'Delete server',
                  danger: true,
                });
                if (!ok) return;
                await del(`/api/servers/${server.id}`);
                toast.success(`${server.name} deleted.`);
                onSaved();
              }}
            >
              Delete server
            </button>
          )}
        </div>
      )}
    </Modal>
  );
}

function ShareDialog({ server, onClose }: { server: Server; onClose: () => void }) {
  const shares = useAsync(() => get<{ shares: Share[] }>(`/api/servers/${server.id}/shares`), [server.id]);
  const [q, setQ] = useState('');
  const directory = useAsync(
    () => (q.trim() ? get<{ users: { id: string; username: string; displayName: string }[] }>(`/api/users/directory?q=${encodeURIComponent(q)}`) : Promise.resolve({ users: [] })),
    [q],
  );
  const [error, setError] = useState<string | null>(null);
  // A manager who was made to bring their own credentials cannot pass the owner's on.
  const [newCredentials, setNewCredentials] = useState<ShareCredentials>(server.credentials === 'own' ? 'own' : 'owner');
  const isOwner = server.access === 'owner';
  const already = new Set(shares.data?.shares.map((s) => s.userId));
  const toast = useToast();
  const run = async (fn: () => Promise<unknown>, done: string) => {
    setError(null);
    try {
      await fn();
      toast.success(done);
      shares.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  const update = (s: Share, change: Partial<Pick<Share, 'permission' | 'credentials' | 'canReshare'>>) =>
    run(
      () =>
        put(`/api/servers/${server.id}/shares/${s.userId}`, {
          permission: change.permission ?? s.permission,
          credentials: change.credentials ?? s.credentials,
          canReshare: change.canReshare ?? s.canReshare,
        }),
      `Sharing updated for @${s.username}.`,
    );

  return (
    <Modal title={`Share ${server.name}`} onClose={onClose}>
      <p className="muted small">
        <strong>Use</strong> lets people connect to the server. <strong>Manage</strong> also lets them edit it. They can never see saved credentials.
      </p>
      {error && <p className="error">{error}</p>}
      <ul className="list">
        {shares.data?.shares.map((s) => (
          <li key={s.userId} className="share-row">
            <div>
              <span>
                {s.displayName} <span className="muted">@{s.username}</span>
              </span>
              {s.sharedBy && s.sharedBy !== server.owner?.username && <span className="badge">Shared by {s.sharedBy}</span>}
            </div>
            <div className="row wrap">
              <select value={s.permission} disabled={!isOwner} onChange={(e) => update(s, { permission: e.target.value as Share['permission'] })}>
                <option value="use">Use</option>
                <option value="manage">Manage</option>
              </select>
              <select
                value={s.credentials}
                disabled={!isOwner && server.credentials === 'own'}
                onChange={(e) => update(s, { credentials: e.target.value as ShareCredentials })}
              >
                <option value="owner">Saved credentials</option>
                <option value="own">Their own credentials</option>
              </select>
              {s.permission === 'manage' && (
                <label className="check small">
                  <input type="checkbox" checked={s.canReshare} disabled={!isOwner} onChange={(e) => update(s, { canReshare: e.target.checked })} />
                  Can share with others
                </label>
              )}
              {(isOwner || s.permission === 'use') && (
                <button className="ghost" onClick={() => run(() => del(`/api/servers/${server.id}/shares/${s.userId}`), `Stopped sharing with @${s.username}.`)}>
                  Remove
                </button>
              )}
            </div>
          </li>
        ))}
        {shares.data?.shares.length === 0 && <li className="muted">Not shared with anyone yet.</li>}
      </ul>
      <Field label="Share with">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by name or username" autoCapitalize="none" />
      </Field>
      <Field label="Credentials they use" hint={server.credentials === 'own' ? 'You use your own credentials for this server, so people you share it with must use theirs too.' : undefined}>
        <select value={newCredentials} disabled={server.credentials === 'own'} onChange={(e) => setNewCredentials(e.target.value as ShareCredentials)}>
          <option value="owner">The server’s saved credentials</option>
          <option value="own">Their own credentials</option>
        </select>
      </Field>
      <ul className="list">
        {directory.data?.users
          .filter((u) => !already.has(u.id) && u.id !== server.owner?.id)
          .map((u) => (
            <li key={u.id}>
              <span>
                {u.displayName} <span className="muted">@{u.username}</span>
              </span>
              <button onClick={() =>
                run(() => put(`/api/servers/${server.id}/shares/${u.id}`, { permission: 'use', credentials: newCredentials }), `${server.name} shared with @${u.username}.`)
              }>
                Share
              </button>
            </li>
          ))}
      </ul>
    </Modal>
  );
}

const CONNECT_PREF = 'anyssh.connectAs.';
type ConnectPref = { kind: ConnectCredential['type']; keyId?: string; username?: string };

/** Last "Connect as" choice per server. Never holds key material: a one-off key is not stored. */
function loadPref(serverId: string): ConnectPref | null {
  try {
    return JSON.parse(localStorage.getItem(CONNECT_PREF + serverId) ?? 'null');
  } catch {
    return null;
  }
}
function savePref(serverId: string, pref: ConnectPref) {
  try {
    localStorage.setItem(CONNECT_PREF + serverId, JSON.stringify(pref));
  } catch {
    /* storage unavailable: the choice just isn't remembered */
  }
}

/** Picks the credentials for one connection. A one-off key stays in this component and in memory only. */
function ConnectDialog({ server, onClose, onConnect }: { server: Server; onClose: () => void; onConnect: (c: ConnectChoice) => void }) {
  const mustBringOwn = server.credentials === 'own';
  const keys = useAsync(() => get<{ keys: SshKey[] }>('/api/keys'), []);
  const pref = loadPref(server.id);
  const initial = pref && !(mustBringOwn && pref.kind === 'saved') ? pref.kind : mustBringOwn ? 'oneoff' : 'saved';
  const [kind, setKind] = useState<ConnectCredential['type']>(initial);
  const [keyId, setKeyId] = useState(pref?.keyId ?? '');
  const [privateKey, setPrivateKey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [username, setUsername] = useState(pref?.username ?? server.username);

  const submit = async () => {
    const credential: ConnectCredential =
      kind === 'saved'
        ? { type: 'saved' }
        : kind === 'key'
          ? { type: 'key', keyId }
          : kind === 'oneoff'
            ? { type: 'oneoff', privateKey, ...(passphrase ? { passphrase } : {}) }
            : { type: 'password' };
    savePref(server.id, { kind, ...(kind === 'key' ? { keyId } : {}), ...(kind === 'saved' ? {} : { username }) });
    onConnect({ credential, ...(kind === 'saved' ? {} : { username }) });
    setPrivateKey('');
    setPassphrase('');
  };

  return (
    <Modal title={`Connect to ${server.name}`} onClose={onClose}>
      <Form submit="Connect" onSubmit={submit}>
        <Field label="Connect as">
          <select value={kind} onChange={(e) => setKind(e.target.value as ConnectCredential['type'])}>
            {!mustBringOwn && <option value="saved">Saved credentials</option>}
            <option value="key">One of my SSH keys</option>
            <option value="oneoff">Paste a key (one time)</option>
            <option value="password">Password</option>
          </select>
        </Field>
        {kind !== 'saved' && (
          <Field label="Username">
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoCapitalize="none" required />
          </Field>
        )}
        {kind === 'key' && (
          <Field label="Key" hint={keys.data?.keys.length === 0 ? 'You don’t have any SSH keys yet. Add one on the SSH keys page.' : undefined}>
            <select value={keyId} onChange={(e) => setKeyId(e.target.value)} required>
              <option value="">Select an SSH key…</option>
              {keys.data?.keys.map((k) => (
                <option key={k.id} value={k.id}>
                  {k.name} ({k.type})
                </option>
              ))}
            </select>
          </Field>
        )}
        {kind === 'oneoff' && (
          <>
            <Field label="Private key" hint="Used for this connection only and never saved.">
              <textarea
                className="mono"
                value={privateKey}
                onChange={(e) => setPrivateKey(e.target.value)}
                rows={5}
                spellCheck={false}
                autoComplete="off"
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                required
              />
            </Field>
            <Field label="Passphrase (optional)">
              <input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoComplete="off" />
            </Field>
          </>
        )}
        {kind === 'password' && <p className="muted small">You’ll be asked for the password when the terminal opens.</p>}
      </Form>
    </Modal>
  );
}

function HostKeyPanel({ server, isOwner, onChanged }: { server: Server; isOwner: boolean; onChanged: () => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [reviewing, setReviewing] = useState(false);
  const pin = server.hostKey;
  const change = server.hostKeyChange;
  const toast = useToast();
  const confirm = useConfirm();
  const run = async (fn: () => Promise<unknown>, done: string) => {
    setError(null);
    try {
      await fn();
      toast.success(done);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  if (!pin && !change) return <p className="muted small">Server fingerprint: not verified yet. You’ll be shown it the first time you connect.</p>;
  return (
    <div className="hostkey-panel">
      {change && (
        <div className="card warn-card">
          <p className="error">
            <strong>This server presented a different fingerprint, so the connection was blocked.</strong> Seen {formatTime(change.seenAt)}.
          </p>
          <p className="muted small">Saved fingerprint</p>
          <p className="fingerprint mono">{pin?.fingerprint}</p>
          <p className="muted small">Fingerprint the server presented</p>
          <p className="fingerprint mono">
            {change.type ?? ''}
            <br />
            {change.fingerprint}
          </p>
          {isOwner ? (
            reviewing ? (
              <>
                <p className="muted small">
                  Only accept it if you reinstalled this server or changed its keys, and you’ve checked this fingerprint on the server itself (<code>ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub</code>).
                </p>
                <Field label="Your password">
                  <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
                </Field>
                <div className="row">
                  <button
                    className="danger"
                    disabled={!password}
                    onClick={() => run(() => post(`/api/servers/${server.id}/host-key/accept`, { fingerprint: change.fingerprint, password }), 'New fingerprint accepted.')}
                  >
                    Accept new fingerprint
                  </button>
                  <button onClick={() => setReviewing(false)}>Back</button>
                </div>
              </>
            ) : (
              <div className="row">
                <button className="danger-outline" onClick={() => setReviewing(true)}>
                  Review and accept
                </button>
                <button onClick={() => run(() => post(`/api/servers/${server.id}/host-key/dismiss`), 'Warning dismissed. The saved fingerprint is unchanged.')}>Dismiss and keep the saved fingerprint</button>
              </div>
            )
          ) : (
            <p className="muted small">Only the owner can accept a new fingerprint.</p>
          )}
        </div>
      )}
      {pin && (
        <p className="muted small">
          Server fingerprint: <code>{pin.fingerprint}</code>
          {pin.type ? ` (${pin.type})` : ''}
          {pin.pinnedAt ? ` · trusted since ${formatTime(pin.pinnedAt)}${pin.pinnedBy ? ` by ${pin.pinnedBy}` : ''}` : ''}{' '}
          {isOwner && (
            <button
              className="link"
              onClick={async () => {
                const ok = await confirm({
                  title: `Remove the saved fingerprint for ${server.name}?`,
                  message: 'You’ll be asked to verify the server’s fingerprint again the next time you connect.',
                  confirmLabel: 'Remove fingerprint',
                  danger: true,
                });
                if (ok) await run(() => post(`/api/servers/${server.id}/forget-host-key`), 'Saved fingerprint removed.');
              }}
            >
              Remove fingerprint
            </button>
          )}
        </p>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
