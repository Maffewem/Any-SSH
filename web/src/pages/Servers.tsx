import { useState } from 'react';
import { del, formatTime, get, patch, post, put, type AuthMethod, type ConnectChoice, type ConnectCredential, type JumpHost, type JumpMode, type Server, type Share, type ShareCredentials, type SshKey } from '../api';
import { Field, Form, Modal, useAsync } from '../ui';

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
            title="Matches name, host, user, notes, owner and tags"
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
          <p>No servers yet. Add one, or ask someone to share theirs with you.</p>
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
                        {s.access === 'manage' ? 'Manager' : 'Shared'} · from {s.owner?.displayName ?? 'unknown'}
                  </span>
                )}
                <span className="badge">{s.credentials === 'own' ? 'Your own credentials' : authLabel(s.authMethod)}</span>
                {s.hostKeyChange ? (
                  <span className="badge warn">Host key CHANGED</span>
                ) : (
                  !s.hostKeyFingerprint && <span className="badge warn">Host key not verified</span>
                )}
                {s.jump.mode !== 'none' && (
                  <span className="badge">{s.jump.mode === 'auto' ? 'Via closest jump host' : `Via ${s.jump.host?.name ?? 'missing jump host'}`}</span>
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
              <button title="Connect with different credentials" onClick={() => setConnecting(s)}>
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
  return m === 'key' ? 'SSH key' : m === 'password' ? 'Stored password' : 'Password on connect';
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
  const [confirmDelete, setConfirmDelete] = useState(false);

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
      <Form submit="Save" onSubmit={save}>
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
                <option value="prompt">Ask for password each time</option>
                <option value="password">Store password (encrypted)</option>
              </select>
            </Field>
            {authMethod === 'key' && (
              <Field label="Key" hint={keys.data?.keys.length === 0 ? 'You have no keys yet. Create one on the Keys page.' : undefined}>
                <select value={keyId} onChange={(e) => setKeyId(e.target.value)} required>
                  <option value="">Choose a key…</option>
                  {keys.data?.keys.map((k) => (
                    <option key={k.id} value={k.id}>
                      {k.name} ({k.type})
                    </option>
                  ))}
                </select>
              </Field>
            )}
            {authMethod === 'password' && (
              <Field label="Password" hint={server?.hasStoredPassword ? 'Leave blank to keep the stored password.' : undefined}>
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" required={!server?.hasStoredPassword} />
              </Field>
            )}
            <Field
              label="Route"
              hint={
                jumpLocked
                  ? `An admin sends this server through ${server?.jump.host?.name ?? 'a jump host'}. Only an admin can change that.`
                  : 'Through a jump host, Any-SSH reaches this server over a relay, and your login to it stays end to end: the jump host never sees your credentials.'
              }
            >
              <select value={jumpMode} onChange={(e) => setJumpMode(e.target.value as JumpMode)} disabled={jumpLocked}>
                <option value="none">Direct from Any-SSH</option>
                <option value="auto">Through the closest jump host</option>
                {(isAdmin || jumpMode === 'fixed') && <option value="fixed">Through a specific jump host (admin)</option>}
              </select>
            </Field>
            {jumpMode === 'fixed' && !jumpLocked && (
              <Field label="Jump host">
                <select value={jumpHostId} onChange={(e) => setJumpHostId(e.target.value)} required>
                  <option value="">Choose a jump host…</option>
                  {jumpHosts.data?.jumpHosts.map((j) => (
                    <option key={j.id} value={j.id}>
                      {j.name}
                      {j.enabled ? '' : ' (disabled)'}
                    </option>
                  ))}
                </select>
              </Field>
            )}
          </>
        ) : (
          <p className="muted">Only the owner can change connection details and credentials.</p>
        )}
        <Field label="Tags" hint="Separate with commas, e.g. prod, web, london. Up to 10. Anyone the server is shared with sees them.">
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
          {isOwner &&
            (confirmDelete ? (
              <button className="danger" onClick={async () => (await del(`/api/servers/${server.id}`), onSaved())}>
                Really delete {server.name}?
              </button>
            ) : (
              <button className="danger-outline" onClick={() => setConfirmDelete(true)}>
                Delete server
              </button>
            ))}
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
  const run = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      shares.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  const update = (s: Share, change: Partial<Pick<Share, 'permission' | 'credentials' | 'canReshare'>>) =>
    run(() =>
      put(`/api/servers/${server.id}/shares/${s.userId}`, {
        permission: change.permission ?? s.permission,
        credentials: change.credentials ?? s.credentials,
        canReshare: change.canReshare ?? s.canReshare,
      }),
    );

  return (
    <Modal title={`Share ${server.name}`} onClose={onClose}>
      <p className="muted small">
        <strong>Use</strong> lets someone connect; <strong>Manage</strong> also lets them rename it. Choose whether they
        connect with this server’s saved credentials (they never see the key or password) or must supply their own.
      </p>
      {error && <p className="error">{error}</p>}
      <ul className="list">
        {shares.data?.shares.map((s) => (
          <li key={s.userId} className="share-row">
            <div>
              <span>
                {s.displayName} <span className="muted">@{s.username}</span>
              </span>
              {s.sharedBy && s.sharedBy !== server.owner?.username && <span className="badge">shared by {s.sharedBy}</span>}
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
                  Can re-share
                </label>
              )}
              {(isOwner || s.permission === 'use') && (
                <button className="ghost" onClick={() => run(() => del(`/api/servers/${server.id}/shares/${s.userId}`))}>
                  Remove
                </button>
              )}
            </div>
          </li>
        ))}
        {shares.data?.shares.length === 0 && <li className="muted">Not shared with anyone yet.</li>}
      </ul>
      <Field label="Add people">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by name or username" autoCapitalize="none" />
      </Field>
      <Field label="They connect with" hint={server.credentials === 'own' ? 'You use your own credentials here, so anyone you share with must too.' : undefined}>
        <select value={newCredentials} disabled={server.credentials === 'own'} onChange={(e) => setNewCredentials(e.target.value as ShareCredentials)}>
          <option value="owner">This server’s saved credentials</option>
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
              <button onClick={() => run(() => put(`/api/servers/${server.id}/shares/${u.id}`, { permission: 'use', credentials: newCredentials }))}>
                Share
              </button>
            </li>
          ))}
      </ul>
    </Modal>
  );
}

/** Picks the credentials for one connection. A one-off key stays in this component and in memory only. */
function ConnectDialog({ server, onClose, onConnect }: { server: Server; onClose: () => void; onConnect: (c: ConnectChoice) => void }) {
  const mustBringOwn = server.credentials === 'own';
  const keys = useAsync(() => get<{ keys: SshKey[] }>('/api/keys'), []);
  const [kind, setKind] = useState<ConnectCredential['type']>(mustBringOwn ? 'oneoff' : 'saved');
  const [keyId, setKeyId] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [username, setUsername] = useState(server.username);

  const submit = async () => {
    const credential: ConnectCredential =
      kind === 'saved'
        ? { type: 'saved' }
        : kind === 'key'
          ? { type: 'key', keyId }
          : kind === 'oneoff'
            ? { type: 'oneoff', privateKey, ...(passphrase ? { passphrase } : {}) }
            : { type: 'password' };
    onConnect({ credential, ...(kind === 'saved' ? {} : { username }) });
    setPrivateKey('');
    setPassphrase('');
  };

  return (
    <Modal title={`Connect to ${server.name}`} onClose={onClose}>
      {mustBringOwn && <p className="muted small">The owner asked you to connect with your own credentials.</p>}
      <Form submit="Connect" onSubmit={submit}>
        <Field label="Credentials">
          <select value={kind} onChange={(e) => setKind(e.target.value as ConnectCredential['type'])}>
            {!mustBringOwn && <option value="saved">This server’s saved credentials</option>}
            <option value="key">One of my saved keys</option>
            <option value="oneoff">A one-off key (not saved)</option>
            <option value="password">Ask me for a password</option>
          </select>
        </Field>
        {kind !== 'saved' && (
          <Field label="SSH username">
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoCapitalize="none" required />
          </Field>
        )}
        {kind === 'key' && (
          <Field label="Key" hint={keys.data?.keys.length === 0 ? 'You have no keys yet. Create one on the Keys page.' : undefined}>
            <select value={keyId} onChange={(e) => setKeyId(e.target.value)} required>
              <option value="">Choose a key…</option>
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
            <Field label="Private key" hint="Used for this connection only. It is never written to the database and is gone when the session ends.">
              <textarea
                className="mono"
                value={privateKey}
                onChange={(e) => setPrivateKey(e.target.value)}
                rows={7}
                spellCheck={false}
                autoComplete="off"
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                required
              />
            </Field>
            <Field label="Passphrase (if the key has one)">
              <input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoComplete="off" />
            </Field>
          </>
        )}
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
  const run = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  if (!pin && !change) return <p className="muted small">Host key: not verified yet. You will be shown its fingerprint on the first connection.</p>;
  return (
    <div className="hostkey-panel">
      {change && (
        <div className="card warn-card">
          <p className="error">
            <strong>This server presented a different host key and was refused.</strong> Seen {formatTime(change.seenAt)}.
          </p>
          <p className="muted small">Pinned</p>
          <p className="fingerprint mono">{pin?.fingerprint}</p>
          <p className="muted small">Presented</p>
          <p className="fingerprint mono">
            {change.type ?? ''}
            <br />
            {change.fingerprint}
          </p>
          {isOwner ? (
            reviewing ? (
              <>
                <p className="muted small">
                  Only accept if you re-keyed or reinstalled this server and checked this fingerprint on the server itself
                  (<code>ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub</code>).
                </p>
                <Field label="Your password">
                  <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
                </Field>
                <div className="row">
                  <button
                    className="danger"
                    disabled={!password}
                    onClick={() => run(() => post(`/api/servers/${server.id}/host-key/accept`, { fingerprint: change.fingerprint, password }))}
                  >
                    Accept the new key
                  </button>
                  <button onClick={() => setReviewing(false)}>Back</button>
                </div>
              </>
            ) : (
              <div className="row">
                <button className="danger-outline" onClick={() => setReviewing(true)}>
                  Review and accept…
                </button>
                <button onClick={() => run(() => post(`/api/servers/${server.id}/host-key/dismiss`))}>Dismiss (keep the pinned key)</button>
              </div>
            )
          ) : (
            <p className="muted small">Only the owner can accept a new key.</p>
          )}
        </div>
      )}
      {pin && (
        <p className="muted small">
          Host key: <code>{pin.fingerprint}</code>
          {pin.type ? ` (${pin.type})` : ''}
          {pin.pinnedAt ? ` · trusted ${formatTime(pin.pinnedAt)}${pin.pinnedBy ? ` by ${pin.pinnedBy}` : ''}` : ''}{' '}
          {isOwner && (
            <button
              className="link"
              onClick={async () => {
                if (confirm('Forget the pinned host key? You will be asked to verify it again on the next connection.')) {
                  await run(() => post(`/api/servers/${server.id}/forget-host-key`));
                }
              }}
            >
              Forget
            </button>
          )}
        </p>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
