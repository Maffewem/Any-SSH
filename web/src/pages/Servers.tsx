import { useState } from 'react';
import { del, get, patch, post, put, type AuthMethod, type ConnectChoice, type ConnectCredential, type Server, type Share, type ShareCredentials, type SshKey } from '../api';
import { Field, Form, Modal, useAsync } from '../ui';

export function ServersPage({ onConnect }: { onConnect: (s: Server, choice?: ConnectChoice) => void }) {
  const { data, error, reload } = useAsync(() => get<{ servers: Server[] }>('/api/servers'), []);
  const [editing, setEditing] = useState<Server | 'new' | null>(null);
  const [sharing, setSharing] = useState<Server | null>(null);
  const [connecting, setConnecting] = useState<Server | null>(null);
  const [filter, setFilter] = useState('');

  const servers = (data?.servers ?? []).filter((s) =>
    `${s.name} ${s.host} ${s.username}`.toLowerCase().includes(filter.toLowerCase()),
  );

  return (
    <section>
      <div className="page-head">
        <h1>Servers</h1>
        <button className="primary" onClick={() => setEditing('new')}>
          Add server
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {data && data.servers.length > 4 && (
        <input className="search" placeholder="Filter servers" value={filter} onChange={(e) => setFilter(e.target.value)} />
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
                {!s.hostKeyFingerprint && <span className="badge warn">Host key not verified</span>}
              </div>
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

function authLabel(m: AuthMethod) {
  return m === 'key' ? 'SSH key' : m === 'password' ? 'Stored password' : 'Password on connect';
}

function ServerForm({ server, onClose, onSaved }: { server: Server | null; onClose: () => void; onSaved: () => void }) {
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
  const [confirmDelete, setConfirmDelete] = useState(false);

  const save = async () => {
    if (!isOwner) {
      await patch(`/api/servers/${server!.id}`, { name, notes });
      return onSaved();
    }
    const body: Record<string, unknown> = { name, host, port: Number(port), username, authMethod, notes };
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
          </>
        ) : (
          <p className="muted">Only the owner can change connection details and credentials.</p>
        )}
        <Field label="Notes">
          <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={2} />
        </Field>
      </Form>
      {server && (
        <div className="subsection">
          {server.hostKeyFingerprint && (
            <p className="muted small">
              Host key: <code>{server.hostKeyFingerprint}</code>{' '}
              <button
                className="link"
                onClick={async () => {
                  if (confirm('Forget the pinned host key? You will be asked to verify it again on the next connection.')) {
                    await post(`/api/servers/${server.id}/forget-host-key`);
                    onSaved();
                  }
                }}
              >
                Forget
              </button>
            </p>
          )}
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
