import { useState } from 'react';
import { del, get, patch, post, put, type AuthMethod, type Server, type Share, type SshKey } from '../api';
import { Field, Form, Modal, useAsync } from '../ui';

export function ServersPage({ onConnect }: { onConnect: (s: Server) => void }) {
  const { data, error, reload } = useAsync(() => get<{ servers: Server[] }>('/api/servers'), []);
  const [editing, setEditing] = useState<Server | 'new' | null>(null);
  const [sharing, setSharing] = useState<Server | null>(null);
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
                <span className="badge">{authLabel(s.authMethod)}</span>
                {!s.hostKeyFingerprint && <span className="badge warn">Host key not verified</span>}
              </div>
            </div>
            <div className="actions">
              <button className="primary" onClick={() => onConnect(s)}>
                Connect
              </button>
              {s.access !== 'use' && <button onClick={() => setEditing(s)}>Edit</button>}
              {s.access !== 'use' && <button onClick={() => setSharing(s)}>Share</button>}
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

  return (
    <Modal title={`Share ${server.name}`} onClose={onClose}>
      <p className="muted small">
        People you share with connect through Any-SSH using this server’s credentials. They never see the private key or
        password. <strong>Use</strong> lets them connect; <strong>Manage</strong> also lets them rename it and share it for use.
      </p>
      {error && <p className="error">{error}</p>}
      <ul className="list">
        {shares.data?.shares.map((s) => (
          <li key={s.userId}>
            <span>
              {s.displayName} <span className="muted">@{s.username}</span>
            </span>
            <span className="row">
              <select
                value={s.permission}
                disabled={!isOwner}
                onChange={(e) => run(() => put(`/api/servers/${server.id}/shares/${s.userId}`, { permission: e.target.value }))}
              >
                <option value="use">Use</option>
                <option value="manage">Manage</option>
              </select>
              {(isOwner || s.permission === 'use') && (
                <button className="ghost" onClick={() => run(() => del(`/api/servers/${server.id}/shares/${s.userId}`))}>
                  Remove
                </button>
              )}
            </span>
          </li>
        ))}
        {shares.data?.shares.length === 0 && <li className="muted">Not shared with anyone yet.</li>}
      </ul>
      <Field label="Add people">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by name or username" autoCapitalize="none" />
      </Field>
      <ul className="list">
        {directory.data?.users
          .filter((u) => !already.has(u.id) && u.id !== server.owner?.id)
          .map((u) => (
            <li key={u.id}>
              <span>
                {u.displayName} <span className="muted">@{u.username}</span>
              </span>
              <button onClick={() => run(() => put(`/api/servers/${server.id}/shares/${u.id}`, { permission: 'use' }))}>Share</button>
            </li>
          ))}
      </ul>
    </Modal>
  );
}
