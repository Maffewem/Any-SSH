import { useState } from 'react';
import { formatTime, get, patch, post, type AuditEntry, type HostKeyRow, type User } from '../api';
import { Field, Form, Modal, SecretOnce, useAsync } from '../ui';
import { DeleteAccountForm } from './DeleteAccount';

interface LinkResult {
  purpose: 'invite' | 'reset';
  sent: boolean;
  url?: string;
  error?: string;
}

function LinkResultView({ result, email }: { result: LinkResult; email: string | null }) {
  if (result.sent) {
    return <p className="ok">{result.purpose === 'invite' ? 'An invite' : 'A password reset link'} was emailed to {email}.</p>;
  }
  return (
    <div>
      <p className="muted small">
        {result.error ?? 'Email is not configured on this server, so nothing was sent.'} Give them this single-use link over a channel you
        trust:
      </p>
      {result.url && <SecretOnce label="Link." value={result.url} />}
    </div>
  );
}

export function AdminUsersPage({ me }: { me: User }) {
  const { data, error, reload } = useAsync(() => get<{ users: User[] }>('/api/admin/users'), []);
  const [creating, setCreating] = useState(false);
  const [selected, setSelected] = useState<User | null>(null);

  return (
    <section>
      <div className="page-head">
        <h1>Users</h1>
        <button className="primary" onClick={() => setCreating(true)}>
          Add user
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      <div className="table-wrap card">
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <th>Status</th>
              <th>2FA</th>
              <th>Last sign-in</th>
            </tr>
          </thead>
          <tbody>
            {data?.users.map((u) => (
              <tr key={u.id} onClick={() => setSelected(u)} className="clickable">
                <td>
                  {u.displayName}
                  <br />
                  <span className="muted small">@{u.username}</span>
                </td>
                <td>{u.role === 'admin' ? 'Admin' : 'User'}</td>
                <td>
                  {u.status === 'disabled' ? (
                    <span className="badge warn">Disabled</span>
                  ) : u.locked ? (
                    <span className="badge warn">Locked</span>
                  ) : u.mustChangePassword ? (
                    <span className="badge">Pending first sign-in</span>
                  ) : (
                    'Active'
                  )}
                </td>
                <td>{u.mfaEnabled ? 'On' : <span className="muted">Off</span>}</td>
                <td className="small">{formatTime(u.lastLoginAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {creating && <CreateUserDialog onClose={() => (setCreating(false), reload())} />}
      {selected && <EditUserDialog user={selected} isSelf={selected.id === me.id} onClose={() => (setSelected(null), reload())} />}
    </section>
  );
}

function CreateUserDialog({ onClose }: { onClose: () => void }) {
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<'user' | 'admin'>('user');
  const [created, setCreated] = useState<{ username: string; email: string | null; temporaryPassword?: string; invite?: LinkResult } | null>(null);

  return (
    <Modal title="Add user" onClose={onClose}>
      {created ? (
        <div>
          {created.temporaryPassword ? (
            <>
              <p>
                <strong>@{created.username}</strong> was created. Send them this temporary password over a channel you trust; they
                must replace it when they first sign in.
              </p>
              <SecretOnce label="Temporary password." value={created.temporaryPassword} />
            </>
          ) : (
            <>
              <p>
                <strong>@{created.username}</strong> was created.
              </p>
              {created.invite && <LinkResultView result={created.invite} email={created.email} />}
            </>
          )}
          <button className="primary" onClick={onClose}>
            Done
          </button>
        </div>
      ) : (
        <Form
          submit="Create user"
          onSubmit={async () => {
            const res = await post<{ user: User; temporaryPassword?: string; invite?: LinkResult }>('/api/admin/users', {
              username,
              ...(displayName ? { displayName } : {}),
              ...(email ? { email } : {}),
              role,
            });
            setCreated({ username: res.user.username, email: res.user.email, temporaryPassword: res.temporaryPassword, invite: res.invite });
          }}
        >
          <Field label="Username">
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoCapitalize="none" required autoFocus />
          </Field>
          <Field label="Display name">
            <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          </Field>
          <Field label="Email" hint="With an email, they get an invite link to set their own password. Without one, you get a temporary password to pass on.">
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </Field>
          <Field label="Role">
            <select value={role} onChange={(e) => setRole(e.target.value as 'user' | 'admin')}>
              <option value="user">User</option>
              <option value="admin">Administrator</option>
            </select>
          </Field>
        </Form>
      )}
    </Modal>
  );
}

function EditUserDialog({ user, isSelf, onClose }: { user: User; isSelf: boolean; onClose: () => void }) {
  const [displayName, setDisplayName] = useState(user.displayName);
  const [email, setEmail] = useState(user.email ?? '');
  const [link, setLink] = useState<LinkResult | null>(null);
  const [role, setRole] = useState(user.role);
  const [status, setStatus] = useState(user.status);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tempPassword, setTempPassword] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  const action = async (label: string, fn: () => Promise<unknown>) => {
    if (!confirm(`${label} for @${user.username}?`)) return;
    setError(null);
    try {
      await fn();
      setMessage(`${label}: done.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Modal title={`@${user.username}`} onClose={onClose}>
      <Form
        submit="Save"
        onSubmit={async () => {
          const emailField = email.trim() !== (user.email ?? '') ? { email: email.trim() || null } : {};
          await patch(`/api/admin/users/${user.id}`, isSelf ? { displayName, ...emailField } : { displayName, ...emailField, role, status });
          onClose();
        }}
      >
        <Field label="Display name">
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} required />
        </Field>
        <Field label="Email">
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        </Field>
        <Field label="Role" hint={isSelf ? 'You cannot change your own role.' : undefined}>
          <select value={role} disabled={isSelf} onChange={(e) => setRole(e.target.value as User['role'])}>
            <option value="user">User</option>
            <option value="admin">Administrator</option>
          </select>
        </Field>
        <Field label="Status" hint={isSelf ? undefined : 'Disabling signs them out and closes their terminals immediately.'}>
          <select value={status} disabled={isSelf} onChange={(e) => setStatus(e.target.value as User['status'])}>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </select>
        </Field>
      </Form>
      {!isSelf && (
        <div className="subsection">
          {message && <p className="ok">{message}</p>}
          {error && <p className="error">{error}</p>}
          {tempPassword && <SecretOnce label="New temporary password." value={tempPassword} />}
          {link && <LinkResultView result={link} email={user.email} />}
          <div className="row wrap">
            {user.email && user.status === 'active' && (
              <button
                onClick={() =>
                  action(user.lastLoginAt ? 'Email a password reset link' : 'Resend the invite', async () => {
                    setLink(await post<LinkResult>(`/api/admin/users/${user.id}/send-link`));
                  })
                }
              >
                {user.lastLoginAt ? 'Email reset link' : 'Resend invite'}
              </button>
            )}
            <button
              onClick={() =>
                action('Reset password', async () => {
                  const res = await post<{ temporaryPassword: string }>(`/api/admin/users/${user.id}/reset-password`);
                  setTempPassword(res.temporaryPassword);
                })
              }
            >
              Reset password
            </button>
            {user.mfaEnabled && <button onClick={() => action('Reset two-factor', () => post(`/api/admin/users/${user.id}/reset-mfa`))}>Reset 2FA</button>}
            <button onClick={() => action('Turn off their trusted IP list', () => post(`/api/admin/users/${user.id}/reset-trusted-ips`))}>Reset trusted IPs</button>
            {user.locked && <button onClick={() => action('Unlock', () => post(`/api/admin/users/${user.id}/unlock`))}>Unlock</button>}
            <button onClick={() => action('Sign out of all devices', () => post(`/api/admin/users/${user.id}/sign-out`))}>Sign out all devices</button>
            <button className="danger-outline" onClick={() => setDeleting((d) => !d)}>
              {deleting ? 'Cancel deletion' : 'Delete account…'}
            </button>
          </div>
          {deleting && <DeleteAccountForm self={false} userId={user.id} username={user.username} onDeleted={onClose} />}
        </div>
      )}
    </Modal>
  );
}

export function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [filter, setFilter] = useState('');
  const [verify, setVerify] = useState<string | null>(null);
  const { error } = useAsync(async () => {
    const res = await get<{ entries: AuditEntry[] }>(`/api/admin/audit?limit=100${filter ? `&action=${encodeURIComponent(filter)}` : ''}`);
    setEntries(res.entries);
    return res;
  }, [filter]);

  const more = async () => {
    const last = entries[entries.length - 1];
    if (!last) return;
    const res = await get<{ entries: AuditEntry[] }>(
      `/api/admin/audit?limit=100&before=${last.seq}${filter ? `&action=${encodeURIComponent(filter)}` : ''}`,
    );
    setEntries([...entries, ...res.entries]);
  };

  return (
    <section>
      <div className="page-head">
        <h1>Audit log</h1>
        <button
          onClick={async () => {
            const r = await get<{ ok: boolean; checked: number; brokenAt: number | null }>('/api/admin/audit/verify');
            setVerify(r.ok ? `Chain intact (${r.checked} entries).` : `Chain BROKEN at entry #${r.brokenAt}. The log has been tampered with.`);
          }}
        >
          Verify integrity
        </button>
      </div>
      {verify && <p className={verify.startsWith('Chain intact') ? 'ok' : 'error'}>{verify}</p>}
      <select className="search" value={filter} onChange={(e) => setFilter(e.target.value)}>
        <option value="">All events</option>
        <option value="auth.">Sign-ins</option>
        <option value="auth.lockout">Lockouts</option>
        <option value="ssh.">SSH sessions</option>
        <option value="share.">Sharing</option>
        <option value="server.">Servers</option>
        <option value="key.">Keys</option>
        <option value="admin.">Administration</option>
        <option value="system.">Software updates</option>
        <option value="user.">Account changes</option>
      </select>
      {error && <p className="error">{error}</p>}
      <div className="table-wrap card">
        <table className="small">
          <thead>
            <tr>
              <th>#</th>
              <th>Time</th>
              <th>Who</th>
              <th>Event</th>
              <th>Details</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.seq} className={e.outcome === 'failure' ? 'failure' : ''}>
                <td>{e.seq}</td>
                <td>{formatTime(e.ts)}</td>
                <td>{e.actorUsername ?? '—'}</td>
                <td>
                  {e.action}
                  {e.outcome === 'failure' && <span className="badge warn">failed</span>}
                </td>
                <td className="mono details">{Object.keys(e.details).length ? JSON.stringify(e.details) : ''}</td>
                <td>{e.ip}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {entries.length > 0 && entries.length % 100 === 0 && <button onClick={more}>Load older</button>}
    </section>
  );
}

export function HostKeysPage() {
  const { data, error } = useAsync(() => get<{ hosts: HostKeyRow[] }>('/api/admin/host-keys'), []);
  return (
    <section>
      <div className="page-head">
        <h1>Host keys</h1>
      </div>
      <p className="muted small">
        The server fingerprint each saved server is pinned to. Admins can see these but cannot change them: only a server’s owner can
        accept a new key. A changed key, or two servers pinned to different keys for the same host, deserves a look.
      </p>
      {error && <p className="error">{error}</p>}
      <div className="table-wrap card">
        <table className="small">
          <thead>
            <tr>
              <th>Server</th>
              <th>Owner</th>
              <th>Pinned fingerprint</th>
              <th>Trusted</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {data?.hosts.map((h) => (
              <tr key={h.serverId} className={h.hostKeyChange ? 'failure' : ''}>
                <td>
                  {h.name}
                  <br />
                  <span className="muted mono">
                    {h.host}
                    {h.port !== 22 ? `:${h.port}` : ''}
                  </span>
                </td>
                <td>@{h.owner.username}</td>
                <td className="mono details">
                  {h.hostKey ? (
                    <>
                      {h.hostKey.type ?? ''} {h.hostKey.fingerprint}
                    </>
                  ) : (
                    '—'
                  )}
                  {h.hostKeyChange && (
                    <>
                      <br />
                      <span className="error">Presented: {h.hostKeyChange.type ?? ''} {h.hostKeyChange.fingerprint}</span>
                    </>
                  )}
                </td>
                <td>{h.hostKey?.pinnedAt ? `${formatTime(h.hostKey.pinnedAt)}${h.hostKey.pinnedBy ? ` by ${h.hostKey.pinnedBy}` : ''}` : '—'}</td>
                <td>
                  {h.hostKeyChange ? (
                    <span className="badge warn">Key changed</span>
                  ) : !h.hostKey ? (
                    <span className="badge">Not verified</span>
                  ) : h.conflict ? (
                    <span className="badge warn">Conflicts with another pin</span>
                  ) : (
                    'OK'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
