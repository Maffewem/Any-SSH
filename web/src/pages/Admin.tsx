import { useState } from 'react';
import { errorMessage, formatTime, get, patch, post, type AuditEntry, type HostKeyRow, type User } from '../api';
import { Field, Form, Modal, SecretOnce, useAsync, useConfirm, useToast } from '../ui';
import { DeleteAccountForm } from './DeleteAccount';

/** Plain-language names for audit events; an unknown event falls back to its code. */
const EVENT_LABELS: Record<string, string> = {
  'admin.backup_keypair': 'Backup key pair generated',
  'admin.backup_test': 'Backup destination tested',
  'admin.ip_unlock': 'IP address unblocked',
  'admin.servers_transfer': 'Servers transferred',
  'admin.settings_change': 'Settings changed',
  'admin.settings_mail_test': 'Test email sent',
  'admin.settings_reset': 'Settings reset',
  'admin.update_cancelled': 'Update canceled',
  'admin.update_requested': 'Update requested',
  'admin.user_approve': 'Registration approved',
  'admin.user_create': 'User added',
  'admin.user_reject': 'Registration declined',
  'admin.user_delete': 'User deleted',
  'admin.user_reset_mfa': '2-step verification reset',
  'admin.user_reset_password': 'Password reset',
  'admin.user_reset_trusted_ips': 'Trusted IP addresses reset',
  'admin.user_sign_out': 'User signed out of all devices',
  'admin.user_unlock': 'User unlocked',
  'admin.user_update': 'User updated',
  'auth.browser_check': 'Browser check failed',
  'auth.email_verified': 'Email address confirmed',
  'auth.ip_challenge': 'IP address verification',
  'auth.lock': 'Session locked',
  'auth.lockout': 'Account locked after failed sign-ins',
  'auth.login': 'Sign-in',
  'auth.logout': 'Sign-out',
  'auth.mfa': '2-step verification',
  'auth.password_ok': 'Password accepted',
  'auth.password_reset_request': 'Password reset requested',
  'auth.register': 'Account created',
  'auth.session_revoke': 'Device signed out',
  'auth.sign_out_everywhere': 'Signed out of all devices',
  'auth.unlock': 'Session unlocked',
  'auth.untrusted_ip': 'Sign-in from an untrusted IP address',
  'backup.run': 'Backup',
  'jump_host.create': 'Jump host added',
  'jump_host.delete': 'Jump host removed',
  'jump_host.host_key_forget': 'Jump host fingerprint removed',
  'jump_host.pin': 'Jump host fingerprint saved',
  'jump_host.test': 'Jump host tested',
  'jump_host.update': 'Jump host updated',
  'key.delete': 'SSH key deleted',
  'key.export': 'SSH key exported',
  'key.generate': 'SSH key generated',
  'key.import': 'SSH key imported',
  'server.create': 'Server added',
  'server.delete': 'Server deleted',
  'server.host_key_accept': 'New server fingerprint accepted',
  'server.host_key_dismiss': 'New server fingerprint dismissed',
  'server.host_key_forget': 'Server fingerprint removed',
  'server.update': 'Server updated',
  'setup.create_admin': 'Administrator account created',
  'share.revoke': 'Sharing removed',
  'ssh.connect': 'Connected to server',
  'ssh.host_key_mismatch': 'Server fingerprint changed',
  'ssh.host_key_trust': 'Server fingerprint trusted',
  'ssh.session_detach': 'Terminal disconnected',
  'ssh.session_end': 'Terminal closed',
  'ssh.session_resume': 'Terminal reconnected',
  'ssh.session_start': 'Terminal opened',
  'system.master_key_rotate': 'Master key rotated',
  'system.update': 'Software updated',
  'user.account_delete': 'Account deleted',
  'user.email_change': 'Email address changed',
  'user.mfa_disable': '2-step verification turned off',
  'user.mfa_enable': '2-step verification turned on',
  'user.mfa_setup': '2-step verification setup started',
  'user.password_change': 'Password changed',
  'user.profile_update': 'Profile updated',
  'user.recovery_codes_regenerate': 'Recovery codes regenerated',
  'user.trusted_ip_add': 'Trusted IP address added',
  'user.trusted_ip_remove': 'Trusted IP address removed',
  'user.trusted_ip_settings': 'Trusted IP settings changed',
};

interface LinkResult {
  purpose: 'invite' | 'reset';
  sent: boolean;
  url?: string;
  error?: string;
}

function LinkResultView({ result, email }: { result: LinkResult; email: string | null }) {
  if (result.sent) {
    return <p className="ok">{result.purpose === 'invite' ? 'An invitation' : 'A password reset link'} was emailed to {email}.</p>;
  }
  return (
    <div>
      <p className="muted small">
        {result.error ?? 'Email isn’t set up on this server, so nothing was sent.'} Share this single-use link with them through a secure channel:
      </p>
      {result.url && <SecretOnce label="Single-use link." value={result.url} />}
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
              <th>2-step verification</th>
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
                  {u.registrationState === 'pending_approval' ? (
                    <span className="badge warn">Awaiting approval</span>
                  ) : u.registrationState === 'unverified' ? (
                    <span className="badge">Email not confirmed</span>
                  ) : u.status === 'disabled' ? (
                    <span className="badge warn">Disabled</span>
                  ) : u.locked ? (
                    <span className="badge warn">Locked</span>
                  ) : u.mustChangePassword ? (
                    <span className="badge">Invited – not signed in yet</span>
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
                <strong>@{created.username}</strong> was created. Share this temporary password with them through a secure channel. They’ll be asked to choose a new password when they first sign in.
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
          submit="Add user"
          success="User added."
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
          <Field label="Email" hint="If you enter an email address, we’ll send an invitation so they can create their own password. Otherwise, you’ll get a temporary password to share with them.">
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
  const toast = useToast();
  const confirm = useConfirm();
  const [error, setError] = useState<string | null>(null);
  const [tempPassword, setTempPassword] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  const action = async (label: string, fn: () => Promise<unknown>) => {
    if (!(await confirm({ title: `${label} for @${user.username}?`, confirmLabel: label, danger: label !== 'Unlock' }))) return;
    setError(null);
    try {
      await fn();
      toast.success(`${label} for @${user.username} completed.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  if (user.registrationState) {
    const waiting = user.registrationState === 'pending_approval';
    return (
      <Modal title={user.displayName} onClose={onClose}>
        <p>
          {user.displayName} (<span className="mono">{user.email}</span>) created this account themselves.{' '}
          {waiting
            ? 'They have confirmed their email address and are waiting for you to approve them. Approved accounts get standard user access and no servers.'
            : 'They haven’t confirmed their email address yet. The account is removed automatically after 7 days if they don’t.'}
        </p>
        {error && <p className="error">{error}</p>}
        <div className="row wrap">
          {waiting && (
            <button
              className="primary"
              onClick={async () => {
                try {
                  await post(`/api/admin/users/${user.id}/approve`);
                  toast.success(`${user.displayName} can now sign in.`);
                  onClose();
                } catch (e) {
                  setError(errorMessage(e));
                }
              }}
            >
              Approve
            </button>
          )}
          <button
            className="danger-outline"
            onClick={async () => {
              if (!(await confirm({ title: `Decline ${user.displayName}?`, message: 'The account is deleted. They can register again.', confirmLabel: 'Decline', danger: true }))) return;
              try {
                await post(`/api/admin/users/${user.id}/reject`);
                onClose();
              } catch (e) {
                setError(errorMessage(e));
              }
            }}
          >
            {waiting ? 'Decline' : 'Delete'}
          </button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title={`@${user.username}`} onClose={onClose}>
      <Form
        submit="Save changes"
        success="User updated."
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
        <Field label="Role" hint={isSelf ? 'You can’t change your own role.' : undefined}>
          <select value={role} disabled={isSelf} onChange={(e) => setRole(e.target.value as User['role'])}>
            <option value="user">User</option>
            <option value="admin">Administrator</option>
          </select>
        </Field>
        <Field label="Status" hint={isSelf ? undefined : 'Disabling a user signs them out and closes their terminals immediately.'}>
          <select value={status} disabled={isSelf} onChange={(e) => setStatus(e.target.value as User['status'])}>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </select>
        </Field>
      </Form>
      {!isSelf && (
        <div className="subsection">
          {error && <p className="error">{error}</p>}
          {tempPassword && <SecretOnce label="New temporary password." value={tempPassword} />}
          {link && <LinkResultView result={link} email={user.email} />}
          <div className="row wrap">
            {user.email && user.status === 'active' && (
              <button
                onClick={() =>
                  action(user.lastLoginAt ? 'Email a password reset link' : 'Resend the invitation', async () => {
                    setLink(await post<LinkResult>(`/api/admin/users/${user.id}/send-link`));
                  })
                }
              >
                {user.lastLoginAt ? 'Email password reset link' : 'Resend invitation'}
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
            {user.mfaEnabled && <button onClick={() => action('Reset 2-step verification', () => post(`/api/admin/users/${user.id}/reset-mfa`))}>Reset 2-step verification</button>}
            <button onClick={() => action('Reset trusted IP addresses', () => post(`/api/admin/users/${user.id}/reset-trusted-ips`))}>Reset trusted IP addresses</button>
            {user.locked && <button onClick={() => action('Unlock', () => post(`/api/admin/users/${user.id}/unlock`))}>Unlock</button>}
            <button onClick={() => action('Sign out of all devices', () => post(`/api/admin/users/${user.id}/sign-out`))}>Sign out of all devices</button>
            <button className="danger-outline" onClick={() => setDeleting((d) => !d)}>
              {deleting ? 'Cancel' : 'Delete account'}
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
        <h1>Activity log</h1>
        <button
          onClick={async () => {
            const r = await get<{ ok: boolean; checked: number; brokenAt: number | null }>('/api/admin/audit/verify');
            setVerify(r.ok ? `The log is intact (${r.checked} entries checked).` : `The log may have been altered. A problem was found at entry #${r.brokenAt}.`);
          }}
        >
          Check log integrity
        </button>
      </div>
      {verify && <p className={verify.startsWith('The log is intact') ? 'ok' : 'error'}>{verify}</p>}
      <select className="search" value={filter} onChange={(e) => setFilter(e.target.value)}>
        <option value="">All activity</option>
        <option value="auth.">Sign-ins</option>
        <option value="auth.lockout">Account lockouts</option>
        <option value="ssh.">Terminal sessions</option>
        <option value="share.">Sharing</option>
        <option value="server.">Servers</option>
        <option value="key.">Keys</option>
        <option value="admin.">Admin actions</option>
        <option value="system.">Software updates</option>
        <option value="user.">Account changes</option>
      </select>
      {error && <p className="error">{error}</p>}
      <div className="table-wrap card">
        <table className="small">
          <thead>
            <tr>
              <th>No.</th>
              <th>Time</th>
              <th>User</th>
              <th>Activity</th>
              <th>Details</th>
              <th>IP address</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.seq} className={e.outcome === 'failure' ? 'failure' : ''}>
                <td>{e.seq}</td>
                <td>{formatTime(e.ts)}</td>
                <td>{e.actorUsername ?? '—'}</td>
                <td>
                  <span title={e.action}>{EVENT_LABELS[e.action] ?? e.action}</span>
                  {e.outcome === 'failure' && <span className="badge warn">Failed</span>}
                </td>
                <td className="mono details">{Object.keys(e.details).length ? JSON.stringify(e.details) : ''}</td>
                <td>{e.ip}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {entries.length > 0 && entries.length % 100 === 0 && <button onClick={more}>Show older activity</button>}
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
        The fingerprint saved for each server. Only a server’s owner can accept a new fingerprint.
      </p>
      {error && <p className="error">{error}</p>}
      <div className="table-wrap card">
        <table className="small">
          <thead>
            <tr>
              <th>Server</th>
              <th>Owner</th>
              <th>Saved fingerprint</th>
              <th>Trusted since</th>
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
                      <span className="error">Server now presents: {h.hostKeyChange.type ?? ''} {h.hostKeyChange.fingerprint}</span>
                    </>
                  )}
                </td>
                <td>{h.hostKey?.pinnedAt ? `${formatTime(h.hostKey.pinnedAt)}${h.hostKey.pinnedBy ? ` by ${h.hostKey.pinnedBy}` : ''}` : '—'}</td>
                <td>
                  {h.hostKeyChange ? (
                    <span className="badge warn">Fingerprint changed</span>
                  ) : !h.hostKey ? (
                    <span className="badge">Not verified yet</span>
                  ) : h.conflict ? (
                    <span className="badge warn">Conflicts with another saved fingerprint</span>
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
