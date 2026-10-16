import { useState } from 'react';
import { del, get, post } from '../api';
import { Field, Form, useAsync } from '../ui';

interface Preview {
  keys: number;
  servers: { id: string; name: string; sharedWith: { id: string; username: string; displayName: string }[] }[];
}
interface Person {
  id: string;
  username: string;
  displayName: string;
}

/**
 * Closes an account. Anything the account owns is deleted with it. Servers shared with other people
 * can be handed to another user instead; otherwise the person must type "delete" to confirm.
 * Used for your own account and, by administrators, for someone else's.
 */
export function DeleteAccountForm(props: { self: boolean; userId?: string; username: string; mfaEnabled?: boolean; onDeleted: () => void }) {
  const { self, userId, username } = props;
  const preview = useAsync(() => get<Preview>(self ? '/api/account/deletion-preview' : `/api/admin/users/${userId}/deletion-preview`), []);
  const [mode, setMode] = useState<'transfer' | 'delete'>('transfer');
  const [query, setQuery] = useState('');
  const [target, setTarget] = useState<Person | null>(null);
  const people = useAsync(
    () => (query.trim().length < 1 ? Promise.resolve({ users: [] as Person[] }) : get<{ users: Person[] }>(`/api/users/directory?q=${encodeURIComponent(query.trim())}`)),
    [query],
  );
  const [confirm, setConfirm] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');

  const data = preview.data;
  if (!data) return preview.error ? <p className="error">{preview.error}</p> : <p className="muted">Loading…</p>;
  const shared = data.servers.filter((s) => s.sharedWith.length > 0);
  const others = new Set(shared.flatMap((s) => s.sharedWith.map((p) => p.username)));
  const candidates = (people.data?.users ?? []).filter((p) => p.username !== username);
  const transferring = shared.length > 0 && mode === 'transfer';

  return (
    <Form
      submit={self ? 'Permanently delete my account' : `Permanently delete @${username}`}
      danger
      onSubmit={async () => {
        if (transferring && !target) throw new Error('Choose who should take over the shared servers.');
        if (shared.length > 0 && !transferring && confirm.trim().toLowerCase() !== 'delete') throw new Error('Type “delete” to confirm.');
        if (self) {
          await post('/api/account/delete', {
            password,
            ...(props.mfaEnabled ? { code } : {}),
            ...(transferring && target ? { transferTo: target.id } : { confirm }),
          });
        } else {
          if (transferring && target) await post(`/api/admin/users/${userId}/transfer-servers`, { to: target.id });
          await del(`/api/admin/users/${userId}?confirm=${encodeURIComponent(confirm)}`);
        }
        props.onDeleted();
      }}
    >
      <p>
        {self ? 'Deleting your account permanently removes' : `Deleting @${username} permanently removes`} {data.keys} SSH key{data.keys === 1 ? '' : 's'},{' '}
        {data.servers.length} server{data.servers.length === 1 ? '' : 's'}, all sharing settings and all signed-in sessions. This cannot be undone.
      </p>
      {shared.length > 0 && (
        <>
          <div className="notice">
            <strong>
              {shared.length} of {self ? 'your' : 'their'} servers {shared.length === 1 ? 'is' : 'are'} shared with other people:
            </strong>
            <ul>
              {shared.map((s) => (
                <li key={s.id}>
                  {s.name} <span className="muted small">shared with {s.sharedWith.map((p) => `@${p.username}`).join(', ')}</span>
                </li>
              ))}
            </ul>
            <p className="small">{others.size === 1 ? 'That person' : 'Those people'} will lose access if {shared.length === 1 ? 'it is' : 'they are'} deleted.</p>
          </div>
          <label className="check">
            <input type="radio" name="shared-mode" checked={mode === 'transfer'} onChange={() => setMode('transfer')} /> Transfer the shared servers to another user
            (including the saved keys they use)
          </label>
          {mode === 'transfer' && (
            <Field label="New owner" hint="Search by name or username. Servers that are not shared are still deleted.">
              {target ? (
                <span className="row">
                  <strong>{target.displayName}</strong> <span className="muted">@{target.username}</span>
                  <button type="button" className="ghost small" onClick={() => setTarget(null)}>
                    Change
                  </button>
                </span>
              ) : (
                <>
                  <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search users" autoComplete="off" />
                  {candidates.map((p) => (
                    <button type="button" key={p.id} className="ghost" onClick={() => setTarget(p)}>
                      {p.displayName} <span className="muted">@{p.username}</span>
                    </button>
                  ))}
                </>
              )}
            </Field>
          )}
          <label className="check">
            <input type="radio" name="shared-mode" checked={mode === 'delete'} onChange={() => setMode('delete')} /> Delete the shared servers as well
          </label>
          {mode === 'delete' && (
            <Field label="Type “delete” to confirm" hint="This deletes the shared servers for everyone they are shared with.">
              <input value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" autoCapitalize="none" />
            </Field>
          )}
        </>
      )}
      {self && (
        <>
          <Field label="Your password" hint="Needed to confirm that this is you.">
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
          </Field>
          {props.mfaEnabled && (
            <Field label="Authentication code">
              <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" required />
            </Field>
          )}
        </>
      )}
    </Form>
  );
}
