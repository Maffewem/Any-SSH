import { useState } from 'react';
import { del, errorMessage, formatTime, get, patch, post, type JumpHost, type JumpTest } from '../api';
import { CopyButton, Field, Form, useAsync } from '../ui';

/** Admin section: the bastions servers can be routed through. */
export function JumpHostsSection() {
  const { data, error, reload } = useAsync(() => get<{ jumpHosts: JumpHost[] }>('/api/admin/jump-hosts'), []);
  const [adding, setAdding] = useState(false);

  return (
    <div className="card settings-section">
      <div className="page-head">
        <h2>Jump hosts</h2>
        <button onClick={() => setAdding((a) => !a)}>{adding ? 'Cancel' : 'Add jump host'}</button>
      </div>
      <p className="muted small">
        Servers can reach their targets through a jump host, so no single box has to be exposed. The jump host only relays encrypted
        traffic: each person’s login to the target stays end to end, and it never sees their key, password or keystrokes. Any-SSH logs in
        to the jump host with its own key (shown below, never the private half). Connections to a jump host are refused until you verify its
        host key. “Closest” means the lowest TCP connect time from this server, measured at connect time, falling back to the next one if
        it fails.
      </p>
      {error && <p className="error">{error}</p>}
      {adding && <AddJumpHost onDone={() => (setAdding(false), reload())} />}
      {data?.jumpHosts.length === 0 && !adding && <p className="muted">No jump hosts yet.</p>}
      {data?.jumpHosts.map((j) => <JumpHostRow key={j.id} jump={j} onChange={reload} />)}
    </div>
  );
}

function AddJumpHost({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('22');
  const [username, setUsername] = useState('');
  return (
    <Form
      submit="Create jump host"
      onSubmit={async () => {
        await post('/api/admin/jump-hosts', { name, host, port: Number(port), username });
        onDone();
      }}
    >
      <Field label="Name">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Home bastion" required />
      </Field>
      <div className="row2">
        <Field label="Host">
          <input value={host} onChange={(e) => setHost(e.target.value)} autoCapitalize="none" required />
        </Field>
        <Field label="Port">
          <input value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" required />
        </Field>
      </div>
      <Field label="SSH username on the jump host" hint="Give this account as little as possible: it only needs to forward connections.">
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoCapitalize="none" required />
      </Field>
    </Form>
  );
}

function JumpHostRow({ jump, onChange }: { jump: JumpHost; onChange: () => void }) {
  const [test, setTest] = useState<JumpTest | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setMessage(null);
    try {
      await fn();
    } catch (e) {
      setMessage(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const authorizedKeysLine = `restrict,port-forwarding ${jump.publicKey}`;

  return (
    <div className="subsection">
      <p>
        <strong>{jump.name}</strong> <span className="mono muted">{jump.username}@{jump.host}{jump.port !== 22 ? `:${jump.port}` : ''}</span>{' '}
        {!jump.enabled && <span className="badge warn">Disabled</span>}{' '}
        {jump.hostKeyFingerprint ? <span className="badge">Host key verified</span> : <span className="badge warn">Host key not verified</span>}
        {jump.serverCount > 0 && <span className="badge">{jump.serverCount} server{jump.serverCount === 1 ? '' : 's'} fixed to it</span>}
      </p>
      <details>
        <summary className="muted small">Authorize Any-SSH on this jump host</summary>
        <p className="muted small">
          Add this line to <code>~/.ssh/authorized_keys</code> of {jump.username} on the jump host. <code>restrict,port-forwarding</code> limits the
          key to relaying connections: no shell, no agent or X11 forwarding.
        </p>
        <div className="row">
          <code className="secret">{authorizedKeysLine}</code>
          <CopyButton text={authorizedKeysLine} />
        </div>
      </details>
      {jump.hostKeyFingerprint && (
        <p className="muted small">
          Pinned host key: <code>{jump.hostKeyFingerprint}</code>
        </p>
      )}
      <div className="row">
        <button
          disabled={busy}
          onClick={() =>
            run(async () => setTest(await post<JumpTest>(`/api/admin/jump-hosts/${jump.id}/test`)))
          }
        >
          Test
        </button>
        <button disabled={busy} onClick={() => run(async () => (await patch(`/api/admin/jump-hosts/${jump.id}`, { enabled: !jump.enabled }), onChange()))}>
          {jump.enabled ? 'Disable' : 'Enable'}
        </button>
        {jump.hostKeyFingerprint && (
          <button
            disabled={busy}
            onClick={() =>
              confirm('Forget the pinned host key? Open terminals through it close, and it cannot be used until you verify a key again.') &&
              run(async () => (await post(`/api/admin/jump-hosts/${jump.id}/forget-host-key`), setTest(null), onChange()))
            }
          >
            Forget host key
          </button>
        )}
        <button
          className="danger-outline"
          disabled={busy}
          onClick={() =>
            confirm(
              `Delete ${jump.name}? Open terminals through it close. Servers fixed to it will refuse to connect (they never fall back to a direct connection).`,
            ) && run(async () => (await del(`/api/admin/jump-hosts/${jump.id}`), onChange()))
          }
        >
          Delete
        </button>
      </div>
      {message && <p className="error">{message}</p>}
      {test && (
        <div className="muted small">
          {test.latencyMs !== null && <p>Reachable in {Math.round(test.latencyMs)} ms.</p>}
          {test.latencyMs === null && <p className="error">Not reachable from Any-SSH.</p>}
          {test.error && <p className="error">{test.error}</p>}
          {test.hostKey === 'unpinned' && test.fingerprint && (
            <>
              <p>
                It presented this host key. Check it matches the jump host (on it: <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>)
                before trusting it:
              </p>
              <p className="fingerprint mono">{test.fingerprint}</p>
              <button
                className="primary"
                disabled={busy}
                onClick={() => run(async () => (await post(`/api/admin/jump-hosts/${jump.id}/pin`, { fingerprint: test.fingerprint }), setTest(null), onChange()))}
              >
                Trust this host key
              </button>
            </>
          )}
          {test.hostKey === 'mismatch' && <p className="error">HOST KEY CHANGED: it presented {test.fingerprint}. Do not trust it unless you changed the jump host’s keys.</p>}
          {test.hostKey === 'match' && test.authenticated && <p className="ok">Host key matches and the Any-SSH key was accepted. Checked {formatTime(Date.now())}.</p>}
        </div>
      )}
    </div>
  );
}
