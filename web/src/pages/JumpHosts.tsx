import { useState } from 'react';
import { del, errorMessage, formatTime, get, patch, post, type JumpHost, type JumpTest } from '../api';
import { CopyButton, Field, Form, useAsync, useConfirm, useToast } from '../ui';

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
        A jump host (also called a bastion host) is a gateway for reaching servers on a private network.
      </p>
      <ul className="muted small">
        <li>
          <strong>Privacy:</strong> a jump host only relays encrypted traffic. It never sees keys, passwords or anything you type.
        </li>
        <li>
          <strong>Routing:</strong> each server can connect directly, through a specific jump host, or through the closest one. A server set to a specific jump host never switches to another route.
        </li>
        <li>
          <strong>Verification:</strong> you can’t use a jump host until you’ve verified its fingerprint.
        </li>
      </ul>
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
      submit="Add jump host"
      success="Jump host added."
      onSubmit={async () => {
        await post('/api/admin/jump-hosts', { name, host, port: Number(port), username });
        onDone();
      }}
    >
      <Field label="Name">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Office gateway" required />
      </Field>
      <div className="row2">
        <Field label="Host">
          <input value={host} onChange={(e) => setHost(e.target.value)} autoCapitalize="none" required />
        </Field>
        <Field label="Port">
          <input value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" required />
        </Field>
      </div>
      <Field label="Jump host username" hint="Use a dedicated account with no other permissions. It only needs to forward connections.">
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoCapitalize="none" required />
      </Field>
    </Form>
  );
}

function JumpHostRow({ jump, onChange }: { jump: JumpHost; onChange: () => void }) {
  const [test, setTest] = useState<JumpTest | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const confirm = useConfirm();
  const run = async (fn: () => Promise<void>, done?: string) => {
    setBusy(true);
    setMessage(null);
    try {
      await fn();
      if (done) toast.success(done);
    } catch (e) {
      setMessage(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const authorizedKeysLine = `restrict,port-forwarding ${jump.publicKey}`;
  const setupCommand = `curl -fsSLO https://raw.githubusercontent.com/Maffewem/Any-SSH/main/deploy/jump-host-setup.sh && less jump-host-setup.sh && sudo bash jump-host-setup.sh --user ${jump.username} --key '${jump.publicKey}'`;

  return (
    <div className="subsection">
      <p>
        <strong>{jump.name}</strong> <span className="mono muted">{jump.username}@{jump.host}{jump.port !== 22 ? `:${jump.port}` : ''}</span>{' '}
        {!jump.enabled && <span className="badge warn">Turned off</span>}{' '}
        {jump.hostKeyFingerprint ? <span className="badge">Fingerprint verified</span> : <span className="badge warn">Fingerprint not verified</span>}
        {jump.serverCount > 0 && <span className="badge">Used by {jump.serverCount} server{jump.serverCount === 1 ? '' : 's'}</span>}
      </p>
      <details>
        <summary className="muted small">Set up this jump host</summary>
        <p className="muted small">
          Recommended: on the jump host, download and review the setup script, then run it. The script creates a dedicated account that can only relay connections (no shell, agent forwarding or X11 forwarding) and authorizes the Any-SSH key. Add <code>--allow host:port</code> to limit it to specific destinations.
        </p>
        <div className="row">
          <code className="secret">{setupCommand}</code>
          <CopyButton text={setupCommand} />
        </div>
        <p className="muted small">
          To set it up manually instead, add this line to <code>~/.ssh/authorized_keys</code> for {jump.username} on the jump host. The <code>restrict,port-forwarding</code> options limit the key to relaying connections.
        </p>
        <div className="row">
          <code className="secret">{authorizedKeysLine}</code>
          <CopyButton text={authorizedKeysLine} />
        </div>
      </details>
      {jump.hostKeyFingerprint && (
        <p className="muted small">
          Verified fingerprint: <code>{jump.hostKeyFingerprint}</code>
        </p>
      )}
      <div className="row">
        <button
          disabled={busy}
          onClick={() =>
            run(async () => setTest(await post<JumpTest>(`/api/admin/jump-hosts/${jump.id}/test`)))
          }
        >
          Test connection
        </button>
        <button disabled={busy} onClick={() => run(async () => (await patch(`/api/admin/jump-hosts/${jump.id}`, { enabled: !jump.enabled }), onChange()), jump.enabled ? `${jump.name} turned off.` : `${jump.name} turned on.`)}>
          {jump.enabled ? 'Turn off' : 'Turn on'}
        </button>
        {jump.hostKeyFingerprint && (
          <button
            disabled={busy}
            onClick={async () =>
              (await confirm({
                title: `Remove the verified fingerprint for ${jump.name}?`,
                message: 'Terminals open through this jump host will close. You won’t be able to use it again until you verify its fingerprint.',
                confirmLabel: 'Remove fingerprint',
                danger: true,
              })) && run(async () => (await post(`/api/admin/jump-hosts/${jump.id}/forget-host-key`), setTest(null), onChange()), 'Verified fingerprint removed.')
            }
          >
            Remove verified fingerprint
          </button>
        )}
        <button
          className="danger-outline"
          disabled={busy}
          onClick={async () =>
            (await confirm({
              title: `Delete ${jump.name}?`,
              message: 'Terminals open through this jump host will close. Servers set to use it won’t connect until you choose another route. They never switch to a direct connection automatically.',
              confirmLabel: 'Delete jump host',
              danger: true,
            })) && run(async () => (await del(`/api/admin/jump-hosts/${jump.id}`), onChange()), `${jump.name} deleted.`)
          }
        >
          Delete
        </button>
      </div>
      {message && <p className="error">{message}</p>}
      {test && (
        <div className="muted small">
          {test.latencyMs !== null && <p>Connected in {Math.round(test.latencyMs)} ms.</p>}
          {test.latencyMs === null && <p className="error">Any-SSH couldn’t connect to this jump host.</p>}
          {test.error && <p className="error">{test.error}</p>}
          {test.hostKey === 'unpinned' && test.fingerprint && (
            <>
              <p>
                The jump host presented this fingerprint. Make sure it matches before you trust it. To check, run this on the jump host: <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>
              </p>
              <p className="fingerprint mono">{test.fingerprint}</p>
              <button
                className="primary"
                disabled={busy}
                onClick={() => run(async () => (await post(`/api/admin/jump-hosts/${jump.id}/pin`, { fingerprint: test.fingerprint }), setTest(null), onChange()), 'Fingerprint verified.')}
              >
                Trust this fingerprint
              </button>
            </>
          )}
          {test.hostKey === 'mismatch' && <p className="error">The jump host’s fingerprint has changed. It presented {test.fingerprint}. Don’t trust it unless you changed the jump host’s keys yourself.</p>}
          {test.hostKey === 'match' && test.authenticated && <p className="ok">The fingerprint matches and the jump host accepted the Any-SSH key. Checked {formatTime(Date.now())}.</p>}
        </div>
      )}
    </div>
  );
}
