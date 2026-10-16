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
        <button onClick={() => setAdding((a) => !a)}>{adding ? 'Cancel' : 'Add a jump host'}</button>
      </div>
      <p className="muted small">
        A jump host (also called a bastion) is a gateway that servers on a private network are reached through, so only the gateway needs to be
        exposed to the internet. You can add as many as you need, for example one per site or network.
      </p>
      <ul className="muted small">
        <li>
          <strong>Privacy:</strong> a jump host relays encrypted traffic only. Each person’s sign-in to the target server is end to end, so the
          jump host never sees their key, password or keystrokes.
        </li>
        <li>
          <strong>Choosing:</strong> each server is set to use no jump host, a specific jump host, or the closest one. “Closest” picks the
          reachable jump host with the lowest connection time from this server and moves on to the next if it fails. A specific jump host never falls
          back to another route.
        </li>
        <li>
          <strong>Trust:</strong> Any-SSH signs in to a jump host with its own key (the public half is shown below). A jump host cannot be used
          until you have verified its host key.
        </li>
      </ul>
      {error && <p className="error">{error}</p>}
      {adding && <AddJumpHost onDone={() => (setAdding(false), reload())} />}
      {data?.jumpHosts.length === 0 && !adding && <p className="muted">No jump hosts have been added.</p>}
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
      <Field label="Account on the jump host" hint="Use a dedicated account with no other permissions. It only needs to forward connections.">
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
        {!jump.enabled && <span className="badge warn">Disabled</span>}{' '}
        {jump.hostKeyFingerprint ? <span className="badge">Host key verified</span> : <span className="badge warn">Host key not verified</span>}
        {jump.serverCount > 0 && <span className="badge">{jump.serverCount} server{jump.serverCount === 1 ? '' : 's'} using it</span>}
      </p>
      <details>
        <summary className="muted small">Set up this jump host</summary>
        <p className="muted small">
          Recommended: on the jump host, download and review the setup script, then run it. It creates a dedicated account that can only relay
          connections (no shell, agent or X11 forwarding) and authorises the Any-SSH key. Add <code>--allow host:port</code> to limit it to specific destinations.
        </p>
        <div className="row">
          <code className="secret">{setupCommand}</code>
          <CopyButton text={setupCommand} />
        </div>
        <p className="muted small">
          To set it up by hand instead, add this line to <code>~/.ssh/authorized_keys</code> for {jump.username} on the jump host.{' '}
          <code>restrict,port-forwarding</code> limits the key to relaying connections.
        </p>
        <div className="row">
          <code className="secret">{authorizedKeysLine}</code>
          <CopyButton text={authorizedKeysLine} />
        </div>
      </details>
      {jump.hostKeyFingerprint && (
        <p className="muted small">
          Verified host key: <code>{jump.hostKeyFingerprint}</code>
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
        <button disabled={busy} onClick={() => run(async () => (await patch(`/api/admin/jump-hosts/${jump.id}`, { enabled: !jump.enabled }), onChange()), jump.enabled ? `${jump.name} disabled.` : `${jump.name} enabled.`)}>
          {jump.enabled ? 'Disable' : 'Enable'}
        </button>
        {jump.hostKeyFingerprint && (
          <button
            disabled={busy}
            onClick={async () =>
              (await confirm({
                title: `Remove the verified host key for ${jump.name}`,
                message: 'Terminals open through this jump host will close, and it cannot be used again until you verify a host key.',
                confirmLabel: 'Remove host key',
                danger: true,
              })) && run(async () => (await post(`/api/admin/jump-hosts/${jump.id}/forget-host-key`), setTest(null), onChange()), 'Verified host key removed.')
            }
          >
            Remove verified host key
          </button>
        )}
        <button
          className="danger-outline"
          disabled={busy}
          onClick={async () =>
            (await confirm({
              title: `Delete jump host ${jump.name}`,
              message: 'Terminals open through it will close. Servers set to use it will not connect until you choose another route; they never fall back to a direct connection.',
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
          {test.latencyMs !== null && <p>Reachable in {Math.round(test.latencyMs)} ms.</p>}
          {test.latencyMs === null && <p className="error">Any-SSH could not reach this jump host.</p>}
          {test.error && <p className="error">{test.error}</p>}
          {test.hostKey === 'unpinned' && test.fingerprint && (
            <>
              <p>
                The jump host presented this host key. Confirm that it matches before trusting it (run this on the jump host: <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>):
              </p>
              <p className="fingerprint mono">{test.fingerprint}</p>
              <button
                className="primary"
                disabled={busy}
                onClick={() => run(async () => (await post(`/api/admin/jump-hosts/${jump.id}/pin`, { fingerprint: test.fingerprint }), setTest(null), onChange()), 'Host key verified.')}
              >
                Trust this host key
              </button>
            </>
          )}
          {test.hostKey === 'mismatch' && <p className="error">WARNING: the host key has changed. The jump host presented {test.fingerprint}. Do not trust it unless you changed the jump host’s keys yourself.</p>}
          {test.hostKey === 'match' && test.authenticated && <p className="ok">The host key matches and the jump host accepted the Any-SSH key. Checked {formatTime(Date.now())}.</p>}
        </div>
      )}
    </div>
  );
}
