import { useState } from 'react';
import { del, formatTime, get, post, type SshKey } from '../api';
import { CopyButton, Field, Form, Modal, useAsync } from '../ui';

export function KeysPage() {
  const { data, error, reload } = useAsync(() => get<{ keys: SshKey[] }>('/api/keys'), []);
  const [dialog, setDialog] = useState<'generate' | 'import' | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  return (
    <section>
      <div className="page-head">
        <h1>SSH keys</h1>
        <div className="row">
          <button className="primary" onClick={() => setDialog('generate')}>
            Generate key
          </button>
          <button onClick={() => setDialog('import')}>Import key</button>
        </div>
      </div>
      <p className="muted small">
        Private keys are encrypted on the server and never leave it, not even to you. Add the public key to the server’s{' '}
        <code>~/.ssh/authorized_keys</code>.
      </p>
      {(error || actionError) && <p className="error">{error ?? actionError}</p>}
      {data?.keys.length === 0 && <div className="empty card">No keys yet.</div>}
      <div className="stack">
        {data?.keys.map((k) => (
          <article key={k.id} className="card">
            <div className="page-head">
              <div>
                <h3>{k.name}</h3>
                <p className="muted small mono">
                  {k.type} · {k.fingerprint} · added {formatTime(k.createdAt)} · {k.lastUsedAt ? `last used ${formatTime(k.lastUsedAt)}` : 'never used'}
                </p>
              </div>
              <div className="row">
                <CopyButton text={k.publicKey} label="Copy public key" />
                <button
                  className="ghost"
                  onClick={async () => {
                    if (!confirm(`Delete key "${k.name}"? Servers using it will stop working.`)) return;
                    setActionError(null);
                    try {
                      await del(`/api/keys/${k.id}`);
                      reload();
                    } catch (e) {
                      setActionError(e instanceof Error ? e.message : String(e));
                    }
                  }}
                >
                  Delete
                </button>
              </div>
            </div>
            <code className="pubkey">{k.publicKey}</code>
          </article>
        ))}
      </div>
      {dialog === 'generate' && <GenerateDialog onClose={() => setDialog(null)} onDone={() => (setDialog(null), reload())} />}
      {dialog === 'import' && <ImportDialog onClose={() => setDialog(null)} onDone={() => (setDialog(null), reload())} />}
    </section>
  );
}

function GenerateDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState('');
  const [type, setType] = useState('ed25519');
  return (
    <Modal title="Generate SSH key" onClose={onClose}>
      <Form submit="Generate" onSubmit={async () => (await post('/api/keys/generate', { name, type }), onDone())}>
        <Field label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. work servers" required autoFocus />
        </Field>
        <Field label="Type">
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="ed25519">Ed25519 (recommended)</option>
            <option value="ecdsa">ECDSA P-256</option>
            <option value="rsa">RSA 4096 (for older servers)</option>
          </select>
        </Field>
      </Form>
    </Modal>
  );
}

function ImportDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  return (
    <Modal title="Import private key" onClose={onClose}>
      <Form
        submit="Import"
        onSubmit={async () => {
          await post('/api/keys/import', { name, privateKey, ...(passphrase ? { passphrase } : {}) });
          setPrivateKey('');
          setPassphrase('');
          onDone();
        }}
      >
        <Field label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
        </Field>
        <Field label="Private key" hint="OpenSSH or PEM format. It is encrypted as soon as it reaches the server.">
          <textarea
            className="mono"
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
            rows={8}
            spellCheck={false}
            autoComplete="off"
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
            required
          />
        </Field>
        <Field label="Passphrase (if the key has one)">
          <input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoComplete="off" />
        </Field>
      </Form>
    </Modal>
  );
}
