import { useState } from 'react';
import { del, downloadText, formatTime, get, post, type SshKey } from '../api';
import { CopyButton, Field, Form, Modal, useAsync, useConfirm, useToast } from '../ui';

export function KeysPage() {
  const toast = useToast();
  const confirm = useConfirm();
  const { data, error, reload } = useAsync(() => get<{ keys: SshKey[] }>('/api/keys'), []);
  const [dialog, setDialog] = useState<'generate' | 'import' | null>(null);
  const [exporting, setExporting] = useState<SshKey | null>(null);
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
        To use a key, add its public key to the server’s <code>~/.ssh/authorized_keys</code> file.
      </p>
      {(error || actionError) && <p className="error">{error ?? actionError}</p>}
      {data?.keys.length === 0 && <div className="empty card">You don’t have any SSH keys yet. Generate or import one to get started.</div>}
      <div className="stack">
        {data?.keys.map((k) => (
          <article key={k.id} className="card">
            <div className="page-head">
              <div>
                <h3>{k.name}</h3>
                <p className="muted small mono">
                  {k.type} · {k.fingerprint} · Added {formatTime(k.createdAt)} · {k.lastUsedAt ? `Last used ${formatTime(k.lastUsedAt)}` : 'Never used'}
                </p>
              </div>
              <div className="row">
                <CopyButton text={k.publicKey} label="Copy public key" />
                <button onClick={() => setExporting(k)}>Export</button>
                <button
                  className="ghost"
                  onClick={async () => {
                    if (
                      !(await confirm({
                        title: `Delete ${k.name}?`,
                        message: 'Servers that use this key will no longer connect until you choose another. This can’t be undone.',
                        confirmLabel: 'Delete SSH key',
                        danger: true,
                      }))
                    )
                      return;
                    setActionError(null);
                    try {
                      await del(`/api/keys/${k.id}`);
                      toast.success(`${k.name} deleted.`);
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
      {exporting && <ExportDialog keyRow={exporting} onClose={() => setExporting(null)} />}
    </section>
  );
}

function GenerateDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState('');
  const [type, setType] = useState('ed25519');
  return (
    <Modal title="Generate SSH key" onClose={onClose}>
      <Form submit="Generate key" success="SSH key generated." onSubmit={async () => (await post('/api/keys/generate', { name, type }), onDone())}>
        <Field label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="For example, Work servers" required autoFocus />
        </Field>
        <Field label="Key type">
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
    <Modal title="Import SSH key" onClose={onClose}>
      <Form
        submit="Import key"
        success="SSH key imported."
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
        <Field label="Private key" hint="OpenSSH or PEM format. The key is encrypted as soon as it reaches the server.">
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

function ExportDialog({ keyRow, onClose }: { keyRow: SshKey; onClose: () => void }) {
  const toast = useToast();
  const [password, setPassword] = useState('');
  const [done, setDone] = useState(false);
  return (
    <Modal title={`Export ${keyRow.name}`} onClose={onClose}>
      <p className="muted small">
        This downloads the private key itself. Anyone who has it can sign in as you, so store it somewhere safe and set its permissions to <code>600</code>. The export is recorded in the activity log.
      </p>
      {done ? (
        <p className="ok">Download complete. Once you’ve moved the key somewhere safe, delete it from your Downloads folder.</p>
      ) : (
        <Form
          submit="Download private key"
          onSubmit={async () => {
            const res = await post<{ filename: string; privateKey: string }>(`/api/keys/${keyRow.id}/export`, { password });
            setPassword('');
            downloadText(res.filename, res.privateKey);
            setDone(true);
            toast.success('Private key downloaded.');
          }}
        >
          <Field label="Your Any-SSH password">
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus required />
          </Field>
        </Form>
      )}
    </Modal>
  );
}
