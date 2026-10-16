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
        Private keys are encrypted on the server. Add the public key to the server’s <code>~/.ssh/authorized_keys</code>.
        You can export a private key to keep a copy elsewhere; it asks for your password first.
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
                <button onClick={() => setExporting(k)}>Export</button>
                <button
                  className="ghost"
                  onClick={async () => {
                    if (
                      !(await confirm({
                        title: `Delete key ${k.name}`,
                        message: 'Servers using it will stop working.',
                        confirmLabel: 'Delete key',
                        danger: true,
                      }))
                    )
                      return;
                    setActionError(null);
                    try {
                      await del(`/api/keys/${k.id}`);
                      toast.success(`Key ${k.name} deleted.`);
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
      <Form submit="Generate" success="Key generated." onSubmit={async () => (await post('/api/keys/generate', { name, type }), onDone())}>
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
        success="Key imported."
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

function ExportDialog({ keyRow, onClose }: { keyRow: SshKey; onClose: () => void }) {
  const toast = useToast();
  const [password, setPassword] = useState('');
  const [done, setDone] = useState(false);
  return (
    <Modal title={`Export ${keyRow.name}`} onClose={onClose}>
      <p className="muted small">
        This downloads the private key itself. Anyone who has it can log in as you, so keep it somewhere safe and set its
        permissions to <code>600</code>. The export is recorded in the audit log.
      </p>
      {done ? (
        <p className="ok">Downloaded. Delete it from your Downloads folder once you have put it where it belongs.</p>
      ) : (
        <Form
          submit="Confirm and download"
          onSubmit={async () => {
            const res = await post<{ filename: string; privateKey: string }>(`/api/keys/${keyRow.id}/export`, { password });
            setPassword('');
            downloadText(res.filename, res.privateKey);
            setDone(true);
            toast.success('Key downloaded.');
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
