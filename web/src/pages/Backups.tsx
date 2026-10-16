import { useState } from 'react';
import { del, downloadText, errorMessage, formatTime, get, post, put, type BackupEncryption, type BackupRunView, type BackupSettingsView, type BackupStatusView, type SettingsView } from '../api';
import { Field, Form, useAsync, useConfirm, useToast } from '../ui';

const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
type Kind = BackupSettingsView['target']['kind'];

const size = (n: number | null) => (n === null ? '—' : n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);

const TRIGGER: Record<BackupRunView['trigger'], string> = { schedule: 'Scheduled', manual: 'Manual', cli: 'Command line' };
const ENCRYPTION: Record<BackupEncryption, string> = { recovery: 'Recovery key', system: 'System-managed', none: 'None' };

/** "this server (/data/backups)" → "This server"; "S3 bucket b/p" → "S3: b/p"; "SFTP u@h:/p" → "SFTP: u@h:/p". */
function place(destination: string | null): string {
  if (!destination) return '—';
  if (destination.startsWith('this server')) return 'This server';
  const m = /^(S3) bucket (.+)$|^(SFTP) (.+)$/.exec(destination);
  return m ? `${m[1] ?? m[3]}: ${m[2] ?? m[4]}` : destination;
}

function RunLine({ run }: { run: BackupRunView }) {
  return (
    <tr>
      <td>{formatTime(run.startedAt)}</td>
      <td>
        {run.outcome === 'success' ? <span className="badge accent">Completed</span> : run.outcome === 'running' ? <span className="badge">Running</span> : <span className="badge warn">Failed</span>}
      </td>
      <td>{TRIGGER[run.trigger]}</td>
      <td>{run.encryption === 'none' ? <span className="badge warn">None</span> : ENCRYPTION[run.encryption]}</td>
      <td>{size(run.bytes)}</td>
      <td className="small">
        <span title={run.destination ?? undefined}>{place(run.destination)}</span>
        {run.error && <div className="error">{run.error}</div>}
        {run.warning && <div className="muted">{run.warning}</div>}
      </td>
    </tr>
  );
}

/** Admin: encrypted backups, where they go, how often, and whether they are working. */
export function BackupSection({ view, onSaved }: { view: SettingsView; onSaved: (s: SettingsView, reset?: true) => void }) {
  const b = view.backup;
  const info = useAsync(() => get<{ status: BackupStatusView; runs: BackupRunView[] }>('/api/admin/backup'), []);
  const status = info.data?.status;

  const [enabled, setEnabled] = useState(b.enabled);
  const [frequency, setFrequency] = useState(b.frequency);
  const [hourUtc, setHour] = useState(String(b.hourUtc));
  const [weekday, setWeekday] = useState(String(b.weekday));
  const [keep, setKeep] = useState(String(b.keep));
  const [encryption, setEncryption] = useState<BackupEncryption>(b.encryption);
  const [acceptUnencrypted, setAcceptUnencrypted] = useState(b.encryption === 'none');
  const [publicKey, setPublicKey] = useState(b.publicKey);
  const [kind, setKind] = useState<Kind>(b.target.kind);
  const t = b.target;
  const [endpoint, setEndpoint] = useState(t.kind === 's3' ? t.endpoint : '');
  const [region, setRegion] = useState(t.kind === 's3' ? t.region : 'us-east-1');
  const [bucket, setBucket] = useState(t.kind === 's3' ? t.bucket : '');
  const [prefix, setPrefix] = useState(t.kind === 's3' ? t.prefix : 'any-ssh');
  const [accessKeyId, setAccessKeyId] = useState(t.kind === 's3' ? t.accessKeyId : '');
  const [pathStyle, setPathStyle] = useState(t.kind === 's3' ? t.pathStyle : false);
  const [secretKey, setSecretKey] = useState('');
  const [host, setHost] = useState(t.kind === 'sftp' ? t.host : '');
  const [port, setPort] = useState(String(t.kind === 'sftp' ? t.port : 22));
  const [username, setUsername] = useState(t.kind === 'sftp' ? t.username : '');
  const [remotePath, setRemotePath] = useState(t.kind === 'sftp' ? t.path : '/backups/any-ssh');
  const [fingerprint, setFingerprint] = useState(t.kind === 'sftp' ? t.hostKeyFingerprint : '');
  const [sftpPassword, setSftpPassword] = useState('');
  const [sftpKey, setSftpKey] = useState('');
  const [password, setPassword] = useState('');
  const [generated, setGenerated] = useState<{ publicKey: string; secretKey: string } | null>(null);
  const [kept, setKept] = useState(false);
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);

  const action = async (fn: () => Promise<string>) => {
    setBusy(true);
    try {
      toast.success(await fn());
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(false);
      info.reload();
    }
  };

  const target = () => {
    if (kind === 's3') {
      return { kind, endpoint: endpoint.trim(), region: region.trim(), bucket: bucket.trim(), prefix: prefix.trim(), accessKeyId: accessKeyId.trim(), pathStyle, ...(secretKey ? { secretKey } : {}) };
    }
    if (kind === 'sftp') {
      return {
        kind,
        host: host.trim(),
        port: Number(port),
        username: username.trim(),
        path: remotePath.trim(),
        hostKeyFingerprint: fingerprint.trim(),
        ...(sftpPassword ? { password: sftpPassword } : {}),
        ...(sftpKey ? { privateKey: sftpKey } : {}),
      };
    }
    return { kind };
  };

  return (
    <div className="card settings-section">
      <div className="page-head">
        <h2>Backups</h2>
        {(b.publicKey || b.target.kind !== 'none' || b.encryption !== 'recovery') && (
          <button
            className="ghost small"
            onClick={async () => {
              const ok = await confirm({
                title: 'Remove backup destination?',
                message: 'Scheduled backups will stop. The destination, its saved credentials and the recovery public key will be removed from Any-SSH. Backups already stored there are not deleted.',
                confirmLabel: 'Remove destination',
                danger: true,
              });
              if (ok) {
                onSaved(await del<SettingsView>('/api/admin/settings/backup'), true);
                toast.success('Backup destination removed. Backups are off.');
              }
            }}
          >
            Remove backup destination
          </button>
        )}
      </div>
      <p className="muted small">
        Backups are verified and encrypted before they leave this server, so the data stays protected even if the storage is lost or stolen.
      </p>

      {status && (
        <div className="subsection">
          <h3>Status</h3>
          <p className={status.last?.outcome === 'failure' || status.stale ? 'error' : undefined}>
            {!status.configured
              ? 'Backups aren’t set up yet.'
              : status.running
                ? 'A backup is in progress…'
                : status.last
                  ? `Last backup ${status.last.outcome === 'success' ? 'completed' : 'failed'} ${formatTime(status.last.startedAt)}${status.last.outcome === 'success' ? ` (${size(status.last.bytes)})` : `: ${status.last.error}`}`
                  : 'No backups have run yet.'}
          </p>
          {status.stale && <p className="error">There hasn’t been a successful backup for more than two scheduled periods. Review the history below.</p>}
          {status.scheduled && status.nextRunAt && <p className="muted small">Next backup: {formatTime(status.nextRunAt)}. If the server is off at that time, the backup runs when it’s back on.</p>}
        </div>
      )}

      <Form
        submit="Save backup settings"
        success="Backup settings saved."
        onSubmit={async () => {
          if (
            encryption === 'none' &&
            b.encryption !== 'none' &&
            (kind === 's3' || kind === 'sftp') &&
            !(await confirm({
              title: 'Send unencrypted backups to another provider?',
              message: 'Anyone with access to that storage can read user accounts, password hashes, server addresses and the activity log.',
              confirmLabel: 'Send unencrypted backups',
              danger: true,
            }))
          ) {
            return false;
          }
          onSaved(
            await put<SettingsView>('/api/admin/settings/backup', {
              enabled,
              frequency,
              hourUtc: Number(hourUtc),
              weekday: Number(weekday),
              keep: Number(keep),
              encryption,
              publicKey: publicKey.trim(),
              target: target(),
              acceptUnencrypted: encryption === 'none' && acceptUnencrypted,
              currentPassword: password,
            }),
          );
          setPassword('');
          setSecretKey('');
          setSftpPassword('');
          setSftpKey('');
          info.reload();
        }}
      >
        <Field label="Encryption">
          <select value={encryption} onChange={(e) => setEncryption(e.target.value as BackupEncryption)}>
            <option value="recovery">Recovery key (most secure)</option>
            <option value="system">System-managed</option>
            <option value="none">No encryption (not recommended)</option>
          </select>
        </Field>
        {encryption === 'recovery' && (
          <p className="muted small">
            Backups are encrypted with a recovery key. This server keeps only the public key, so neither this server nor the storage can read them. Store the secret key in a password manager, separate from the master key. You need both to restore a backup.
          </p>
        )}
        {encryption === 'system' && (
          <p className="muted small">
            Backups are encrypted with a key derived from this server&rsquo;s master key, so there is no extra key to store. The master key alone can restore them. The storage can’t read them, but anyone who has both a backup and this server (or its master key) can. After you rotate the master key, keep the old one until older backups have been deleted.
          </p>
        )}
        {encryption === 'none' && (
          <div className="card">
            <p className="error">
              <strong>Backups won’t be encrypted.</strong> Anyone who can read the storage can see every account, password hash, server address and the activity log.
              Saved SSH keys and passwords stay protected by the master key, but nothing else is.
            </p>
            {(kind === 's3' || kind === 'sftp') && <p className="error">These backups are sent to another provider. Choose an encryption option unless you fully trust that storage.</p>}
            <label className="check">
              <input type="checkbox" checked={acceptUnencrypted} onChange={(e) => setAcceptUnencrypted(e.target.checked)} /> I understand that backups will be stored without encryption
            </label>
          </div>
        )}
        {encryption === 'recovery' && (
          <>
          <Field label="Recovery public key" hint="Backups are encrypted with this key. Generate key pair below, or run `any-ssh backup-key` on a trusted computer so the secret key never reaches this server.">
            <input value={publicKey} onChange={(e) => setPublicKey(e.target.value)} placeholder="anybak-pub-1-…" className="mono" autoComplete="off" />
          </Field>
          {b.keyId && b.publicKey === publicKey.trim() && <p className="muted small">Key ID: {b.keyId}. Make sure it matches the ID saved with your secret key.</p>}
          <div className="row wrap">
            <button
              type="button"
              onClick={async () => {
                const pair = await post<{ publicKey: string; secretKey: string }>('/api/admin/backup/keypair');
                setGenerated(pair);
                setKept(false);
                setPublicKey(pair.publicKey);
                toast.success('Key pair generated. Save the secret key now.');
              }}
            >
              Generate key pair
            </button>
          </div>
          {generated && (
            <div className="card">
              <p>
                <strong>Save this secret key now.</strong> It’s shown only once and isn’t stored on this server. Without it, your backups can’t be restored.
              </p>
              <textarea readOnly rows={3} value={generated.secretKey} className="mono" onFocus={(e) => e.target.select()} />
              <div className="row wrap">
                <button type="button" onClick={() => downloadText('any-ssh-backup-secret-key.txt', `${generated.secretKey}\n`)}>
                  Download secret key
                </button>
                <label className="check">
                  <input type="checkbox" checked={kept} onChange={(e) => setKept(e.target.checked)} /> I’ve saved the secret key in a safe place
                </label>
                <button type="button" className="ghost small" disabled={!kept} onClick={() => setGenerated(null)}>
                  Hide secret key
                </button>
              </div>
            </div>
          )}
          </>
        )}

        <Field label="Where to store backups">
          <select value={kind} onChange={(e) => setKind(e.target.value as Kind)}>
            <option value="none">Not set up</option>
            <option value="s3">S3-compatible storage (AWS, Backblaze B2, Cloudflare R2, MinIO…)</option>
            <option value="sftp">SFTP server</option>
            <option value="local">This server (local folder)</option>
          </select>
        </Field>

        {kind === 's3' && (
          <>
            <div className="row2">
              <Field label="Endpoint" hint="Leave blank for Amazon S3. Otherwise enter https://host with no path.">
                <input value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="https://s3.eu-central-003.backblazeb2.com" />
              </Field>
              <Field label="Region">
                <input value={region} onChange={(e) => setRegion(e.target.value)} required />
              </Field>
            </div>
            <div className="row2">
              <Field label="Bucket">
                <input value={bucket} onChange={(e) => setBucket(e.target.value)} required />
              </Field>
              <Field label="Folder">
                <input value={prefix} onChange={(e) => setPrefix(e.target.value)} placeholder="any-ssh" />
              </Field>
            </div>
            <Field label="Access key ID">
              <input value={accessKeyId} onChange={(e) => setAccessKeyId(e.target.value)} autoComplete="off" required />
            </Field>
            <Field
              label="Secret access key"
              hint={t.kind === 's3' && t.hasSecretKey ? 'A secret access key is saved. Leave blank to keep it. If you change the endpoint, region, bucket or access key ID, you’ll need to enter it again.' : 'Stored encrypted and never shown again. Use a key that has write access to this bucket only.'}
            >
              <input type="password" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} autoComplete="new-password" placeholder={t.kind === 's3' && t.hasSecretKey ? '••••••••' : ''} />
            </Field>
            <label className="check">
              <input type="checkbox" checked={pathStyle} onChange={(e) => setPathStyle(e.target.checked)} /> Path-style addressing (MinIO and some others need this)
            </label>
          </>
        )}

        {kind === 'sftp' && (
          <>
            <div className="row2">
              <Field label="Server">
                <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="backup.example.com" required />
              </Field>
              <Field label="Port">
                <input value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" required />
              </Field>
            </div>
            <div className="row2">
              <Field label="Username">
                <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" required />
              </Field>
              <Field label="Folder">
                <input value={remotePath} onChange={(e) => setRemotePath(e.target.value)} required />
              </Field>
            </div>
            <Field label="Server fingerprint" hint="Required before Any-SSH connects. To see the server’s fingerprint, leave this blank, save, then select “Test destination” and verify it.">
              <input value={fingerprint} onChange={(e) => setFingerprint(e.target.value)} className="mono" placeholder="SHA256:…" />
            </Field>
            <Field
              label="Password"
              hint={t.kind === 'sftp' && t.hasPassword ? 'A password is saved. Leave blank to keep it. If you change the server or username, you’ll need to enter it again.' : 'Stored encrypted and never shown again. You can use a private key instead.'}
            >
              <input type="password" value={sftpPassword} onChange={(e) => setSftpPassword(e.target.value)} autoComplete="new-password" placeholder={t.kind === 'sftp' && t.hasPassword ? '••••••••' : ''} />
            </Field>
            <Field label="Private key (optional)" hint={t.kind === 'sftp' && t.hasPrivateKey ? 'A private key is saved. Leave blank to keep it.' : 'Paste an OpenSSH or PEM private key without a passphrase. It’s stored encrypted.'}>
              <textarea rows={3} value={sftpKey} onChange={(e) => setSftpKey(e.target.value)} className="mono" />
            </Field>
          </>
        )}

        {kind !== 'none' && (
          <>
            <label className="check">
              <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Back up automatically
            </label>
            {enabled && (
              <>
                <div className="row2">
                  <Field label="How often">
                    <select value={frequency} onChange={(e) => setFrequency(e.target.value as typeof frequency)}>
                      <option value="hourly">Every hour</option>
                      <option value="daily">Every day</option>
                      <option value="weekly">Every week</option>
                    </select>
                  </Field>
                  {frequency !== 'hourly' && (
                    <Field label="Hour (UTC)">
                      <input value={hourUtc} onChange={(e) => setHour(e.target.value)} inputMode="numeric" required />
                    </Field>
                  )}
                </div>
                {frequency === 'weekly' && (
                  <Field label="Day of the week">
                    <select value={weekday} onChange={(e) => setWeekday(e.target.value)}>
                      {WEEKDAYS.map((d, i) => (
                        <option key={d} value={i}>
                          {d}
                        </option>
                      ))}
                    </select>
                  </Field>
                )}
              </>
            )}
            <Field label="Backups to keep" hint="After each successful backup, older backups beyond this number are deleted from the destination.">
              <input value={keep} onChange={(e) => setKeep(e.target.value)} inputMode="numeric" required />
            </Field>
          </>
        )}

        <Field label="Your password" hint="Required to change the backup destination or encryption.">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </Field>
      </Form>

      <div className="subsection">
        <h3>Test and back up</h3>
        <p className="muted small">Both use your saved settings. “Test destination” writes and deletes a small file. “Back up now” creates a real backup.</p>
        <div className="row wrap">
          <button
            disabled={busy}
            onClick={() =>
              action(async () => {
                const r = await post<{ destination: string }>('/api/admin/backup/test');
                return `Connected to ${r.destination}. A test file was written and removed.`;
              })
            }
          >
            Test destination
          </button>
          <button
            className="primary"
            disabled={busy || !status?.configured}
            onClick={() =>
              action(async () => {
                const r = await post<{ run: BackupRunView }>('/api/admin/backup/run');
                if (r.run.outcome !== 'success') throw new Error(r.run.error ?? 'The backup didn’t complete.');
                return `Backup saved: ${r.run.name} (${size(r.run.bytes)}).`;
              })
            }
          >
            Back up now
          </button>
        </div>
      </div>

      {info.data && info.data.runs.length > 0 && (
        <div className="subsection">
          <h3>History</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Status</th>
                  <th>Started by</th>
                  <th>Encryption</th>
                  <th>Size</th>
                  <th>Destination</th>
                </tr>
              </thead>
              <tbody>
                {info.data.runs.map((r) => (
                  <RunLine key={r.id} run={r} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="subsection">
        <h3>Restore a backup</h3>
        <p className="muted small">
          Restoring replaces the entire database, so it must be done on the server rather than in the browser: <code>sudo any-ssh restore &lt;backup file&gt; [secret key file]</code>. The secret key file is needed only for backups encrypted with a recovery key. The backup is checked before anything is replaced. To confirm a backup can be restored without changing anything, run <code>any-ssh verify-backup</code>.
        </p>
      </div>
    </div>
  );
}
