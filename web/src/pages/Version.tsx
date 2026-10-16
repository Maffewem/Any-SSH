import { useEffect, useState } from 'react';
import { del, errorMessage, formatTime, get, post } from '../api';
import { useAsync, useConfirm, useToast } from '../ui';

interface Published {
  version: string | null;
  commit: string | null;
  builtAt: string | null;
}
interface VersionInfo {
  current: Published;
  checkEnabled: boolean;
  autoUpdate: boolean;
  image: string;
  checkedAt: number | null;
  latest: Published | null;
  updateAvailable: boolean | null;
  error: string | null;
  maintenance: { enabled: boolean; days: number[]; start: string; durationMinutes: number; timezone: string; open: boolean; nextStart: number | null };
  agentActive: boolean;
  pending: { id: string; scheduledFor: number; trigger: 'manual' | 'auto'; requestedBy: string } | null;
  warningMinutes: number;
}

interface HistoryEntry {
  id: number;
  ts: number;
  result: 'success' | 'failure' | 'rolled_back';
  trigger: 'manual' | 'auto';
  from: string;
  to: string;
  note: string | null;
}

const RESULT_LABEL = { success: 'Updated', failure: 'Failed', rolled_back: 'Rolled back' } as const;

const short = (c: string | null) => (c ? c.slice(0, 7) : 'unknown');

/** Admin-only: what is running, and whether a newer build has been published. Applying updates happens on the host. */
export function VersionCard() {
  const confirm = useConfirm();
  const toast = useToast();
  const { data } = useAsync(() => get<VersionInfo>('/api/admin/version'), []);
  const history = useAsync(() => get<{ updates: HistoryEntry[] }>('/api/admin/version/history'), []);
  const [busy, setBusy] = useState(false);
  const [info, setInfo] = useState<VersionInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  // Keep the page current (e.g. after the server restarts into a new build) without needing a manual reload.
  useEffect(() => {
    const id = setInterval(() => {
      get<VersionInfo>('/api/admin/version').then(setInfo, () => {});
    }, 30_000);
    return () => clearInterval(id);
  }, []);
  const v = info ?? data;
  if (!v) return null;

  const run = async (fn: () => Promise<VersionInfo>) => {
    setBusy(true);
    setError(null);
    try {
      setInfo(await fn());
      setConfirming(false);
      history.reload();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const check = async () => {
    setBusy(true);
    setError(null);
    try {
      setInfo(await post<VersionInfo>('/api/admin/version/check'));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card" style={{ padding: '0.75rem 1rem', marginBottom: '1rem' }}>
      <div className="page-head" style={{ margin: 0 }}>
        <div>
          <strong>Any-SSH {v.current.version ?? 'dev'}</strong>{' '}
          <span className="muted small" style={{ fontWeight: 400 }}>
            Build {short(v.current.commit)}
            {v.current.builtAt ? `, ${formatTime(Date.parse(v.current.builtAt))}` : ''}
          </span>
          {v.updateAvailable && <span className="badge warn" style={{ marginLeft: 8 }}>Update available</span>}
          {v.updateAvailable === false && <span className="badge" style={{ marginLeft: 8 }}>Up to date</span>}
        </div>
        {v.checkEnabled && (
          <button onClick={check} disabled={busy}>
            {busy ? 'Checking…' : 'Check for updates'}
          </button>
        )}
      </div>
      {v.updateAvailable && (
        <p className="small" style={{ margin: '0.5rem 0 0' }}>
          Build {short(v.latest?.commit ?? null)} is published. {v.autoUpdate ? 'Automatic updates are on and will install it.' : 'Run'}{' '}
          {!v.autoUpdate && <code>sudo any-ssh update</code>} {!v.autoUpdate && 'on the server to install it (it backs up first).'}
        </p>
      )}
      {v.pending ? (
        <div className="notice-row" role="status">
          <p className="small" style={{ margin: 0 }}>
            {v.pending.trigger === 'auto' ? 'Automatic update' : `Update requested by ${v.pending.requestedBy}`} scheduled for {formatTime(v.pending.scheduledFor)}. Connected users have been
            warned. The server backs up, installs and restarts within a few minutes of that time.
          </p>
          <button
            disabled={busy}
            onClick={async () => {
              const ok = await confirm({
                title: 'Cancel the scheduled update',
                message: 'Connected users will no longer be warned.',
                confirmLabel: 'Cancel update',
                danger: true,
              });
              if (ok) {
                await run(() => del<VersionInfo>('/api/admin/version/update-now'));
                toast.success('Scheduled update cancelled.');
              }
            }}
          >
            Cancel update
          </button>
        </div>
      ) : (
        <div style={{ margin: '0.5rem 0 0' }}>
          {!confirming ? (
            <button
              disabled={busy || !v.agentActive || (v.checkEnabled && v.updateAvailable !== true)}
              onClick={() => setConfirming(true)}
              title={!v.agentActive ? 'Needs the update agent on the server' : v.checkEnabled && v.updateAvailable !== true ? 'No newer version is known. Check for updates first.' : ''}
            >
              Update now
            </button>
          ) : (
            <p className="small" style={{ margin: 0 }}>
              Warn everyone connected, then back up and restart in about {v.warningMinutes} minutes? Open terminals disconnect and reconnect on their own.{' '}
              <button className="primary" disabled={busy} onClick={() => run(() => post<VersionInfo>('/api/admin/version/update-now'))}>
                {busy ? 'Scheduling…' : 'Yes, update'}
              </button>{' '}
              <button className="ghost" disabled={busy} onClick={() => setConfirming(false)}>
                Never mind
              </button>
            </p>
          )}
          {v.agentActive && v.checkEnabled && v.updateAvailable !== true && (
            <p className="muted small" style={{ margin: '0.25rem 0 0' }}>
              {v.updateAvailable === false ? 'This server is up to date.' : 'No update check has completed yet.'} Update now becomes available when a newer version is found; use “Check for updates” to look again.
            </p>
          )}
          {!v.agentActive && (
            <p className="muted small" style={{ margin: '0.25rem 0 0' }}>
              To enable this, run <code>sudo any-ssh web-update on</code> on the server once.
            </p>
          )}
        </div>
      )}
      <p className="muted small" style={{ margin: '0.5rem 0 0' }}>
        {v.maintenance.enabled
          ? `Maintenance window: ${v.maintenance.start} for ${v.maintenance.durationMinutes} min (${v.maintenance.timezone}); ${v.maintenance.open ? 'open now' : v.maintenance.nextStart ? `next opens ${formatTime(v.maintenance.nextStart)}` : 'closed'}.`
          : 'No maintenance window set: automatic updates may install at any time (once a day).'}
      </p>
      <p className="muted small" style={{ margin: '0.5rem 0 0' }}>
        {v.checkEnabled
          ? `Checks ${v.image} every few hours${v.checkedAt ? `; last checked ${formatTime(v.checkedAt)}` : ''}.`
          : 'Update checks are off (ANYSSH_UPDATE_CHECK=false).'}{' '}
        {v.autoUpdate ? 'Automatic updates: on.' : 'Automatic updates: off (any-ssh auto-update on).'}
      </p>
      {(error || v.error) && <p className="error small">{error ?? `Last check failed: ${v.error}`}</p>}
      <div className="subsection">
        <h3>Update history</h3>
        {history.data && history.data.updates.length === 0 && <p className="muted small">No updates recorded yet.</p>}
        {history.data && history.data.updates.length > 0 && (
          <div className="table-wrap" style={{ width: '100%' }}>
            <table className="small">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Result</th>
                  <th>Version</th>
                  <th>Started by</th>
                </tr>
              </thead>
              <tbody>
                {history.data.updates.map((u) => (
                  <tr key={u.id} className={u.result === 'success' ? '' : 'failure'}>
                    <td>{formatTime(u.ts)}</td>
                    <td>
                      {RESULT_LABEL[u.result] ?? u.result}
                      {u.note && <div className="muted">{u.note}</div>}
                    </td>
                    <td>
                      {u.from} → {u.to}
                    </td>
                    <td>{u.trigger === 'auto' ? 'Automatic update' : 'Manual'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {history.error && <p className="error small">{history.error}</p>}
      </div>
    </div>
  );
}
