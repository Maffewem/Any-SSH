import { useState } from 'react';
import { errorMessage, formatTime, get, post } from '../api';
import { useAsync } from '../ui';

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
}

const short = (c: string | null) => (c ? c.slice(0, 7) : 'unknown');

/** Admin-only: what is running, and whether a newer build has been published. Applying updates happens on the host. */
export function VersionCard() {
  const { data } = useAsync(() => get<VersionInfo>('/api/admin/version'), []);
  const [busy, setBusy] = useState(false);
  const [info, setInfo] = useState<VersionInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const v = info ?? data;
  if (!v) return null;

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
          <span className="muted small">
            build {short(v.current.commit)}
            {v.current.builtAt ? `, ${formatTime(Date.parse(v.current.builtAt))}` : ''}
          </span>
          {v.updateAvailable && <span className="badge warn" style={{ marginLeft: 8 }}>Update available</span>}
          {v.updateAvailable === false && <span className="badge" style={{ marginLeft: 8 }}>Up to date</span>}
        </div>
        {v.checkEnabled && (
          <button onClick={check} disabled={busy}>
            {busy ? 'Checking…' : 'Check now'}
          </button>
        )}
      </div>
      {v.updateAvailable && (
        <p className="small" style={{ margin: '0.5rem 0 0' }}>
          Build {short(v.latest?.commit ?? null)} is published. {v.autoUpdate ? 'Automatic updates are on and will install it.' : 'Run'}{' '}
          {!v.autoUpdate && <code>sudo any-ssh update</code>} {!v.autoUpdate && 'on the server to install it (it backs up first).'}
        </p>
      )}
      <p className="muted small" style={{ margin: '0.5rem 0 0' }}>
        {v.checkEnabled
          ? `Checks ${v.image} every few hours${v.checkedAt ? `; last checked ${formatTime(v.checkedAt)}` : ''}. Set ANYSSH_UPDATE_CHECK=false to turn this off.`
          : 'Update checks are turned off (ANYSSH_UPDATE_CHECK=false), so this server never contacts the registry.'}{' '}
        {v.autoUpdate ? 'Automatic updates: on.' : 'Automatic updates: off (any-ssh auto-update on).'}
      </p>
      {(error || v.error) && <p className="error small">{error ?? `Last check failed: ${v.error}`}</p>}
    </div>
  );
}
