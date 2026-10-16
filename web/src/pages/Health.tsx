import { useEffect, useState } from 'react';
import { errorMessage, formatTime, get, post, type Health, type HealthProbe } from '../api';

const bytes = (n: number | null) => {
  if (n === null) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) (v /= 1024), i++;
  return `${v.toFixed(i === 0 || v >= 100 ? 0 : 1)} ${units[i]}`;
};

function duration(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
}

function Reach({ probe }: { probe: HealthProbe | null }) {
  if (!probe) return <span className="muted">Not checked yet</span>;
  return probe.reachable ? (
    <span className="ok">Reachable · {probe.latencyMs} ms</span>
  ) : (
    <span className="error" title={probe.error ?? undefined}>
      Unreachable
    </span>
  );
}

function HostKey({ state }: { state: 'pinned' | 'unverified' | 'changed' }) {
  return state === 'pinned' ? (
    <span className="ok">Verified</span>
  ) : state === 'changed' ? (
    <span className="error">CHANGED, connections refused</span>
  ) : (
    <span className="warn-text">Not verified yet</span>
  );
}

/** Admin-only status of this install, the jump hosts and every saved server. */
export function HealthPage() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  const check = async () => {
    setChecking(true);
    try {
      setHealth(await post<Health>('/api/admin/health/check'));
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setChecking(false);
    }
  };

  // Show the last result at once, then measure.
  useEffect(() => {
    get<Health>('/api/admin/health').then(setHealth, (e) => setError(errorMessage(e)));
    void check();
  }, []);

  const s = health?.summary;
  const cert = health?.certificate;
  const attention =
    s && (s.unreachable > 0 || s.hostKeyChanged > 0 || s.jumpHostsDown > 0 || s.noJumpHostAvailable || health.backups.stale || (cert?.daysLeft ?? 99) < 14);

  return (
    <section>
      <div className="page-head">
        <h1>Status</h1>
        <button onClick={check} disabled={checking}>
          {checking ? 'Checking…' : 'Check now'}
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {health && s && (
        <>
          <p className={attention ? 'warn-text' : 'ok'}>
            {attention ? 'Needs attention: ' : 'All good: '}
            {s.reachable} of {s.servers - s.viaJumpHost} directly reachable
            {s.viaJumpHost > 0 ? `, ${s.viaJumpHost} via jump hosts` : ''}
            {s.hostKeyChanged > 0 ? `, ${s.hostKeyChanged} with a changed host key` : ''}
            {s.hostKeyUnverified > 0 ? `, ${s.hostKeyUnverified} not verified yet` : ''}
            {s.jumpHostsDown > 0 ? `, ${s.jumpHostsDown} jump host${s.jumpHostsDown === 1 ? '' : 's'} down` : ''}.
          </p>
          {s.noJumpHostAvailable && <p className="warn-text">Some servers are set to use the closest jump host, but none is enabled.</p>}

          <h2>This install</h2>
          <div className="card">
            <dl className="facts">
              <dt>Version</dt>
              <dd>
                {health.app.version}
                {health.app.commit ? ` (${health.app.commit.slice(0, 7)})` : ''}
                {health.app.updateAvailable ? <span className="warn-text"> · update available</span> : null}
              </dd>
              <dt>Running for</dt>
              <dd>
                {duration(health.app.uptimeSeconds)} · since {formatTime(health.app.startedAt)}
              </dd>
              <dt>Open terminals</dt>
              <dd>
                {health.app.terminals.open}
                {health.app.terminals.detached > 0 ? ` (${health.app.terminals.detached} waiting to reconnect)` : ''}
              </dd>
              <dt>Disk</dt>
              <dd>
                {bytes(health.storage.freeBytes)} free of {bytes(health.storage.totalBytes)} · database {bytes(health.storage.databaseBytes)}
              </dd>
              <dt>Certificate</dt>
              <dd>
                {!cert ? (
                  <span className="muted">Not checked (needs an https public address)</span>
                ) : cert.error ? (
                  <span className="muted">{cert.error}</span>
                ) : (
                  <span className={cert.trusted === false || (cert.daysLeft ?? 0) < 14 ? 'error' : 'ok'}>
                    {cert.host}: expires {formatTime(cert.notAfter)} ({cert.daysLeft} days)
                    {cert.trusted === false ? ' · not trusted' : ''}
                  </span>
                )}
              </dd>
              <dt>Backups</dt>
              <dd>
                {!health.backups.configured ? (
                  <span className="muted">Not set up</span>
                ) : (
                  <span className={health.backups.stale || health.backups.lastOutcome === 'failure' ? 'error' : ''}>
                    Last success {formatTime(health.backups.lastSuccessAt)}
                    {health.backups.stale ? ' · overdue' : ''}
                    {health.backups.lastOutcome === 'failure' ? ' · last attempt failed' : ''}
                  </span>
                )}
              </dd>
            </dl>
          </div>

          <h2>Jump hosts</h2>
          {health.jumpHosts.length === 0 ? (
            <p className="muted">None set up.</p>
          ) : (
            <div className="table-wrap card">
              <table className="small">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Reachability</th>
                    <th>Host key</th>
                    <th>Servers</th>
                  </tr>
                </thead>
                <tbody>
                  {health.jumpHosts.map((j) => (
                    <tr key={j.id}>
                      <td>
                        {j.name}
                        {!j.enabled && <span className="badge">Disabled</span>}
                        <br />
                        <span className="muted mono">
                          {j.host}:{j.port}
                        </span>
                      </td>
                      <td>
                        <Reach probe={j.probe} />
                      </td>
                      <td>
                        <HostKey state={j.hostKey} />
                      </td>
                      <td>{j.serverCount}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <h2>Servers</h2>
          {health.servers.length === 0 ? (
            <p className="muted">No servers saved yet.</p>
          ) : (
            <div className="table-wrap card">
              <table className="small">
                <thead>
                  <tr>
                    <th>Server</th>
                    <th>Reachability</th>
                    <th>Host key</th>
                    <th>Route</th>
                  </tr>
                </thead>
                <tbody>
                  {health.servers.map((v) => (
                    <tr key={v.id} className={v.hostKey === 'changed' || (v.probe && !v.probe.reachable) ? 'failure' : ''}>
                      <td>
                        {v.name}
                        <br />
                        <span className="muted mono">
                          {v.host}
                          {v.port !== 22 ? `:${v.port}` : ''} · @{v.owner}
                        </span>
                      </td>
                      <td>{v.route.testable ? <Reach probe={v.probe} /> : <span className="muted">Not tested directly</span>}</td>
                      <td>
                        <HostKey state={v.hostKey} />
                      </td>
                      <td>
                        {v.route.mode === 'none' ? 'Direct' : v.route.mode === 'auto' ? 'Closest jump host' : `Via ${v.route.jumpHost ?? 'a missing jump host'}`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="muted small">Last checked {formatTime(health.generatedAt)}.</p>
        </>
      )}
    </section>
  );
}
