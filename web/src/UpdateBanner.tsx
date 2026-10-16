import { useEffect, useState } from 'react';
import { get } from './api';

/** Shown to everyone signed in while an update is scheduled, so a restart never comes as a surprise. */
export function UpdateBanner() {
  const [at, setAt] = useState<number | null>(null);
  const [, tick] = useState(0);
  useEffect(() => {
    let live = true;
    const load = () =>
      get<{ scheduledFor: number | null }>('/api/update-notice').then(
        (r) => live && setAt(r.scheduledFor),
        () => {},
      );
    void load();
    const poll = setInterval(load, 30_000);
    const clock = setInterval(() => tick((n) => n + 1), 15_000);
    return () => {
      live = false;
      clearInterval(poll);
      clearInterval(clock);
    };
  }, []);
  if (!at) return null;
  const mins = Math.max(0, Math.ceil((at - Date.now()) / 60_000));
  return (
    <div className="update-banner" role="status">
      Any-SSH will update and restart{mins > 0 ? ` in about ${mins} minute${mins === 1 ? '' : 's'}` : ' now'}. Open terminals will disconnect briefly and
      reconnect automatically. Finish any important work first.
    </div>
  );
}
