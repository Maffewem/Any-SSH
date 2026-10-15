import { randomUUID } from 'node:crypto';
import type { DB } from './db.js';
import { windowState, type MaintenanceWindow } from './maintenance.js';

/**
 * Updates asked for in the web app, and the host agent's heartbeat. The web app cannot touch Docker: it only
 * records the request here. The host's `any-ssh update-poll` (a systemd timer) reads it from the database, and
 * starts the update (backup first, rollback if unhealthy) once `scheduled_for` has passed. The delay is the
 * warning period for people with open terminals.
 */

/** How long connected users are warned before an update restarts the server. */
export const WARNING_MINUTES = 2;
/** The agent polls every few minutes; a heartbeat older than this means it is not running. */
export const AGENT_STALE_MS = 15 * 60_000;

export interface UpdateRequest {
  id: string;
  requestedAt: number;
  requestedBy: string;
  trigger: 'manual' | 'auto';
  scheduledFor: number;
  announced: boolean;
}

interface Row {
  id: string;
  requested_at: number;
  requested_by: string;
  trigger: 'manual' | 'auto';
  scheduled_for: number;
  announced: number;
}

const toRequest = (r: Row): UpdateRequest => ({
  id: r.id,
  requestedAt: r.requested_at,
  requestedBy: r.requested_by,
  trigger: r.trigger,
  scheduledFor: r.scheduled_for,
  announced: r.announced === 1,
});

export class UpdateRequests {
  constructor(private readonly db: DB) {}

  /** The request waiting to run, if any. */
  pending(): UpdateRequest | null {
    const r = this.db.prepare("SELECT * FROM update_requests WHERE status = 'pending' ORDER BY requested_at DESC LIMIT 1").get() as Row | undefined;
    return r ? toRequest(r) : null;
  }

  /** Records a request. Returns null when one is already waiting. */
  create(requestedBy: string, trigger: 'manual' | 'auto', now = Date.now()): UpdateRequest | null {
    if (this.pending()) return null;
    const id = randomUUID();
    this.db
      .prepare("INSERT INTO update_requests (id, requested_at, requested_by, trigger, scheduled_for, status) VALUES (?, ?, ?, ?, ?, 'pending')")
      .run(id, now, requestedBy, trigger, now + WARNING_MINUTES * 60_000);
    return this.pending();
  }

  cancel(id: string): boolean {
    return this.db.prepare("UPDATE update_requests SET status = 'cancelled' WHERE id = ? AND status = 'pending'").run(id).changes > 0;
  }

  markAnnounced(id: string): void {
    this.db.prepare('UPDATE update_requests SET announced = 1 WHERE id = ?').run(id);
  }

  /** Host agent: the next request that is due, marked as started so it runs once. */
  claimDue(now = Date.now()): UpdateRequest | null {
    return this.db.transaction(() => {
      const r = this.db.prepare("SELECT * FROM update_requests WHERE status = 'pending' AND scheduled_for <= ? ORDER BY scheduled_for LIMIT 1").get(now) as Row | undefined;
      if (!r) return null;
      this.db.prepare("UPDATE update_requests SET status = 'started' WHERE id = ?").run(r.id);
      return toRequest(r);
    })();
  }

  heartbeat(now = Date.now()): void {
    this.db.prepare('UPDATE update_agent SET last_seen_at = ? WHERE id = 1').run(now);
  }

  agent(): { lastSeenAt: number | null; lastAutoCheck: number | null } {
    const r = this.db.prepare('SELECT last_seen_at, last_auto_check FROM update_agent WHERE id = 1').get() as { last_seen_at: number | null; last_auto_check: number | null };
    return { lastSeenAt: r.last_seen_at, lastAutoCheck: r.last_auto_check };
  }

  agentActive(now = Date.now()): boolean {
    const seen = this.agent().lastSeenAt;
    return seen !== null && now - seen < AGENT_STALE_MS;
  }

  /**
   * Host agent: should it look for an update now on its own? Only when automatic updates are on, no request is
   * waiting, the maintenance window is open (if one is set), and it has not already looked during this window
   * (or in the last 24 hours when there is no window). Records the check.
   */
  shouldCheckAuto(autoUpdate: boolean, window: MaintenanceWindow, now = Date.now()): boolean {
    if (!autoUpdate || this.pending()) return false;
    const state = windowState(window, now);
    if (!state.open) return false;
    const last = this.agent().lastAutoCheck;
    const since = state.currentStart ?? now - 24 * 3600_000;
    if (last !== null && last >= since) return false;
    this.db.prepare('UPDATE update_agent SET last_auto_check = ? WHERE id = 1').run(now);
    return true;
  }

  /** Host agent: an automatic update was found; schedule it, unless the window would close before it starts. */
  scheduleAuto(window: MaintenanceWindow, now = Date.now()): UpdateRequest | null {
    const state = windowState(window, now);
    if (state.currentEnd !== null && state.currentEnd < now + (WARNING_MINUTES + 1) * 60_000) return null;
    return this.create('automatic update', 'auto', now);
  }
}
