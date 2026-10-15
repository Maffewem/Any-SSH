/**
 * Maintenance window: when automatic updates may be applied. Evaluated in an IANA timezone so
 * "Sunday 04:00" stays 04:00 across daylight-saving changes.
 */
export interface MaintenanceWindow {
  enabled: boolean;
  /** 0 = Sunday … 6 = Saturday: the day the window opens. */
  days: number[];
  /** Local opening time, "HH:MM". */
  start: string;
  durationMinutes: number;
  timezone: string;
}

export const DEFAULT_MAINTENANCE: MaintenanceWindow = {
  enabled: false,
  days: [0, 1, 2, 3, 4, 5, 6],
  start: '04:00',
  durationMinutes: 120,
  timezone: 'UTC',
};

export function validTimezone(tz: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

interface Parts {
  y: number;
  m: number;
  d: number;
  h: number;
  mi: number;
}

function partsIn(ts: number, tz: string): Parts {
  const f = new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric' });
  const get = (t: string) => Number(f.formatToParts(ts).find((p) => p.type === t)!.value);
  return { y: get('year'), m: get('month'), d: get('day'), h: get('hour'), mi: get('minute') };
}

/** The instant at which the wall clock in `tz` reads y-m-d h:mi. */
function instantOf(y: number, m: number, d: number, h: number, mi: number, tz: string): number {
  const wall = Date.UTC(y, m - 1, d, h, mi);
  let guess = wall;
  for (let i = 0; i < 2; i++) {
    const p = partsIn(guess, tz);
    guess += wall - Date.UTC(p.y, p.m - 1, p.d, p.h, p.mi);
  }
  return guess;
}

export interface WindowState {
  /** True when automatic updates may be applied right now. Always true when no window is configured. */
  open: boolean;
  /** When the window that is open now began (or null). */
  currentStart: number | null;
  currentEnd: number | null;
  /** When the next window begins (null when none is configured). */
  nextStart: number | null;
}

export function windowState(w: MaintenanceWindow, now = Date.now()): WindowState {
  if (!w.enabled || w.days.length === 0) return { open: true, currentStart: null, currentEnd: null, nextStart: null };
  const [hh, mm] = w.start.split(':').map(Number) as [number, number];
  const today = partsIn(now, w.timezone);
  let currentStart: number | null = null;
  let nextStart: number | null = null;
  for (let off = -2; off <= 8; off++) {
    const day = new Date(Date.UTC(today.y, today.m - 1, today.d + off));
    if (!w.days.includes(day.getUTCDay())) continue;
    const start = instantOf(day.getUTCFullYear(), day.getUTCMonth() + 1, day.getUTCDate(), hh, mm, w.timezone);
    const end = start + w.durationMinutes * 60_000;
    if (start <= now && now < end) currentStart = start;
    else if (start > now && (nextStart === null || start < nextStart)) nextStart = start;
  }
  return { open: currentStart !== null, currentStart, currentEnd: currentStart === null ? null : currentStart + w.durationMinutes * 60_000, nextStart };
}
