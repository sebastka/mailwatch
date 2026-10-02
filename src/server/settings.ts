// Settings edited in the app (stored in the meta table): quiet hours, the minimum severity sent
// to Telegram, and whether record changes are announced. Quiet hours as in zdwatch.
import type { QuietHours, Settings, Severity } from '../shared/types.ts';
import type { Store } from './db.ts';

export const DEFAULT_SETTINGS: Settings = {
  quietHours: { enabled: false, start: '22:00', end: '07:00', exemptErrors: true },
  notifyMinSeverity: 'warning',
  notifyChanges: true,
};

export const SEVERITY_ORDER: Record<Severity, number> = { info: 1, warning: 2, error: 3 };

const TIME_RE = /^([01]\d|2[0-3]):([0-5]\d)$/;
const minutesOf = (hhmm: string) => {
  const m = TIME_RE.exec(hhmm)!;
  return Number(m[1]) * 60 + Number(m[2]);
};

export function parseSettings(v: unknown): Settings | string {
  if (!v || typeof v !== 'object') return 'expected a JSON object';
  const o = v as { quietHours?: Record<string, unknown>; notifyMinSeverity?: unknown; notifyChanges?: unknown };
  const q = o.quietHours;
  if (!q || typeof q !== 'object') return 'quietHours is required';
  if (typeof q.enabled !== 'boolean') return 'quietHours.enabled must be true or false';
  if (typeof q.exemptErrors !== 'boolean') return 'quietHours.exemptErrors must be true or false';
  for (const k of ['start', 'end'] as const) {
    if (typeof q[k] !== 'string' || !TIME_RE.test(q[k])) return `quietHours.${k} must be a time like 22:00`;
  }
  if (q.start === q.end) return 'quiet hours must not start and end at the same time';
  const sev = o.notifyMinSeverity ?? DEFAULT_SETTINGS.notifyMinSeverity;
  if (sev !== 'info' && sev !== 'warning' && sev !== 'error') return 'notifyMinSeverity must be info, warning or error';
  const changes = o.notifyChanges ?? DEFAULT_SETTINGS.notifyChanges;
  if (typeof changes !== 'boolean') return 'notifyChanges must be true or false';
  return {
    quietHours: { enabled: q.enabled, start: q.start as string, end: q.end as string, exemptErrors: q.exemptErrors },
    notifyMinSeverity: sev,
    notifyChanges: changes,
  };
}

export async function loadSettings(store: Store): Promise<Settings> {
  const raw = await store.getMeta('settings');
  if (!raw) return DEFAULT_SETTINGS;
  try {
    const parsed = parseSettings(JSON.parse(raw));
    return typeof parsed === 'string' ? DEFAULT_SETTINGS : parsed;
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export async function saveSettings(store: Store, s: Settings): Promise<void> {
  await store.setMeta('settings', JSON.stringify(s));
}

const HOUR = 3_600_000;
const offsets = new Map<string, number>();
const formatters = new Map<string, Intl.DateTimeFormat>();

/** Offset of `tz` from UTC at instant t, in milliseconds (local = utc + offset). */
export function tzOffset(t: number, tz: string): number {
  // Offsets change on whole (quarter) hours; cache per hour.
  const key = `${tz}|${Math.floor(t / HOUR)}`;
  const hit = offsets.get(key);
  if (hit !== undefined) return hit;
  let f = formatters.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      hourCycle: 'h23',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
    formatters.set(tz, f);
  }
  const p = Object.fromEntries(f.formatToParts(t).map((x) => [x.type, x.value]));
  const asUtc = Date.UTC(+p.year!, +p.month! - 1, +p.day!, +p.hour!, +p.minute!, +p.second!);
  const off = asUtc - Math.floor(t / 1000) * 1000;
  if (offsets.size > 50_000) offsets.clear();
  offsets.set(key, off);
  return off;
}

/**
 * The quiet period (start and end instants) that contains `now`, or else the latest one that
 * ended before it. Times are daily in `tz`; "22:00"–"07:00" spans midnight.
 */
export function quietPeriod(q: QuietHours, now: number, tz: string): { start: number; end: number; active: boolean } {
  const startMin = minutesOf(q.start);
  const length = ((minutesOf(q.end) - startMin + 1440) % 1440) * 60_000;
  const DAY = 86_400_000;
  const localMidnight = Math.floor((now + tzOffset(now, tz)) / DAY) * DAY;
  let best: { start: number; end: number; active: boolean } | null = null;
  for (let d = 0; d <= 2; d++) {
    const localStart = localMidnight - d * DAY + startMin * 60_000;
    const start = localStart - tzOffset(localStart - tzOffset(now, tz), tz);
    const end = start + length;
    if (start <= now && now < end) return { start, end, active: true };
    if (end <= now && (!best || end > best.end)) best = { start, end, active: false };
  }
  return best!;
}

export const isQuiet = (q: QuietHours, now: number, tz: string) => q.enabled && quietPeriod(q, now, tz).active;
