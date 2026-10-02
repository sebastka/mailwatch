// Formatting. Times are shown in the server's TIMEZONE, so everyone sees the same thing.
let tz = 'UTC';
export const setTimezone = (t: string) => {
  tz = t;
};

export const num = (n: number) => n.toLocaleString('en');

export function compact(n: number): string {
  if (n < 10_000) return num(n);
  return new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 }).format(n);
}

export function percent(r: number | null): string {
  if (r === null) return '–';
  const p = r * 100;
  // Keep 99.97% from rounding up to a misleading 100.0%.
  if (p > 99.9 && p < 100) return `${p.toFixed(2)}%`;
  return `${p.toFixed(1)}%`;
}

const fmt = (o: Intl.DateTimeFormatOptions) => new Intl.DateTimeFormat('en-GB', { timeZone: tz, ...o });

/** "3 Sep" for an ISO instant; YYYY-MM-DD days are UTC dates and shown as such. */
export function shortDay(s: string): string {
  if (s.length === 10)
    return new Intl.DateTimeFormat('en-GB', { timeZone: 'UTC', day: 'numeric', month: 'short' }).format(
      new Date(`${s}T00:00:00Z`),
    );
  return fmt({ day: 'numeric', month: 'short' }).format(new Date(s));
}

/** "2026-09-03" for an ISO string (UTC). */
export const day = (s: string) => s.slice(0, 10);

export function dateTime(s: string | null): string {
  if (!s) return '–';
  return fmt({ day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }).format(
    new Date(s),
  );
}

export function ago(s: string | null, now = Date.now()): string {
  if (!s) return 'never';
  const sec = Math.round((now - Date.parse(s)) / 1000);
  if (sec < 0) return 'in a moment';
  if (sec < 45) return 'just now';
  const min = Math.round(sec / 60);
  if (min < 60) return `${min} min ago`;
  const h = Math.round(min / 60);
  if (h < 36) return `${h} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

export function duration(from: string, to: string | null, now = Date.now()): string {
  const min = Math.round(((to ? Date.parse(to) : now) - Date.parse(from)) / 60_000);
  if (min < 60) return `${min} min`;
  const h = min / 60;
  if (h < 48) return `${Math.round(h * 10) / 10} h`;
  return `${Math.round(h / 24)} days`;
}

/** "42 s", "3 min 10 s", "2 h 5 min" */
export function seconds(n: number | null): string {
  if (n === null) return '–';
  if (n < 60) return `${n} s`;
  if (n < 3600) return `${Math.floor(n / 60)} min${n % 60 ? ` ${n % 60} s` : ''}`;
  return `${Math.floor(n / 3600)} h ${Math.round((n % 3600) / 60)} min`;
}

export function todayUtc(offsetDays = 0): string {
  return new Date(Date.now() + offsetDays * 86_400_000).toISOString().slice(0, 10);
}

export const plural = (n: number, one: string, many = `${one}s`) => `${num(n)} ${n === 1 ? one : many}`;
