import { useState } from 'react';
import type { Alert } from '../../shared/types.ts';
import { api } from '../api.ts';
import { dateTime } from '../format.ts';

const SNOOZES = [
  { minutes: 60, label: '1 hour' },
  { minutes: 240, label: '4 hours' },
  { minutes: 1440, label: '24 hours' },
  { minutes: 7 * 1440, label: '7 days' },
  { minutes: 30 * 1440, label: '30 days' },
];

/** Who took an alert: acknowledged by …, snoozed until … */
export function AlertTaken({ a }: { a: Alert }) {
  if (!a.ackedAt && !a.snoozedUntil) return null;
  return (
    <span className="muted small">
      {a.ackedAt && <>Acknowledged by {a.ackedBy ?? 'someone'}</>}
      {a.ackedAt && a.snoozedUntil && ' · '}
      {a.snoozedUntil && <>Telegram snoozed until {dateTime(a.snoozedUntil)}</>}
    </span>
  );
}

/** Acknowledge (someone is on it) and snooze (no Telegram for this alert for a while). */
export function AlertActions({ a, onDone }: { a: Alert; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    fn().then(
      () => {
        setBusy(false);
        onDone();
      },
      (e: Error) => {
        setBusy(false);
        setError(e.message);
      },
    );
  };
  return (
    <span className="alert-actions" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>
      {!a.resolvedAt && !a.ackedAt && (
        <button type="button" className="btn" disabled={busy} onClick={() => run(() => api.ack(a.id))}>
          Acknowledge
        </button>
      )}
      {!a.snoozedUntil && (
        <select
          className="btn"
          aria-label="Snooze Telegram for this alert"
          value=""
          disabled={busy}
          onChange={(e) => {
            const m = Number(e.target.value);
            if (m) run(() => api.snooze(a.id, m));
          }}
        >
          <option value="">Snooze…</option>
          {SNOOZES.map((s) => (
            <option key={s.minutes} value={s.minutes}>
              for {s.label}
            </option>
          ))}
        </select>
      )}
      {error && <span className="delta-up small">{error}</span>}
    </span>
  );
}
