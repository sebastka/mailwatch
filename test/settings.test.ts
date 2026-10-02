import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isQuiet, parseSettings, quietPeriod } from '../src/server/settings.ts';

const q = (start: string, end: string, enabled = true) => ({ enabled, start, end, exemptErrors: true });
const t = (s: string) => Date.parse(s);
const iso = (n: number) => new Date(n).toISOString();

test('quiet hours spanning midnight, in the configured time zone', () => {
  const tz = 'Europe/Copenhagen';
  const night = q('22:00', '07:00');
  // 23:30 local (CEST, UTC+2) is quiet; the period started 22:00 local.
  const p = quietPeriod(night, t('2026-09-28T21:30:00Z'), tz);
  assert.deepEqual(
    [p.active, iso(p.start), iso(p.end)],
    [true, '2026-09-28T20:00:00.000Z', '2026-09-29T05:00:00.000Z'],
  );
  // 06:59 local next morning still quiet; 07:00 not, and the last period is the night before.
  assert.equal(isQuiet(night, t('2026-09-29T04:59:00Z'), tz), true);
  const after = quietPeriod(night, t('2026-09-29T05:00:00Z'), tz);
  assert.deepEqual([after.active, iso(after.end)], [false, '2026-09-29T05:00:00.000Z']);
  assert.equal(isQuiet(night, t('2026-09-29T12:00:00Z'), tz), false);
  // Disabled quiet hours are never quiet.
  assert.equal(isQuiet(q('22:00', '07:00', false), t('2026-09-28T21:30:00Z'), tz), false);
  // The same clock times in winter (UTC+1).
  const w = quietPeriod(night, t('2026-12-01T22:00:00Z'), tz);
  assert.deepEqual([w.active, iso(w.start)], [true, '2026-12-01T21:00:00.000Z']);
});

test('quiet hours within one day', () => {
  const lunch = q('12:00', '13:00');
  assert.equal(isQuiet(lunch, t('2026-09-28T12:30:00Z'), 'UTC'), true);
  assert.equal(isQuiet(lunch, t('2026-09-28T13:30:00Z'), 'UTC'), false);
  assert.equal(iso(quietPeriod(lunch, t('2026-09-28T11:00:00Z'), 'UTC').end), '2026-09-27T13:00:00.000Z');
});

test('settings are validated', () => {
  assert.equal(typeof parseSettings({ quietHours: q('22:00', '07:00') }), 'object');
  assert.match(parseSettings({ quietHours: q('25:00', '07:00') }) as string, /start/);
  assert.match(parseSettings({ quietHours: q('07:00', '07:00') }) as string, /same time/);
  assert.match(parseSettings({ quietHours: { ...q('22:00', '07:00'), enabled: 'yes' } }) as string, /enabled/);
  assert.match(parseSettings(null) as string, /JSON object/);
});
