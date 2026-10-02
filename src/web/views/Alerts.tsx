import { useState } from 'react';
import { alertPath, areaOf } from '../../shared/paths.ts';
import { api } from '../api.ts';
import { AlertActions, AlertTaken } from '../components/AlertActions.tsx';
import { Card, ErrorBanner, Refs, StatusIcon, StatusLabel } from '../components/ui.tsx';
import { dateTime, duration } from '../format.ts';
import { useAsync } from '../hooks.ts';

const RANGES = [
  { key: 'active', label: 'Active' },
  { key: '7', label: '7 days' },
  { key: '30', label: '30 days' },
  { key: '90', label: '90 days' },
  { key: '365', label: '1 year' },
] as const;

export function AlertsView({
  version,
  onChanged,
  onOpen,
}: {
  version: number;
  onChanged: () => void;
  onOpen: (path: string, domain?: string) => void;
}) {
  const [range, setRange] = useState<(typeof RANGES)[number]['key']>('active');
  const alerts = useAsync(
    () => api.alerts(range === 'active' ? { active: true } : { days: Number(range) }),
    [range, version],
  );
  const snoozes = useAsync(() => api.snoozes(), [version]);
  const rows = alerts.data ?? [];

  return (
    <>
      <div className="filters">
        <div className="segmented" role="group" aria-label="Alerts">
          {RANGES.map((r) => (
            <button key={r.key} type="button" aria-pressed={range === r.key} onClick={() => setRange(r.key)}>
              {r.label}
            </button>
          ))}
        </div>
      </div>
      {(snoozes.data?.length ?? 0) > 0 && (
        <div className="section-top">
          <Card title="Snoozed" desc="No Telegram messages for these alerts until the time shown">
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Alert</th>
                    <th>Until</th>
                    <th>By</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {snoozes.data!.map((z) => (
                    <tr key={z.key}>
                      <td>{z.title}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>{dateTime(z.until)}</td>
                      <td>{z.createdBy ?? '–'}</td>
                      <td>
                        <button type="button" className="btn" onClick={() => void api.unsnooze(z.key).then(onChanged)}>
                          Unsnooze
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}
      {alerts.error && <ErrorBanner>Could not load the alerts: {alerts.error}</ErrorBanner>}
      <Card
        title="Alerts"
        desc="A warning or error opens an alert once it is seen in ALERT_CONFIRMATIONS consecutive checks; it resolves as soon as it is gone. Click a row for the details."
      >
        <div className="table-wrap" style={{ opacity: alerts.loading ? 0.55 : 1 }}>
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Alert</th>
                <th>Domain</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Telegram</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr
                  key={a.id}
                  className="clickable"
                  tabIndex={0}
                  onClick={() => onOpen(alertPath(a), a.domain ?? '')}
                  onKeyDown={(e) => e.key === 'Enter' && onOpen(alertPath(a), a.domain ?? '')}
                >
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <span className="fail-count">
                      <StatusIcon level={a.resolvedAt ? 'ok' : a.severity} size={14} />
                      {a.resolvedAt ? 'Resolved' : <StatusLabel level={a.severity} />}
                    </span>
                  </td>
                  <td>
                    <b>{areaOf(a)}</b>: {a.title}
                    <Refs refs={a.refs} />
                    {a.detail && <div className="muted small">{a.detail}</div>}
                  </td>
                  <td>{a.domain ?? '–'}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{dateTime(a.startedAt)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {duration(a.startedAt, a.resolvedAt)}
                    {!a.resolvedAt && <span className="muted"> (ongoing)</span>}
                  </td>
                  <td>
                    {a.notified ? 'sent' : <span className="muted">{a.silenced ? 'not sent' : '–'}</span>}
                    <div>
                      <AlertTaken a={a} />
                    </div>
                  </td>
                  <td>
                    <AlertActions a={a} onDone={onChanged} />
                  </td>
                </tr>
              ))}
              {!alerts.loading && rows.length === 0 && (
                <tr>
                  <td colSpan={7} className="empty">
                    {range === 'active' ? 'No active alerts.' : 'No alerts in this period.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
