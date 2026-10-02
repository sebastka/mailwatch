import type { Alert, CheckKind, DomainOverview, Level } from '../../shared/types.ts';
import { alertPath, areaOf, CHECK_LABEL } from '../../shared/paths.ts';
import { api } from '../api.ts';
import { ChangeList } from '../components/Changes.tsx';
import { Card, ErrorBanner, StatusIcon, StatusLabel } from '../components/ui.tsx';
import { LEVEL_ORDER } from '../levels.ts';
import { ago, dateTime, plural } from '../format.ts';
import { useAsync } from '../hooks.ts';

const CHECKS: CheckKind[] = [
  'domain',
  'mx',
  'spf',
  'dkim',
  'dmarc',
  'mta-sts',
  'tls-rpt',
  'dane',
  'bimi',
  'dnsbl',
  'senders',
];

function cellText(c: DomainOverview['checks'][number]): string {
  if (c.level === 'error') return `${c.counts.error}`;
  if (c.level === 'warning') return `${c.counts.warning}`;
  return c.level === 'info' ? 'Info' : 'OK';
}

export function OverviewView({
  overview,
  alerts,
  domain,
  version,
  onOpen,
}: {
  overview: DomainOverview[] | null;
  alerts: Alert[];
  domain: string;
  version: number;
  onOpen: (path: string, domain?: string) => void;
}) {
  const changes = useAsync(() => api.changes({ limit: 15, ...(domain ? { domain } : {}) }), [domain, version]);
  const rows = (overview ?? []).filter((d) => !domain || d.name === domain);
  const shown = alerts.filter((a) => !domain || a.domain === domain || a.domain === null);
  const counts = (l: Level) => rows.filter((d) => d.level === l).length;
  const lastCheck =
    rows
      .flatMap((d) => d.checks.map((c) => c.checkedAt))
      .sort()
      .at(-1) ?? null;

  return (
    <>
      <div className="grid kpis-4">
        <div className="card stat hero">
          <div className="label">Domains</div>
          <div className="value">{rows.length}</div>
          <div className="foot">
            {counts('error') > 0 && (
              <span className="status-pill">
                <StatusIcon level="error" size={12} /> {counts('error')} with errors
              </span>
            )}{' '}
            {counts('warning') > 0 && (
              <span className="status-pill">
                <StatusIcon level="warning" size={12} /> {counts('warning')} with warnings
              </span>
            )}
            {counts('error') + counts('warning') === 0 && rows.length > 0 && 'no warnings or errors'}
          </div>
        </div>
        <div className="card stat">
          <div className="label">Active alerts</div>
          <div className="value">{shown.length}</div>
          <div className="foot">
            {shown.filter((a) => a.severity === 'error').length} errors,{' '}
            {shown.filter((a) => a.severity === 'warning').length} warnings
          </div>
        </div>
        <div className="card stat">
          <div className="label">Senders</div>
          <div className="value">{rows.filter((d) => d.sender).length}</div>
          <div className="foot">domains sending delivery tests</div>
        </div>
        <div className="card stat">
          <div className="label">Last check</div>
          <div className="value" style={{ fontSize: 20 }}>
            {ago(lastCheck)}
          </div>
          <div className="foot">{dateTime(lastCheck)}</div>
        </div>
      </div>

      {!overview && <div className="muted">Loading…</div>}
      {overview && !overview.length && (
        <ErrorBanner>No domain is configured. Set DOMAIN_1_NAME etc. (see .env.example).</ErrorBanner>
      )}

      {rows.length > 0 && (
        <Card
          title="Domains"
          desc="Worst result of every check. Numbers count the errors or warnings; click a cell for the details."
        >
          <div className="table-wrap">
            <table className="matrix">
              <thead>
                <tr>
                  <th>Domain</th>
                  {CHECKS.map((c) => (
                    <th key={c} className="cell">
                      {CHECK_LABEL[c]}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((d) => (
                  <tr key={d.name}>
                    <td>
                      <span className="status-pill">
                        {d.level && <StatusIcon level={d.level} size={14} />}
                        <b>{d.name}</b>
                      </span>
                      {d.sender && (
                        <span className="tag" style={{ marginLeft: 6 }}>
                          sender
                        </span>
                      )}
                    </td>
                    {CHECKS.map((check) => {
                      const c = d.checks.find((x) => x.check === check);
                      return (
                        <td key={check} className="cell">
                          {c ? (
                            <a
                              href={`/${check}?domain=${encodeURIComponent(d.name)}`}
                              title={`${CHECK_LABEL[check]}: ${c.counts.error} errors, ${c.counts.warning} warnings, ${c.counts.info} notes · checked ${dateTime(c.checkedAt)}`}
                              onClick={(e) => {
                                e.preventDefault();
                                onOpen(`/${check}`, d.name);
                              }}
                            >
                              <StatusIcon level={c.level} size={14} />
                              {cellText(c)}
                            </a>
                          ) : (
                            <span className="muted">–</span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <div className="grid two-even section">
        <Card title="Active alerts" desc={shown.length ? 'Worst first' : undefined}>
          {shown.length === 0 ? (
            <div className="muted">No active alerts.</div>
          ) : (
            <ul className="findings">
              {[...shown]
                .sort(
                  (a, b) => LEVEL_ORDER[b.severity] - LEVEL_ORDER[a.severity] || b.startedAt.localeCompare(a.startedAt),
                )
                .slice(0, 12)
                .map((a) => (
                  <li key={a.id} className="finding">
                    <StatusIcon level={a.severity} />
                    <div>
                      <div className="t">
                        <a
                          href={alertPath(a)}
                          onClick={(e) => {
                            e.preventDefault();
                            onOpen(alertPath(a), a.domain ?? '');
                          }}
                        >
                          {areaOf(a)}: {a.title}
                        </a>
                        <StatusLabel level={a.severity} />
                      </div>
                      <div className="d">
                        {a.domain ?? 'MailWatch'} · since {dateTime(a.startedAt)}
                      </div>
                    </div>
                  </li>
                ))}
            </ul>
          )}
          {shown.length > 12 && (
            <p className="small">
              <a href="/alerts" onClick={(e) => (e.preventDefault(), onOpen('/alerts'))}>
                {plural(shown.length - 12, 'more alert')}
              </a>
            </p>
          )}
        </Card>
        <Card
          title="Recent record changes"
          desc="SPF, DKIM, DMARC, MTA-STS, TLS-RPT, MX, TLSA and BIMI records as seen by the checks"
        >
          {changes.data && <ChangeList changes={changes.data} showDomain={!domain} />}
        </Card>
      </div>
    </>
  );
}
