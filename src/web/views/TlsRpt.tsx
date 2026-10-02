// The TLS-RPT tab: the _smtp._tls record check, then the analysis of the TLS reports received
// (the tlsrpt dashboard).
import { useState } from 'react';
import { RESULT_TYPES } from '../../shared/result-types.ts';
import { api } from '../api.ts';
import { BarList } from '../components/BarList.tsx';
import { ReportFilterBar } from '../components/ReportFilters.tsx';
import { useReportFilters } from '../report-filters.ts';
import { StackedChart } from '../components/StackedChart.tsx';
import { FailureTable, OrgTable, PolicyTable, TlsReportTable, TlsSeriesTable } from '../components/TlsTables.tsx';
import { TlsReportDrawer } from '../components/TlsReportDrawer.tsx';
import { Card, ChartCard, ErrorBanner, Insights } from '../components/ui.tsx';
import { compact, num, percent, shortDay } from '../format.ts';
import { useAsync } from '../hooks.ts';
import { CheckView } from './CheckView.tsx';

export function TlsReportsSection({
  domain,
  version,
  onDomain,
}: {
  domain: string;
  version: number;
  onDomain: (d: string) => void;
}) {
  const { state, update, filters } = useReportFilters(domain);
  const key = JSON.stringify(filters);
  const [open, setOpen] = useState<number | null>(null);
  const options = useAsync(() => api.tlsFilters(), [version]);
  const overview = useAsync(() => api.tlsOverview(filters), [key, version]);
  const reports = useAsync(() => api.tlsReports(filters), [key, version]);
  const o = overview.data;

  return (
    <>
      <h2 className="section-title">TLS reports received</h2>
      <ReportFilterBar state={state} update={update} options={options.data} />
      {overview.error && <ErrorBanner>Could not load the TLS reports: {overview.error}</ErrorBanner>}
      {o && (
        <div style={{ opacity: overview.loading ? 0.55 : 1, transition: 'opacity .15s' }}>
          <div className="grid kpis">
            <div className="card stat hero">
              <div className="label">TLS success rate</div>
              <div className="value">{percent(o.kpis.successRate)}</div>
              {o.kpis.sessions > 0 && (
                <div className="meter" aria-hidden="true">
                  <span
                    style={{ width: `${(o.kpis.successful / o.kpis.sessions) * 100}%`, background: 'var(--series-1)' }}
                  />
                  {o.kpis.failed > 0 && (
                    <span
                      style={{ width: `${(o.kpis.failed / o.kpis.sessions) * 100}%`, background: 'var(--series-2)' }}
                    />
                  )}
                </div>
              )}
              <div className="foot">
                {o.range.from ? `${shortDay(o.range.from)} – ${shortDay(o.range.to!)}` : 'No data'}
              </div>
            </div>
            <div className="card stat">
              <div className="label">Sessions</div>
              <div className="value">{compact(o.kpis.sessions)}</div>
              <div className="foot">{num(o.kpis.successful)} successful</div>
            </div>
            <div className="card stat">
              <div className="label">Failed sessions</div>
              <div className="value">{compact(o.kpis.failed)}</div>
              <div className="foot">
                {o.failureTypes.length} failure type{o.failureTypes.length === 1 ? '' : 's'}
              </div>
            </div>
            <div className="card stat">
              <div className="label">Reports</div>
              <div className="value">{compact(o.kpis.reports)}</div>
              <div className="foot">
                from {o.kpis.reporters} reporter{o.kpis.reporters === 1 ? '' : 's'}
              </div>
            </div>
          </div>

          <Insights
            items={o.insights}
            onPick={(s) =>
              s.kind === 'domain' ? onDomain(s.value) : s.kind === 'org' ? update({ org: s.value }) : undefined
            }
          />

          <div className="grid two">
            <ChartCard
              title={`Sessions per ${o.bucket}`}
              desc="Deduplicated across policies, by report start date (UTC)"
              chart={
                <StackedChart
                  data={o.series}
                  bucket={o.bucket}
                  what="Sessions"
                  rateLabel="Success rate"
                  series={[
                    { key: 'successful', label: 'Successful sessions', color: 'var(--series-1)' },
                    { key: 'failed', label: 'Failed sessions', color: 'var(--series-2)' },
                  ]}
                />
              }
              table={<TlsSeriesTable data={o.series} bucket={o.bucket} />}
            />
            <ChartCard
              title="Failures by result type"
              desc="Failed sessions, as reported in failure details"
              chart={
                o.failureTypes.length ? (
                  <BarList
                    unit="sessions"
                    items={o.failureTypes.map((f) => ({
                      key: f.resultType,
                      label: f.resultType,
                      value: f.sessions,
                      note: `${RESULT_TYPES[f.resultType] ?? 'Unknown result type.'} Seen in ${f.reports} report${f.reports === 1 ? '' : 's'}.`,
                    }))}
                  />
                ) : (
                  <div className="empty">No failures reported in this range.</div>
                )
              }
              table={
                <table>
                  <thead>
                    <tr>
                      <th>Result type</th>
                      <th className="num">Sessions</th>
                      <th className="num">Reports</th>
                    </tr>
                  </thead>
                  <tbody>
                    {o.failureTypes.map((f) => (
                      <tr key={f.resultType}>
                        <td title={RESULT_TYPES[f.resultType]}>{f.resultType}</td>
                        <td className="num">{num(f.sessions)}</td>
                        <td className="num">{num(f.reports)}</td>
                      </tr>
                    ))}
                    {o.failureTypes.length === 0 && (
                      <tr>
                        <td colSpan={3} className="empty">
                          No failures reported in this range.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              }
            />
          </div>

          <div className="section">
            <Card title="Reporters" desc="Organisations that sent reports">
              <div className="table-wrap">
                <OrgTable rows={o.byOrg} />
              </div>
            </Card>
          </div>
          <div className="section">
            <Card
              title="Policies"
              desc="Policies reporters applied, per domain. Mode and MX come from the latest report."
            >
              <div className="table-wrap">
                <PolicyTable rows={o.byPolicy} />
              </div>
            </Card>
          </div>
          {o.failureDetails.length > 0 && (
            <div className="section">
              <Card
                title="Failure details"
                desc="Grouped by domain, policy, result type, receiving MX/IP and sending MTA"
              >
                <div className="table-wrap">
                  <FailureTable rows={o.failureDetails} />
                </div>
              </Card>
            </div>
          )}
        </div>
      )}
      <div className="section" style={{ opacity: reports.loading && reports.data ? 0.55 : 1 }}>
        <Card title="Reports" desc="Click a report to see its policies, failures and raw JSON">
          {reports.data && <TlsReportTable key={key} rows={reports.data} onOpen={setOpen} />}
        </Card>
      </div>
      {open !== null && <TlsReportDrawer id={open} onClose={() => setOpen(null)} />}
    </>
  );
}

export function TlsRptView({
  domain,
  version,
  onDomain,
}: {
  domain: string;
  version: number;
  onDomain: (d: string) => void;
}) {
  return (
    <CheckView check="tls-rpt" domain={domain} version={version}>
      <TlsReportsSection domain={domain} version={version} onDomain={onDomain} />
    </CheckView>
  );
}
