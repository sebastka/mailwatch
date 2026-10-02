// DMARC aggregate (rua) and failure (ruf) report analysis.
import { useState } from 'react';
import type { DmarcOverview, DmarcReportSummary, DmarcSourceStat } from '../../shared/types.ts';
import { TAB_SPECS } from '../../shared/rfcs.ts';
import { api } from '../api.ts';
import { ReportFilterBar } from '../components/ReportFilters.tsx';
import { useReportFilters } from '../report-filters.ts';
import { StackedChart } from '../components/StackedChart.tsx';
import { Card, ChartCard, Drawer, ErrorBanner, FailCount, Insights, SpecPanel, StatusPill } from '../components/ui.tsx';
import { compact, dateTime, day, num, percent, shortDay } from '../format.ts';
import { useAsync } from '../hooks.ts';

const PAGE = 25;

function Pager({ page, pages, onPage }: { page: number; pages: number; onPage: (p: number) => void }) {
  if (pages <= 1) return null;
  return (
    <div className="pager">
      <button type="button" className="btn" disabled={page === 0} onClick={() => onPage(page - 1)}>
        Previous
      </button>
      <span>
        Page {page + 1} of {pages}
      </span>
      <button type="button" className="btn" disabled={page >= pages - 1} onClick={() => onPage(page + 1)}>
        Next
      </button>
    </div>
  );
}

const result = (r: string) => <StatusPill level={r === 'pass' ? 'ok' : r === 'none' ? 'info' : 'error'} text={r} />;

function SourceTable({ rows, ip, onIp }: { rows: DmarcSourceStat[]; ip: string; onIp: (ip: string) => void }) {
  const [page, setPage] = useState(0);
  const shown = ip ? rows.filter((r) => r.ip === ip) : rows;
  const pages = Math.max(1, Math.ceil(shown.length / PAGE));
  const p = Math.min(page, pages - 1);
  return (
    <>
      {ip && (
        <p className="small">
          Showing {ip} only ·{' '}
          <button type="button" className="btn-link" onClick={() => onIp('')}>
            show all sources
          </button>
        </p>
      )}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Source</th>
              <th className="num">Messages</th>
              <th className="num">Failed DMARC</th>
              <th className="num">SPF aligned</th>
              <th className="num">DKIM aligned</th>
              <th>From domains</th>
              <th>DKIM signatures</th>
              <th>Reporters</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {shown.slice(p * PAGE, (p + 1) * PAGE).map((s) => (
              <tr key={s.ip}>
                <td className="mono">
                  {s.ip}
                  {s.ptr && <div className="muted">{s.ptr}</div>}
                </td>
                <td className="num">{num(s.messages)}</td>
                <td className="num">
                  <FailCount n={s.failed} />
                </td>
                <td className="num">{percent(s.messages ? s.spfAligned / s.messages : null)}</td>
                <td className="num">{percent(s.messages ? s.dkimAligned / s.messages : null)}</td>
                <td>{s.headerFrom.join(', ')}</td>
                <td className="small">{s.dkimDomains.join(', ') || <span className="muted">none</span>}</td>
                <td className="small">{s.reporters.join(', ')}</td>
                <td>{shortDay(s.lastSeen)}</td>
              </tr>
            ))}
            {shown.length === 0 && (
              <tr>
                <td colSpan={9} className="empty">
                  No sources in this range
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <Pager page={p} pages={pages} onPage={setPage} />
    </>
  );
}

function ReportTable({ rows, onOpen }: { rows: DmarcReportSummary[]; onOpen: (id: number) => void }) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const p = Math.min(page, pages - 1);
  return (
    <>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Period</th>
              <th>Reporter</th>
              <th>Domain</th>
              <th className="num">Messages</th>
              <th className="num">Failed</th>
              <th>Received</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(p * PAGE, (p + 1) * PAGE).map((r) => (
              <tr
                key={r.id}
                className="clickable"
                tabIndex={0}
                onClick={() => onOpen(r.id)}
                onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), onOpen(r.id))}
              >
                <td style={{ whiteSpace: 'nowrap' }}>{day(r.start)}</td>
                <td>{r.org}</td>
                <td>{r.domain}</td>
                <td className="num">{num(r.messages)}</td>
                <td className="num">
                  <FailCount n={r.failed} />
                </td>
                <td className="muted" style={{ whiteSpace: 'nowrap' }}>
                  {dateTime(r.receivedAt)}
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="empty">
                  No reports in this range
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <Pager page={p} pages={pages} onPage={setPage} />
    </>
  );
}

function ReportDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { data: r, error } = useAsync(() => api.dmarcReport(id), [id]);
  return (
    <Drawer title={r ? `${r.org} · ${r.domain} · ${r.start.slice(0, 10)}` : 'DMARC report'} onClose={onClose}>
      {error && <p>Could not load the report: {error}</p>}
      {r && (
        <>
          <dl className="kv">
            <dt>Report ID</dt>
            <dd className="mono">{r.reportId}</dd>
            <dt>Period</dt>
            <dd>
              {dateTime(r.start)} – {dateTime(r.end)}
            </dd>
            <dt>Contact</dt>
            <dd>{[r.email, r.extraContact].filter(Boolean).join(' · ') || '–'}</dd>
            <dt>Published policy</dt>
            <dd className="mono">
              p={r.policy.p ?? '?'}
              {r.policy.sp && ` sp=${r.policy.sp}`}
              {r.policy.np && ` np=${r.policy.np}`}
              {r.policy.pct !== null && ` pct=${r.policy.pct}`} adkim={r.policy.adkim ?? 'r'} aspf=
              {r.policy.aspf ?? 'r'}
            </dd>
            <dt>Messages</dt>
            <dd>
              {num(r.messages)}, <FailCount n={r.failed} /> failed DMARC
            </dd>
            <dt>Email</dt>
            <dd>
              {r.source.from ?? '–'}
              {r.source.subject && <div className="muted">{r.source.subject}</div>}
            </dd>
            <dt>Attachment</dt>
            <dd className="mono">{r.source.filename ?? '–'}</dd>
            {r.errors.length > 0 && (
              <>
                <dt>Reporter errors</dt>
                <dd>{r.errors.join('; ')}</dd>
              </>
            )}
          </dl>
          <h3>Records</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th className="num">Count</th>
                  <th>Disposition</th>
                  <th>DKIM / SPF (aligned)</th>
                  <th>Identifiers</th>
                  <th>Auth results</th>
                </tr>
              </thead>
              <tbody>
                {r.records.map((x, i) => (
                  <tr key={i}>
                    <td className="mono">{x.sourceIp}</td>
                    <td className="num">{num(x.count)}</td>
                    <td>
                      {x.disposition}
                      {x.reasons.map((re, j) => (
                        <div key={j} className="muted small">
                          {re.type}
                          {re.comment ? `: ${re.comment}` : ''}
                        </div>
                      ))}
                    </td>
                    <td>
                      {result(x.dkim)} {result(x.spf)}
                    </td>
                    <td className="small">
                      From: {x.headerFrom}
                      {x.envelopeFrom && <div>MAIL FROM: {x.envelopeFrom}</div>}
                      {x.envelopeTo && <div>To: {x.envelopeTo}</div>}
                    </td>
                    <td className="small mono">
                      {x.dkimResults.map((k, j) => (
                        <div key={`d${j}`}>
                          dkim {k.domain}
                          {k.selector ? ` (${k.selector})` : ''}: {k.result}
                        </div>
                      ))}
                      {x.spfResults.map((k, j) => (
                        <div key={`s${j}`}>
                          spf {k.domain}
                          {k.scope ? ` (${k.scope})` : ''}: {k.result}
                        </div>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <h3>Raw report (XML)</h3>
          <pre className="code">{r.raw}</pre>
        </>
      )}
    </Drawer>
  );
}

function FailureDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { data: r, error } = useAsync(() => api.failure(id), [id]);
  return (
    <Drawer title={r ? `Failure report · ${r.reportedDomain ?? '?'}` : 'Failure report'} onClose={onClose}>
      {error && <p>Could not load the report: {error}</p>}
      {r && (
        <>
          <dl className="kv">
            {r.fields.map(([k, v], i) => (
              <div key={i} style={{ display: 'contents' }}>
                <dt>{k}</dt>
                <dd className="mono">{v}</dd>
              </div>
            ))}
            <dt>Reported by</dt>
            <dd>{r.reporter ?? '–'}</dd>
            <dt>Received</dt>
            <dd>{dateTime(r.receivedAt)}</dd>
          </dl>
          <h3>
            Headers of the original message <span className="muted h3-note">bodies are never stored</span>
          </h3>
          <pre className="code">{r.headers ?? '(not included in the report)'}</pre>
        </>
      )}
    </Drawer>
  );
}

function Aggregate({
  o,
  ip,
  setIp,
  onDomain,
  onOrg,
}: {
  o: DmarcOverview;
  ip: string;
  setIp: (ip: string) => void;
  onDomain: (d: string) => void;
  onOrg: (o: string) => void;
}) {
  return (
    <>
      <div className="grid kpis">
        <div className="card stat hero">
          <div className="label">DMARC pass rate</div>
          <div className="value">{percent(o.kpis.passRate)}</div>
          {o.kpis.messages > 0 && (
            <div className="meter" aria-hidden="true">
              <span style={{ width: `${(o.kpis.passed / o.kpis.messages) * 100}%`, background: 'var(--series-1)' }} />
              {o.kpis.failed > 0 && (
                <span style={{ width: `${(o.kpis.failed / o.kpis.messages) * 100}%`, background: 'var(--series-2)' }} />
              )}
            </div>
          )}
          <div className="foot">
            {o.range.from ? `${shortDay(o.range.from)} – ${shortDay(o.range.to!)}` : 'No data'}
          </div>
        </div>
        <div className="card stat">
          <div className="label">Messages</div>
          <div className="value">{compact(o.kpis.messages)}</div>
          <div className="foot">{num(o.kpis.passed)} passed</div>
        </div>
        <div className="card stat">
          <div className="label">Failed DMARC</div>
          <div className="value">{compact(o.kpis.failed)}</div>
          <div className="foot">
            {num(o.kpis.quarantined)} quarantined, {num(o.kpis.rejected)} rejected
          </div>
        </div>
        <div className="card stat">
          <div className="label">Sources</div>
          <div className="value">{compact(o.kpis.sources)}</div>
          <div className="foot">
            {o.kpis.reports} reports from {o.kpis.reporters} reporter{o.kpis.reporters === 1 ? '' : 's'}
          </div>
        </div>
      </div>

      <Insights
        items={o.insights}
        onPick={(s) => (s.kind === 'ip' ? setIp(s.value) : s.kind === 'domain' ? onDomain(s.value) : onOrg(s.value))}
      />

      <ChartCard
        title={`Messages per ${o.bucket}`}
        desc="By report start date (UTC); a message passes DMARC with aligned SPF or aligned DKIM"
        chart={
          <StackedChart
            data={o.series}
            bucket={o.bucket}
            what="Messages"
            rateLabel="Pass rate"
            series={[
              { key: 'passed', label: 'Passed DMARC', color: 'var(--series-1)' },
              { key: 'failed', label: 'Failed DMARC', color: 'var(--series-2)' },
            ]}
          />
        }
        table={
          <table>
            <thead>
              <tr>
                <th>{o.bucket === 'week' ? 'Week of' : 'Day'}</th>
                <th className="num">Reports</th>
                <th className="num">Passed</th>
                <th className="num">Failed</th>
                <th className="num">Pass rate</th>
              </tr>
            </thead>
            <tbody>
              {o.series
                .filter((d) => d.reports > 0)
                .map((d) => (
                  <tr key={d.start}>
                    <td>{d.start}</td>
                    <td className="num">{num(d.reports)}</td>
                    <td className="num">{num(d.passed)}</td>
                    <td className="num">
                      <FailCount n={d.failed} />
                    </td>
                    <td className="num">{percent(d.passed + d.failed ? d.passed / (d.passed + d.failed) : null)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        }
      />

      <div className="section">
        <Card
          title="Sending sources"
          desc="Every IP address that sent mail as your domains, busiest first, with its reverse DNS name"
        >
          <SourceTable rows={o.bySource} ip={ip} onIp={setIp} />
        </Card>
      </div>

      <div className="grid two-even section">
        <Card title="Domains" desc="Policy from the latest report">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Policy</th>
                  <th className="num">Messages</th>
                  <th className="num">Failed</th>
                </tr>
              </thead>
              <tbody>
                {o.byDomain.map((d) => (
                  <tr key={d.domain}>
                    <td>{d.domain}</td>
                    <td className="mono">
                      p={d.policy?.p ?? '?'}
                      {d.policy?.pct !== null && d.policy?.pct !== undefined && d.policy.pct !== 100
                        ? ` pct=${d.policy.pct}`
                        : ''}
                    </td>
                    <td className="num">{num(d.messages)}</td>
                    <td className="num">
                      <FailCount n={d.failed} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title="Reporters" desc="Organisations that sent reports">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Reporter</th>
                  <th className="num">Reports</th>
                  <th className="num">Messages</th>
                  <th className="num">Failed</th>
                  <th>Last report</th>
                </tr>
              </thead>
              <tbody>
                {o.byOrg.map((r) => (
                  <tr key={r.org}>
                    <td>{r.org}</td>
                    <td className="num">{num(r.reports)}</td>
                    <td className="num">{num(r.messages)}</td>
                    <td className="num">
                      <FailCount n={r.failed} />
                    </td>
                    <td>{shortDay(r.lastReportEnd)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      {o.selectors.length > 0 && (
        <div className="section">
          <Card
            title="DKIM selectors seen"
            desc="Signatures in the reports, by signing domain and selector. These are also checked on the DKIM tab."
          >
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Selector</th>
                    <th className="num">Pass</th>
                    <th className="num">Fail</th>
                  </tr>
                </thead>
                <tbody>
                  {o.selectors.map((s) => (
                    <tr key={`${s.domain}-${s.selector}`}>
                      <td>{s.domain}</td>
                      <td className="mono">{s.selector}</td>
                      <td className="num">{num(s.pass)}</td>
                      <td className="num">
                        <FailCount n={s.fail} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}
    </>
  );
}

export function DmarcReportsView({
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
  const [ip, setIp] = useState('');
  const [open, setOpen] = useState<number | null>(null);
  const [openFailure, setOpenFailure] = useState<number | null>(null);
  const options = useAsync(() => api.dmarcFilters(), [version]);
  const overview = useAsync(() => api.dmarcOverview(filters), [key, version]);
  const reports = useAsync(() => api.dmarcReports(filters), [key, version]);
  const failures = useAsync(() => api.failures(filters), [key, version]);
  const o = overview.data;

  return (
    <>
      <p className="desc" style={{ marginTop: 0 }}>
        Aggregate reports (rua) tell you which servers send mail as your domains and whether it passes DMARC. Failure
        reports (ruf) describe single failing messages; few providers send them.
      </p>
      <SpecPanel
        docs={TAB_SPECS['dmarc-reports']}
        findings={(o?.insights ?? []).map((i, n) => ({
          code: `insight-${n}`,
          level: i.level,
          title: i.title,
          detail: i.detail,
          refs: i.refs ?? [],
        }))}
      />
      <ReportFilterBar state={state} update={update} options={options.data} />
      {overview.error && <ErrorBanner>Could not load the DMARC reports: {overview.error}</ErrorBanner>}
      {o && (
        <div style={{ opacity: overview.loading ? 0.55 : 1, transition: 'opacity .15s' }}>
          <Aggregate o={o} ip={ip} setIp={setIp} onDomain={onDomain} onOrg={(org) => update({ org })} />
        </div>
      )}
      <div className="section">
        <Card title="Aggregate reports" desc="Click a report to see its records and the raw XML">
          {reports.data && <ReportTable key={key} rows={reports.data} onOpen={setOpen} />}
        </Card>
      </div>
      <div className="section">
        <Card title="Failure reports" desc="Auth-failure reports (RFC 6591): report fields and the original headers">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Received</th>
                  <th>Domain</th>
                  <th>Failure</th>
                  <th>Source IP</th>
                  <th>From / subject</th>
                  <th>Reporter</th>
                </tr>
              </thead>
              <tbody>
                {(failures.data ?? []).map((f) => (
                  <tr
                    key={f.id}
                    className="clickable"
                    tabIndex={0}
                    onClick={() => setOpenFailure(f.id)}
                    onKeyDown={(e) => e.key === 'Enter' && setOpenFailure(f.id)}
                  >
                    <td style={{ whiteSpace: 'nowrap' }}>{dateTime(f.receivedAt)}</td>
                    <td>{f.reportedDomain ?? '–'}</td>
                    <td>
                      {f.authFailure ?? '–'}
                      {f.deliveryResult && <div className="muted small">{f.deliveryResult}</div>}
                    </td>
                    <td className="mono">{f.sourceIp ?? '–'}</td>
                    <td className="small">
                      {f.headerFrom ?? '–'}
                      {f.subject && <div className="muted">{f.subject}</div>}
                    </td>
                    <td className="small">{f.reporter ?? '–'}</td>
                  </tr>
                ))}
                {failures.data && failures.data.length === 0 && (
                  <tr>
                    <td colSpan={6} className="empty">
                      No failure reports in this range
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
      {open !== null && <ReportDrawer id={open} onClose={() => setOpen(null)} />}
      {openFailure !== null && <FailureDrawer id={openFailure} onClose={() => setOpenFailure(null)} />}
    </>
  );
}
