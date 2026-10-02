import { useState } from 'react';
import type { FailureDetailStat, OrgStat, PolicyStat, TimeBucket, TlsReportSummary } from '../../shared/types.ts';
import { RESULT_TYPES } from '../../shared/result-types.ts';
import { dateTime, day, num, percent, shortDay } from '../format.ts';
import { FailCount } from './ui.tsx';

const rate = (sessions: number, failed: number) => percent(sessions ? (sessions - failed) / sessions : null);

export function TlsSeriesTable({ data, bucket }: { data: TimeBucket[]; bucket: 'day' | 'week' }) {
  const rows = data.filter((d) => d.reports > 0);
  return (
    <table>
      <thead>
        <tr>
          <th>{bucket === 'week' ? 'Week of' : 'Day'}</th>
          <th className="num">Reports</th>
          <th className="num">Successful</th>
          <th className="num">Failed</th>
          <th className="num">Success rate</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((d) => (
          <tr key={d.start}>
            <td>{d.start}</td>
            <td className="num">{num(d.reports)}</td>
            <td className="num">{num(d.successful)}</td>
            <td className="num">
              <FailCount n={d.failed} />
            </td>
            <td className="num">{rate(d.successful + d.failed, d.failed)}</td>
          </tr>
        ))}
        {rows.length === 0 && (
          <tr>
            <td colSpan={5} className="empty">
              No reports in this range
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}

export function OrgTable({ rows }: { rows: OrgStat[] }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Reporter</th>
          <th className="num">Reports</th>
          <th className="num">Sessions</th>
          <th className="num">Failed</th>
          <th className="num">Success rate</th>
          <th>Last report</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((o) => (
          <tr key={o.org}>
            <td>{o.org}</td>
            <td className="num">{num(o.reports)}</td>
            <td className="num">{num(o.sessions)}</td>
            <td className="num">
              <FailCount n={o.failed} />
            </td>
            <td className="num">{rate(o.sessions, o.failed)}</td>
            <td>{shortDay(o.lastReportEnd)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function PolicyTable({ rows }: { rows: PolicyStat[] }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Domain</th>
          <th>Policy</th>
          <th>Mode</th>
          <th>MX</th>
          <th className="num">Reports</th>
          <th className="num">Successful</th>
          <th className="num">Failed</th>
          <th>Last seen</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((p) => (
          <tr key={`${p.domain}-${p.type}`}>
            <td>{p.domain}</td>
            <td>
              <span className="tag" title={p.latestPolicyString.join('\n')}>
                {p.type === 'sts' ? 'MTA-STS' : p.type === 'tlsa' ? 'DANE (TLSA)' : p.type}
              </span>
            </td>
            <td>{p.latestMode ?? <span className="muted">–</span>}</td>
            <td className="mono">{p.latestMxHosts.join(', ') || <span className="muted">–</span>}</td>
            <td className="num">{num(p.reports)}</td>
            <td className="num">{num(p.successful)}</td>
            <td className="num">
              <FailCount n={p.failed} />
            </td>
            <td>{shortDay(p.lastSeen)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function FailureTable({ rows }: { rows: FailureDetailStat[] }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Result</th>
          <th>Domain / policy</th>
          <th>Receiving MX</th>
          <th>Receiving IP</th>
          <th>Sending MTA</th>
          <th className="num">Sessions</th>
          <th>Reporters</th>
          <th>Seen</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((f, i) => (
          <tr key={i}>
            <td title={RESULT_TYPES[f.resultType]}>
              <b>{f.resultType}</b>
              {f.failureReasonCode && <div className="muted">{f.failureReasonCode}</div>}
              {f.additionalInformation && (
                <div className="muted" style={{ overflowWrap: 'anywhere' }}>
                  {f.additionalInformation}
                </div>
              )}
            </td>
            <td>
              {f.domain} <span className="tag">{f.policyType}</span>
            </td>
            <td className="mono">
              {f.receivingMxHostname ?? '–'}
              {f.receivingMxHelo && <div className="muted">HELO {f.receivingMxHelo}</div>}
            </td>
            <td className="mono">{f.receivingIp ?? '–'}</td>
            <td className="mono">{f.sendingMtaIp ?? '–'}</td>
            <td className="num">{num(f.sessions)}</td>
            <td>{f.reporters.join(', ')}</td>
            <td style={{ whiteSpace: 'nowrap' }}>
              {day(f.firstSeen) === day(f.lastSeen)
                ? shortDay(f.lastSeen)
                : `${shortDay(f.firstSeen)} – ${shortDay(f.lastSeen)}`}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const PAGE = 25;

export function TlsReportTable({ rows, onOpen }: { rows: TlsReportSummary[]; onOpen: (id: number) => void }) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const p = Math.min(page, pages - 1);
  const slice = rows.slice(p * PAGE, (p + 1) * PAGE);
  return (
    <>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Period</th>
              <th>Reporter</th>
              <th>Domains</th>
              <th>Policies</th>
              <th className="num">Sessions</th>
              <th className="num">Failed</th>
              <th>Received</th>
            </tr>
          </thead>
          <tbody>
            {slice.map((r) => (
              <tr
                key={r.id}
                className="clickable"
                tabIndex={0}
                onClick={() => onOpen(r.id)}
                onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), onOpen(r.id))}
              >
                <td style={{ whiteSpace: 'nowrap' }}>{day(r.start)}</td>
                <td>{r.org}</td>
                <td>{r.domains.join(', ')}</td>
                <td>
                  {r.policyTypes.map((t) => (
                    <span className="tag" key={t}>
                      {t}
                    </span>
                  ))}
                </td>
                <td className="num">{num(r.sessions)}</td>
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
                <td colSpan={7} className="empty">
                  No reports in this range
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {pages > 1 && (
        <div className="pager">
          <button type="button" className="btn" disabled={p === 0} onClick={() => setPage(p - 1)}>
            Previous
          </button>
          <span>
            Page {p + 1} of {pages}
          </span>
          <button type="button" className="btn" disabled={p >= pages - 1} onClick={() => setPage(p + 1)}>
            Next
          </button>
        </div>
      )}
    </>
  );
}
