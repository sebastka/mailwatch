import { useEffect, useRef } from 'react';
import { RESULT_TYPES } from '../../shared/result-types.ts';
import { api } from '../api.ts';
import { dateTime, num } from '../format.ts';
import { useAsync } from '../hooks.ts';
import { CodeView } from './CodeView.tsx';
import { FailCount } from './ui.tsx';

export function TlsReportDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { data: r, error } = useAsync(() => api.tlsReport(id), [id]);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="Report details">
        <div className="card-head">
          <h2>{r ? `${r.org} · ${r.start.slice(0, 10)}` : 'Report'}</h2>
          <button ref={closeRef} type="button" className="btn" onClick={onClose}>
            Close
          </button>
        </div>
        {error && <p>Could not load report: {error}</p>}
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
              <dd>{r.contactInfo ?? '–'}</dd>
              <dt>Received</dt>
              <dd>{dateTime(r.receivedAt)}</dd>
              <dt>Sessions</dt>
              <dd>
                {num(r.sessions)} total, <FailCount n={r.failed} /> failed
              </dd>
              <dt>Email</dt>
              <dd>
                {r.source.from ?? '–'}
                {r.source.subject && <div className="muted">{r.source.subject}</div>}
              </dd>
              <dt>Attachment</dt>
              <dd className="mono">{r.source.filename ?? '–'}</dd>
              <dt>Mailbox</dt>
              <dd className="mono">{r.source.mailbox ?? '–'}</dd>
            </dl>

            <h3>Policies</h3>
            {r.policies.map((p, i) => (
              <div className="policy-block" key={i}>
                <div>
                  <span className="tag">{p.type}</span>
                  <b>{p.domain}</b>
                  {p.mode && <span className="muted"> · mode: {p.mode}</span>}
                </div>
                <div className="muted" style={{ marginTop: 4 }}>
                  {num(p.successful)} successful, {num(p.failed)} failed
                  {p.mxHosts.length > 0 && <> · MX: {p.mxHosts.join(', ')}</>}
                </div>
                {p.policyString.length > 0 && <pre style={{ marginTop: 8 }}>{p.policyString.join('\n')}</pre>}
                {p.failures.length > 0 && (
                  <div className="table-wrap" style={{ marginTop: 8 }}>
                    <table>
                      <thead>
                        <tr>
                          <th>Result</th>
                          <th>Sending MTA</th>
                          <th>Receiving MX / IP</th>
                          <th className="num">Sessions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {p.failures.map((f, j) => (
                          <tr key={j}>
                            <td title={RESULT_TYPES[f.resultType]}>
                              {f.resultType}
                              {f.failureReasonCode && <div className="muted">{f.failureReasonCode}</div>}
                              {f.additionalInformation && <div className="muted">{f.additionalInformation}</div>}
                            </td>
                            <td className="mono">{f.sendingMtaIp ?? '–'}</td>
                            <td className="mono">
                              {f.receivingMxHostname ?? '–'}
                              {f.receivingMxHelo && <div className="muted">HELO {f.receivingMxHelo}</div>}
                              <div className="muted">{f.receivingIp ?? ''}</div>
                            </td>
                            <td className="num">{num(f.failedSessionCount)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ))}

            <h3>Raw report (JSON)</h3>
            <CodeView value={r.raw} format="json" label="Raw report as JSON" />

            <h3>
              As YAML <span className="muted h3-note">for easier reading; generated in the browser, not stored</span>
            </h3>
            <CodeView value={r.raw} format="yaml" label="Report as YAML" />
          </>
        )}
      </aside>
    </>
  );
}
