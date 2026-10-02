// End-to-end delivery tests: every sender domain to every recipient mailbox.
import { useState } from 'react';
import type { DeliveryPair, DeliveryProbe, Finding, Level, ProbeStatus, Status } from '../../shared/types.ts';
import { TAB_SPECS } from '../../shared/rfcs.ts';
import { api } from '../api.ts';
import { Card, Drawer, ErrorBanner, SpecPanel, StatusPill } from '../components/ui.tsx';
import { ago, dateTime, seconds } from '../format.ts';
import { useAsync } from '../hooks.ts';

const PAGE = 25;

const STATUS: Record<ProbeStatus, { level: Level; text: string }> = {
  sending: { level: 'info', text: 'sending' },
  sent: { level: 'info', text: 'waiting' },
  inbox: { level: 'ok', text: 'inbox' },
  spam: { level: 'warning', text: 'junk' },
  lost: { level: 'error', text: 'not delivered' },
  'send-failed': { level: 'error', text: 'send failed' },
};

const authLevel = (r: string | null): Level =>
  r === null ? 'info' : r === 'pass' ? 'ok' : r === 'none' || r === 'neutral' ? 'warning' : 'error';

function Auth({ p }: { p: DeliveryProbe }) {
  if (!p.auth) return <span className="muted">–</span>;
  return (
    <span className="small" style={{ display: 'inline-flex', gap: 8, flexWrap: 'wrap' }}>
      {(['spf', 'dkim', 'dmarc'] as const).map((k) => (
        <StatusPill key={k} level={authLevel(p.auth![k])} text={`${k} ${p.auth![k] ?? '?'}`} />
      ))}
    </span>
  );
}

/** Findings for the specification panel, from the latest result of every pair. */
function pairFindings(pairs: DeliveryPair[]): Finding[] {
  const out: Finding[] = [];
  for (const { latest: p } of pairs) {
    if (!p) continue;
    if (p.status === 'send-failed')
      out.push({ code: 'send', level: 'error', title: '', detail: '', refs: [{ doc: 'rfc5321' }] });
    if (p.status === 'spam')
      out.push({ code: 'spam', level: 'warning', title: '', detail: '', refs: [{ doc: 'rfc8601' }] });
    if (p.auth?.spf && p.auth.spf !== 'pass')
      out.push({ code: 'spf', level: 'warning', title: '', detail: '', refs: [{ doc: 'rfc7208' }] });
    if (p.auth?.dkim && p.auth.dkim !== 'pass')
      out.push({ code: 'dkim', level: 'warning', title: '', detail: '', refs: [{ doc: 'rfc6376' }] });
    if (p.auth?.dmarc && p.auth.dmarc !== 'pass')
      out.push({ code: 'dmarc', level: 'error', title: '', detail: '', refs: [{ doc: 'rfc7489' }] });
  }
  return out;
}

function ProbeDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { data: p, error } = useAsync(() => api.probe(id), [id]);
  return (
    <Drawer title={p ? `${p.sender} → ${p.recipient}` : 'Delivery test'} onClose={onClose}>
      {error && <p>Could not load the test: {error}</p>}
      {p && (
        <>
          <dl className="kv">
            <dt>Result</dt>
            <dd>
              <StatusPill level={STATUS[p.status].level} text={STATUS[p.status].text} />
              {p.error && <div className="muted">{p.error}</div>}
            </dd>
            <dt>Sent</dt>
            <dd>{dateTime(p.sentAt)}</dd>
            <dt>Submission answer</dt>
            <dd className="mono">{p.smtpResponse ?? '–'}</dd>
            <dt>Arrived</dt>
            <dd>
              {dateTime(p.receivedAt)}
              {p.latencySeconds !== null && <> · after {seconds(p.latencySeconds)}</>}
              {p.folder && <> · in {p.folder}</>}
            </dd>
            <dt>Authentication</dt>
            <dd>
              <Auth p={p} />
              {p.auth?.arc && <div className="small">arc {p.auth.arc}</div>}
              {p.auth?.compauth && <div className="small">compauth {p.auth.compauth}</div>}
              {p.auth?.scl !== null && p.auth?.scl !== undefined && (
                <div className="small">spam confidence level (SCL) {p.auth.scl}</div>
              )}
            </dd>
            <dt>Sending IP</dt>
            <dd className="mono">{p.clientIp ?? '–'}</dd>
            <dt>DKIM selectors</dt>
            <dd className="mono">{p.dkimSelectors.join(', ') || '–'}</dd>
            <dt>Token</dt>
            <dd className="mono">{p.token}</dd>
          </dl>
          <h3>
            Headers as received <span className="muted h3-note">as the recipient’s provider delivered them</span>
          </h3>
          <pre className="code">{p.headers ?? '(not arrived)'}</pre>
        </>
      )}
    </Drawer>
  );
}

export function DeliveryView({
  domain,
  version,
  status,
  canEdit,
  onChanged,
}: {
  domain: string;
  version: number;
  status: Status | null;
  canEdit: boolean;
  onChanged: () => void;
}) {
  const [days, setDays] = useState(7);
  const [open, setOpen] = useState<number | null>(null);
  const [page, setPage] = useState(0);
  const [msg, setMsg] = useState<string | null>(null);
  const data = useAsync(() => api.delivery(days), [days, version]);
  const pairs = (data.data?.pairs ?? []).filter((p) => !domain || p.sender === domain);
  const recent = (data.data?.recent ?? []).filter((p) => !domain || p.sender === domain);
  const senders = [...new Set(pairs.map((p) => p.sender))];
  const recipients = status?.recipients ?? [];
  const pages = Math.max(1, Math.ceil(recent.length / PAGE));
  const page0 = Math.min(page, pages - 1);
  const configured = (status?.domains.some((d) => d.sender) ?? false) && recipients.length > 0;

  const sendNow = () => {
    setMsg(null);
    api.runDelivery().then(
      () => {
        setMsg('Test messages are being sent; results appear as the recipients are searched.');
        onChanged();
      },
      (e: Error) => setMsg(e.message),
    );
  };

  return (
    <>
      <p className="desc" style={{ marginTop: 0 }}>
        Every sender domain sends a test message to every recipient mailbox on its interval. MailWatch then searches the
        Inbox and Junk folders: where did it land, how fast, and how did the provider authenticate it? Found messages
        are moved to the trash.
      </p>
      <SpecPanel docs={TAB_SPECS.delivery} findings={pairFindings(pairs)} />
      {!configured && status && (
        <ErrorBanner>
          No delivery tests are configured. Give a domain SMTP settings (DOMAIN_n_SMTPHOST, _SMTPUSER, _SMTPPASS) and
          add recipients (RECIPIENT_n_IMAPHOST, …); see .env.example.
        </ErrorBanner>
      )}
      <div className="filters">
        <div className="segmented" role="group" aria-label="Period">
          {[1, 7, 30, 90].map((d) => (
            <button key={d} type="button" aria-pressed={days === d} onClick={() => setDays(d)}>
              {d === 1 ? '24 hours' : `${d} days`}
            </button>
          ))}
        </div>
        {canEdit && configured && !status?.demo && (
          <button type="button" className="btn" onClick={sendNow} disabled={status?.delivery.running}>
            Send test messages now
          </button>
        )}
        {msg && <span className="muted small">{msg}</span>}
      </div>

      {senders.length > 0 && (
        <Card
          title="Senders × recipients"
          desc={`Latest result; counts over the last ${days === 1 ? '24 hours' : `${days} days`}. Timeout ${status?.delivery.timeoutMinutes ?? '?'} minutes.`}
        >
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Sender</th>
                  {recipients.map((r) => (
                    <th key={r.name}>{r.name}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {senders.map((s) => (
                  <tr key={s}>
                    <td>
                      <b>{s}</b>
                    </td>
                    {recipients.map((r) => {
                      const p = pairs.find((x) => x.sender === s && x.recipient === r.name);
                      const l = p?.latest;
                      return (
                        <td key={r.name}>
                          {l ? (
                            <button
                              type="button"
                              className="btn-link"
                              onClick={() => setOpen(l.id)}
                              style={{ textAlign: 'left' }}
                            >
                              <StatusPill level={STATUS[l.status].level} text={STATUS[l.status].text} />
                            </button>
                          ) : (
                            <span className="muted">nothing sent yet</span>
                          )}
                          {l && (
                            <div className="small muted">
                              {ago(l.sentAt)}
                              {l.latencySeconds !== null && ` · ${seconds(l.latencySeconds)}`}
                            </div>
                          )}
                          {l && (l.status === 'inbox' || l.status === 'spam') && (
                            <div>
                              <Auth p={l} />
                            </div>
                          )}
                          {p && p.sent > 0 && (
                            <div className="small muted">
                              {p.inbox} inbox · {p.spam} junk · {p.lost} lost · {p.failed} failed of {p.sent}
                              {p.medianLatencySeconds !== null && ` · median ${seconds(p.medianLatencySeconds)}`}
                            </div>
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

      <div className="section">
        <Card title="Recent test messages" desc="Click a row to see the headers the recipient received">
          <div className="table-wrap" style={{ opacity: data.loading ? 0.55 : 1 }}>
            <table>
              <thead>
                <tr>
                  <th>Sent</th>
                  <th>Sender</th>
                  <th>Recipient</th>
                  <th>Result</th>
                  <th className="num">Latency</th>
                  <th>Authentication</th>
                  <th>Sending IP</th>
                </tr>
              </thead>
              <tbody>
                {recent.slice(page0 * PAGE, (page0 + 1) * PAGE).map((p) => (
                  <tr
                    key={p.id}
                    className="clickable"
                    tabIndex={0}
                    onClick={() => setOpen(p.id)}
                    onKeyDown={(e) => e.key === 'Enter' && setOpen(p.id)}
                  >
                    <td style={{ whiteSpace: 'nowrap' }}>{dateTime(p.sentAt)}</td>
                    <td>{p.sender}</td>
                    <td>{p.recipient}</td>
                    <td>
                      <StatusPill level={STATUS[p.status].level} text={STATUS[p.status].text} />
                      {p.error && <div className="muted small">{p.error}</div>}
                    </td>
                    <td className="num">{seconds(p.latencySeconds)}</td>
                    <td>
                      <Auth p={p} />
                    </td>
                    <td className="mono">{p.clientIp ?? '–'}</td>
                  </tr>
                ))}
                {!recent.length && (
                  <tr>
                    <td colSpan={7} className="empty">
                      No test messages in this period
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {recent.length > PAGE && (
            <div className="pager">
              <button type="button" className="btn" disabled={page0 === 0} onClick={() => setPage(page0 - 1)}>
                Previous
              </button>
              <span>
                Page {page0 + 1} of {pages}
              </span>
              <button type="button" className="btn" disabled={page0 >= pages - 1} onClick={() => setPage(page0 + 1)}>
                Next
              </button>
            </div>
          )}
        </Card>
      </div>
      {open !== null && <ProbeDrawer id={open} onClose={() => setOpen(null)} />}
    </>
  );
}
