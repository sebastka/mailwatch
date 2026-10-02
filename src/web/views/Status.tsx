import { useState } from 'react';
import type { JobStatus, Settings, Status } from '../../shared/types.ts';
import { api } from '../api.ts';
import { Card, StatusIcon, StatusPill } from '../components/ui.tsx';
import { ago, dateTime, num } from '../format.ts';
import { useAsync } from '../hooks.ts';

function Job({
  name,
  job,
  action,
  schedule,
}: {
  name: string;
  job: JobStatus;
  action?: React.ReactNode;
  schedule?: string;
}) {
  return (
    <tr>
      <td>
        <b>{name}</b>
      </td>
      <td>
        {schedule ??
          (job.intervalMinutes ? `every ${job.intervalMinutes} min` : <span className="muted">manual only</span>)}
      </td>
      <td>
        {job.running ? (
          <span className="status-pill">
            <span className="spin" /> running
          </span>
        ) : job.lastError ? (
          <StatusPill level="error" text="failed" />
        ) : job.lastSuccessAt ? (
          <StatusPill level="ok" text="ok" />
        ) : (
          <span className="muted">not run yet</span>
        )}
        {job.lastError && <div className="muted small">{job.lastError}</div>}
      </td>
      <td title={dateTime(job.lastRunAt)}>{ago(job.lastRunAt)}</td>
      <td>{job.nextRunAt ? dateTime(job.nextRunAt) : '–'}</td>
      <td>{action}</td>
    </tr>
  );
}

function SettingsEditor({ initial, canEdit, quiet }: { initial: Settings; canEdit: boolean; quiet: boolean }) {
  const [s, setS] = useState(initial);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const q = s.quietHours;
  const setQ = (patch: Partial<Settings['quietHours']>) => {
    setS((x) => ({ ...x, quietHours: { ...x.quietHours, ...patch } }));
    setMsg(null);
  };
  const save = async () => {
    setBusy(true);
    try {
      await api.saveSettings(s);
      setMsg({ ok: true, text: 'Saved.' });
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };
  return (
    <form
      className="form quiet-hours"
      onSubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      <h3>Notifications{quiet && <span className="badge">quiet now</span>}</h3>
      <fieldset disabled={!canEdit || busy}>
        <label className="inline">
          Send alerts from severity
          <select
            value={s.notifyMinSeverity}
            onChange={(e) => setS({ ...s, notifyMinSeverity: e.target.value as Settings['notifyMinSeverity'] })}
          >
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="error">error</option>
          </select>
          up
        </label>
        <label className="inline">
          <input
            type="checkbox"
            checked={s.notifyChanges}
            onChange={(e) => setS({ ...s, notifyChanges: e.target.checked })}
          />
          Announce changed DNS records
        </label>
        <label className="inline">
          <input type="checkbox" checked={q.enabled} onChange={(e) => setQ({ enabled: e.target.checked })} />
          Quiet hours: hold messages every day from
          <input type="time" value={q.start} required onChange={(e) => setQ({ start: e.target.value })} />
          to
          <input type="time" value={q.end} required onChange={(e) => setQ({ end: e.target.value })} />
        </label>
        <label className="inline">
          <input type="checkbox" checked={q.exemptErrors} onChange={(e) => setQ({ exemptErrors: e.target.checked })} />
          Send errors during quiet hours anyway
        </label>
      </fieldset>
      <p className="muted small">
        Held alerts that are still open when the quiet hours end are sent then; those that resolved in the meantime are
        dropped. Alerts below the threshold are shown in the dashboard only. Times in the server time zone.
      </p>
      {canEdit && (
        <div className="inline">
          <button type="submit" className="btn" disabled={busy}>
            Save
          </button>
          {msg && <span className={msg.ok ? 'muted' : 'delta-up'}>{msg.text}</span>}
        </div>
      )}
    </form>
  );
}

export function StatusView({
  status,
  canEdit,
  onChanged,
}: {
  status: Status | null;
  canEdit: boolean;
  onChanged: () => void;
}) {
  const settings = useAsync(() => api.settings(), []);
  const [test, setTest] = useState<{ busy: boolean; msg: string | null; ok: boolean }>({
    busy: false,
    msg: null,
    ok: true,
  });
  if (!status) return <div className="muted">Loading…</div>;
  const sendTest = async () => {
    setTest({ busy: true, msg: null, ok: true });
    try {
      await api.testTelegram();
      setTest({ busy: false, msg: 'Sent.', ok: true });
    } catch (e) {
      setTest({ busy: false, msg: (e as Error).message, ok: false });
    }
  };
  const syncNow = () => void api.syncReports().then(onChanged);

  return (
    <>
      <Card title="Jobs">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Job</th>
                <th>Schedule</th>
                <th>State</th>
                <th>Last run</th>
                <th>Next run</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <Job name="DNS and server checks" job={status.checks} />
              <Job
                name="Report mailboxes"
                job={status.reports}
                action={
                  status.mailboxes.length > 0 && (
                    <button
                      type="button"
                      className="btn"
                      onClick={syncNow}
                      disabled={status.reports.running || status.demo}
                    >
                      Sync now
                    </button>
                  )
                }
              />
              <Job
                name="Delivery tests"
                job={{ ...status.delivery, intervalMinutes: status.delivery.intervalMinutes }}
              />
            </tbody>
          </table>
        </div>
      </Card>

      <div className="section">
        <Card
          title="Report mailboxes"
          desc="DMARC aggregate, DMARC failure and TLS reports are read from these (read-only, except for the opt-in cleanup)"
        >
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Mailbox</th>
                  <th>Folder</th>
                  <th>State</th>
                  <th className="num">Messages</th>
                  <th>Last success</th>
                  <th>Cleanup</th>
                </tr>
              </thead>
              <tbody>
                {status.mailboxes.map((m) => (
                  <tr key={m.key}>
                    <td>
                      <b>{m.name}</b>
                      <div className="muted small">{m.address ?? m.key}</div>
                    </td>
                    <td className="mono">{m.folder}</td>
                    <td>
                      {m.running ? (
                        <span className="spin" />
                      ) : m.lastError ? (
                        <StatusPill level="error" text="failing" />
                      ) : m.lastSuccessAt ? (
                        <StatusPill level="ok" text="ok" />
                      ) : (
                        '–'
                      )}
                      {m.lastError && <div className="muted small">{m.lastError}</div>}
                      {m.issues.length > 0 && (
                        <details className="issues">
                          <summary className="small">
                            {m.issues.length} message{m.issues.length === 1 ? '' : 's'} without a usable report
                          </summary>
                          <ul className="small">
                            {m.issues.slice(0, 20).map((i) => (
                              <li key={i.uid}>
                                {dateTime(i.date)} · {i.from ?? '?'} · {i.subject ?? '(no subject)'}:{' '}
                                {i.status === 'no-report' ? 'no report found' : i.error}
                              </li>
                            ))}
                          </ul>
                        </details>
                      )}
                    </td>
                    <td className="num">{num(m.messages)}</td>
                    <td>{dateTime(m.lastSuccessAt)}</td>
                    <td className="small">
                      {m.cleanup ? (
                        `after ${m.cleanup.afterMonths} months${m.cleanup.dryRun ? ' (dry run)' : ''}`
                      ) : (
                        <span className="muted">off</span>
                      )}
                    </td>
                  </tr>
                ))}
                {!status.mailboxes.length && (
                  <tr>
                    <td colSpan={6} className="empty">
                      No report mailbox is configured (MAILBOX_n_IMAPHOST, …). Point rua=/ruf= of DMARC and rua= of
                      TLS-RPT at a mailbox and configure it here.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      <div className="section">
        <Card
          title="Delivery test recipients"
          desc={`Searched for test messages; a message not found within ${status.delivery.timeoutMinutes} minutes is "not delivered"`}
        >
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Recipient</th>
                  <th>Login</th>
                  <th>State</th>
                  <th>Last search</th>
                </tr>
              </thead>
              <tbody>
                {status.recipients.map((r) => (
                  <tr key={r.name}>
                    <td>
                      <b>{r.name}</b>
                      <div className="muted small">{r.address}</div>
                    </td>
                    <td>{r.auth === 'oauth2' ? 'OAuth2' : 'password'}</td>
                    <td>
                      {r.lastError ? (
                        <StatusPill level="error" text="failing" />
                      ) : r.lastSuccessAt ? (
                        <StatusPill level="ok" text="ok" />
                      ) : (
                        <span className="muted">not searched yet</span>
                      )}
                      {r.lastError && <div className="muted small">{r.lastError}</div>}
                    </td>
                    <td>{dateTime(r.lastPollAt ?? r.lastSuccessAt)}</td>
                  </tr>
                ))}
                {!status.recipients.length && (
                  <tr>
                    <td colSpan={4} className="empty">
                      No recipient is configured (RECIPIENT_n_IMAPHOST, …).
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="subhead">Sender domains</div>
          <ul className="small">
            {status.domains.map((d) => (
              <li key={d.name}>
                <b>{d.name}</b>:{' '}
                {d.sender ? `sends from ${d.from} every ${d.sendIntervalMinutes} min` : 'checked only, does not send'}
                {d.dkimSelectors.length > 0 && <> · DKIM selectors {d.dkimSelectors.join(', ')}</>}
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <div className="grid two-even section">
        <Card title="Telegram" desc="Where alerts are announced">
          {status.telegram.configured ? (
            <>
              <p>
                <span className="fail-count">
                  <StatusIcon level={status.telegram.lastError ? 'error' : 'ok'} size={12} />
                  {status.telegram.lastError ? `Last message failed: ${status.telegram.lastError}` : 'Configured'}
                </span>
              </p>
              {canEdit && (
                <button type="button" className="btn" disabled={test.busy} onClick={() => void sendTest()}>
                  Send a test message
                </button>
              )}
              {test.msg && <p className={test.ok ? 'muted' : 'delta-up'}>{test.msg}</p>}
            </>
          ) : (
            <p className="muted">
              Not configured: set TELEGRAM_TOKEN and TELEGRAM_CHAT_ID. Alerts are still shown in the dashboard.
            </p>
          )}
          {settings.data && <SettingsEditor initial={settings.data} canEdit={canEdit} quiet={status.telegram.quiet} />}
        </Card>
        <Card title="Settings" desc="From the environment">
          <dl className="kv">
            <dt>Time zone</dt>
            <dd>{status.timezone}</dd>
            <dt>DNS resolvers</dt>
            <dd className="mono">{status.dns.resolvers.join(', ')}</dd>
            <dt>Blocklist resolvers</dt>
            <dd className="mono">{status.dns.blocklistResolvers.join(', ')}</dd>
            <dt>Spamhaus</dt>
            <dd>{status.dns.spamhausDqs ? 'via DQS (SPAMHAUS_DQS_KEY set)' : 'public zones'}</dd>
            <dt>Port 25 probes</dt>
            <dd>{status.smtpProbe ? 'on' : 'off (SMTP_PROBE=false)'}</dd>
            <dt>Mode</dt>
            <dd>{status.demo ? 'Demo (seeded data, nothing runs)' : 'Live'}</dd>
          </dl>
        </Card>
      </div>
    </>
  );
}
