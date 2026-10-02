import { useState, type ComponentType, type ReactNode } from 'react';
import type { CheckKind, CheckResult } from '../../shared/types.ts';
import { CHECK_LABEL } from '../../shared/paths.ts';
import { TAB_SPECS } from '../../shared/rfcs.ts';
import { api } from '../api.ts';
import { ChangeList } from '../components/Changes.tsx';
import { Card, ErrorBanner, FindingList, SpecPanel, StatusPill } from '../components/ui.tsx';
import { ago, dateTime } from '../format.ts';
import { useAsync } from '../hooks.ts';
import { CHECK_INTRO } from './check-intro.ts';
import * as D from './details.tsx';

const DETAILS: Record<CheckKind, ComponentType<{ data: unknown; domain: string }>> = {
  domain: D.DomainDetails,
  mx: D.MxDetails,
  spf: D.SpfDetails,
  dkim: D.DkimDetails,
  dmarc: D.DmarcDetails,
  'mta-sts': D.MtaStsDetails,
  'tls-rpt': D.TlsRptDetails,
  dane: D.DaneDetails,
  bimi: D.BimiDetails,
  dnsbl: D.DnsblDetails,
  senders: D.SendersDetails,
};

/** One card per domain: status, findings (OK ones collapsible) and the check's details. */
export function CheckResults({ check, results }: { check: CheckKind; results: CheckResult[] }) {
  const [showOk, setShowOk] = useState(true);
  const Details = DETAILS[check];
  return (
    <div className="domain-cards">
      {results.map((r) => (
        <Card
          key={r.domain}
          title={
            <span className="domain-head">
              <StatusPill level={r.level} text={r.domain} />
            </span>
          }
          desc={
            <span title={dateTime(r.checkedAt)}>
              Checked {ago(r.checkedAt)} · {r.durationMs} ms
            </span>
          }
          actions={
            <label className="field small">
              <input type="checkbox" checked={showOk} onChange={(e) => setShowOk(e.target.checked)} /> Show OK
            </label>
          }
        >
          <FindingList findings={r.findings} showOk={showOk} />
          {r.data !== null && Details && (
            <details className="collapsible" style={{ marginTop: 12 }} open>
              <summary className="subhead" style={{ display: 'inline' }}>
                Details
              </summary>
              <Details data={r.data} domain={r.domain} />
            </details>
          )}
        </Card>
      ))}
    </div>
  );
}

export function CheckView({
  check,
  domain,
  version,
  children,
}: {
  check: CheckKind;
  domain: string;
  version: number;
  children?: ReactNode;
}) {
  const results = useAsync(() => api.checks(check, domain || undefined), [check, domain, version]);
  const changes = useAsync(
    () => api.changes({ check, ...(domain ? { domain } : {}), limit: 30 }),
    [check, domain, version],
  );
  const rows = results.data ?? [];
  return (
    <>
      <p className="desc" style={{ marginTop: 0 }}>
        {CHECK_INTRO[check]}
      </p>
      <SpecPanel docs={TAB_SPECS[check]} findings={rows.flatMap((r) => r.findings)} />
      {results.error && <ErrorBanner>Could not load the results: {results.error}</ErrorBanner>}
      {results.data && !rows.length && (
        <div className="muted">Not checked yet. The first check runs right after the start.</div>
      )}
      <div style={{ opacity: results.loading ? 0.55 : 1, transition: 'opacity .15s' }}>
        <CheckResults check={check} results={rows} />
      </div>
      {children}
      {check !== 'dnsbl' && (
        <div className="section">
          <Card title={`${CHECK_LABEL[check]} record changes`} desc="Changes seen between two checks">
            {changes.data && <ChangeList changes={changes.data} showDomain={!domain} showCheck={false} />}
          </Card>
        </div>
      )}
    </>
  );
}
