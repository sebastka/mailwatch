// Findings from the reports of the last REPORT_ANALYSIS_DAYS days, per domain. They feed the
// alerts; the report tabs show the full analysis.
import type { Finding } from '../../shared/types.ts';
import type { Store } from '../db.ts';
import { buildDmarcOverview, partialSources, unalignedSources } from './dmarc-analysis.ts';
import { buildTlsOverview } from './tls-analysis.ts';

const day = (offset: number, now: Date) => new Date(now.getTime() + offset * 86_400_000).toISOString().slice(0, 10);

/** Which report addresses a domain publishes (from its latest checks); unknown domains count as publishing. */
export type Publishes = (domain: string) => { dmarc: boolean; tls: boolean };

/** Window in which a domain must have had reports before their absence is noticed. */
const SILENT_LOOKBACK_DAYS = 30;

export async function reportFindings(
  store: Store,
  domains: string[],
  days: number,
  now = new Date(),
  opts: { silentDays?: number; publishes?: Publishes } = {},
): Promise<Map<string, Finding[]>> {
  const out = new Map<string, Finding[]>();
  const filters = { from: day(-(days - 1), now), to: day(0, now) };
  const silentDays = opts.silentDays ?? 0;
  const last = silentDays > 0 ? await store.lastReportDays(SILENT_LOOKBACK_DAYS) : null;
  for (const domain of domains) {
    const fs: Finding[] = [];
    if (last) fs.push(...silentFindings(domain, last, silentDays, now, opts.publishes?.(domain)));
    const [dmarc, tls] = await Promise.all([
      store.loadDmarcReports({ ...filters, domain }),
      store.loadTlsReports({ ...filters, domain }),
    ]);

    if (dmarc.length) {
      const o = buildDmarcOverview(dmarc, filters, now);
      const partial = partialSources(o);
      if (partial.length) {
        const failed = partial.reduce((s, x) => s + x.failed, 0);
        fs.push({
          code: 'dmarc-reports.partial',
          level: 'warning',
          title: `${partial.length} sending source${partial.length === 1 ? '' : 's'} fail DMARC for part of their mail`,
          detail: `${failed} messages in the last ${days} days, from ${partial
            .map((s) => s.ip)
            .slice(0, 5)
            .join(', ')}. Usually a legitimate sender with a broken SPF or DKIM setup.`,
          refs: [{ doc: 'rfc7489', section: '3.1' }],
        });
      }
      const unaligned = unalignedSources(o);
      if (unaligned.length) {
        fs.push({
          code: 'dmarc-reports.unaligned',
          level: 'warning',
          title: `${unaligned.length} source${unaligned.length === 1 ? '' : 's'} sign with another domain`,
          detail: `${unaligned
            .slice(0, 5)
            .map((s) => `${s.ip} (${s.dkimDomains.join(', ')})`)
            .join(
              '; ',
            )}. DKIM passes but is not aligned, so DMARC fails: configure DKIM with ${domain} at that service.`,
          refs: [{ doc: 'rfc7489', section: '3.1.1' }],
        });
      }
      for (const s of o.selectors.filter((x) => x.domain === domain && x.fail > 0 && x.pass === 0)) {
        fs.push({
          code: 'dmarc-reports.dkim-fail',
          level: 'warning',
          title: `DKIM selector "${s.selector}" fails in the reports`,
          detail: `${s.fail} messages signed with ${s.selector}._domainkey.${domain} failed DKIM in the last ${days} days.`,
          subject: s.selector,
          refs: [{ doc: 'rfc6376', section: '6.1' }],
        });
      }
    }

    if (tls.length) {
      const o = buildTlsOverview(tls, filters, now);
      const { sessions, failed } = o.kpis;
      if (failed > 0 && sessions > 0) {
        const rate = failed / sessions;
        if (rate >= 0.01) {
          const top = o.failureTypes[0];
          fs.push({
            code: 'tls-reports.failures',
            level: rate >= 0.05 ? 'error' : 'warning',
            title: `${failed} failed TLS session${failed === 1 ? '' : 's'} reported (${(rate * 100).toFixed(1)}%)`,
            detail: `In the last ${days} days${top ? `; most common: ${top.resultType}` : ''}. Senders could not deliver to your MX over (validated) TLS.`,
            refs: [{ doc: 'rfc8460', section: '4.3' }],
          });
        }
      }
    }
    out.set(domain, fs);
  }
  return out;
}

/**
 * A reporting pipeline that stopped: reports arrived in the last 30 days, but none for
 * `silentDays` days. Usually a broken mailbox, a full quota, a lost rua= address or a sync
 * problem; reports are sent daily, so a few days of silence is unusual for an active domain.
 */
function silentFindings(
  domain: string,
  last: { dmarc: Map<string, string>; tls: Map<string, string> },
  silentDays: number,
  now: Date,
  publishes = { dmarc: true, tls: true },
): Finding[] {
  const out: Finding[] = [];
  const cutoff = day(-silentDays, now);
  const kinds = [
    ['dmarc', 'dmarc-reports.silent', 'DMARC aggregate', 'rua= of the DMARC record', 'rfc7489', '7.2'],
    ['tls', 'tls-reports.silent', 'TLS', 'rua= of the TLS-RPT record', 'rfc8460', '3'],
  ] as const;
  for (const [kind, code, what, where, doc, section] of kinds) {
    const d = last[kind].get(domain.toLowerCase());
    if (!d || d >= cutoff || !publishes[kind]) continue;
    const ago = Math.round((Date.parse(day(0, now)) - Date.parse(d)) / 86_400_000);
    out.push({
      code,
      level: 'warning',
      title: `No ${what} reports for ${ago} days`,
      detail: `The last report covers ${d}; before that, reports arrived regularly. Check the ${where}, the report mailbox (quota, credentials) and the Status tab. Threshold: REPORT_SILENT_DAYS=${silentDays}.`,
      refs: [{ doc, section }],
    });
  }
  return out;
}
