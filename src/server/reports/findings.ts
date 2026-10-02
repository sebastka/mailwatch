// Findings from the reports of the last REPORT_ANALYSIS_DAYS days, per domain. They feed the
// alerts; the report tabs show the full analysis.
import type { Finding } from '../../shared/types.ts';
import type { Store } from '../db.ts';
import { buildDmarcOverview, partialSources, unalignedSources } from './dmarc-analysis.ts';
import { buildTlsOverview } from './tls-analysis.ts';

const day = (offset: number, now: Date) => new Date(now.getTime() + offset * 86_400_000).toISOString().slice(0, 10);

export async function reportFindings(
  store: Store,
  domains: string[],
  days: number,
  now = new Date(),
): Promise<Map<string, Finding[]>> {
  const out = new Map<string, Finding[]>();
  const filters = { from: day(-(days - 1), now), to: day(0, now) };
  for (const domain of domains) {
    const fs: Finding[] = [];
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
