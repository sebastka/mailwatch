// Aggregation of DMARC aggregate reports into the DMARC reports tab, and the findings that
// feed the alerts.
import type {
  DmarcBucket,
  DmarcDomainStat,
  DmarcOrgStat,
  DmarcOverview,
  DmarcReportSummary,
  DmarcSelectorStat,
  DmarcSourceStat,
  Filters,
  Insight,
  InsightSubject,
} from '../../shared/types.ts';
import type { DmarcReportRow } from '../db.ts';
import { passes } from './dmarc.ts';

const DAY_MS = 86_400_000;
const MAX_DAILY_BUCKETS = 120;
const STALE_DAYS = 7;
/** A source that passes for some messages but fails for at least this many is "probably yours, broken". */
const PARTIAL_MIN_FAILED = 5;

const toDay = (ms: number) => new Date(ms).toISOString().slice(0, 10);
const dayMs = (day: string) => Date.parse(`${day}T00:00:00Z`);
function weekStart(day: string): string {
  const ms = dayMs(day);
  const dow = (new Date(ms).getUTCDay() + 6) % 7;
  return toDay(ms - dow * DAY_MS);
}

export function summarizeDmarc(r: DmarcReportRow): DmarcReportSummary {
  let messages = 0;
  let failed = 0;
  for (const x of r.records) {
    messages += x.count;
    if (!passes(x)) failed += x.count;
  }
  return {
    id: r.id,
    org: r.org,
    reportId: r.reportId,
    domain: r.domain,
    start: r.begin,
    end: r.end,
    messages,
    failed,
    receivedAt: r.receivedAt,
  };
}

export function buildDmarcOverview(
  reports: DmarcReportRow[],
  filters: Filters,
  now = new Date(),
  ptr: (ip: string) => string | null = () => null,
): DmarcOverview {
  const days = reports.map((r) => r.day).sort();
  const from = filters.from ?? days[0] ?? null;
  const to = filters.to ?? days.at(-1) ?? null;
  const spanDays = from && to ? Math.round((dayMs(to) - dayMs(from)) / DAY_MS) + 1 : 0;
  const bucket: 'day' | 'week' = spanDays > MAX_DAILY_BUCKETS ? 'week' : 'day';
  const bucketOf = (day: string) => (bucket === 'week' ? weekStart(day) : day);

  const series = new Map<string, DmarcBucket>();
  if (from && to) {
    const step = bucket === 'week' ? 7 * DAY_MS : DAY_MS;
    for (let ms = dayMs(bucketOf(from)); ms <= dayMs(to); ms += step) {
      const d = toDay(ms);
      series.set(d, { start: d, passed: 0, failed: 0, reports: 0 });
    }
  }

  type SourceAcc = DmarcSourceStat & { hf: Set<string>; ef: Set<string>; dd: Set<string>; rep: Set<string> };
  const sources = new Map<string, SourceAcc>();
  const orgs = new Map<string, DmarcOrgStat>();
  const domains = new Map<string, DmarcDomainStat>();
  const selectors = new Map<string, DmarcSelectorStat>();
  const overrides = new Map<string, number>();
  let messages = 0;
  let passed = 0;
  let quarantined = 0;
  let rejected = 0;
  let lastReportEnd: string | null = null;

  for (const r of reports) {
    if (!lastReportEnd || r.end > lastReportEnd) lastReportEnd = r.end;
    const b = bucketOf(r.day);
    const tb = series.get(b) ?? { start: b, passed: 0, failed: 0, reports: 0 };
    tb.reports++;
    const o = orgs.get(r.org) ?? { org: r.org, reports: 0, messages: 0, failed: 0, lastReportEnd: r.end };
    o.reports++;
    if (r.end > o.lastReportEnd) o.lastReportEnd = r.end;
    const d = domains.get(r.domain) ?? {
      domain: r.domain,
      reports: 0,
      messages: 0,
      passed: 0,
      failed: 0,
      policy: null,
      lastSeen: '',
    };
    d.reports++;
    // Reports are processed oldest first: the latest published policy wins.
    if (r.end >= d.lastSeen) {
      d.lastSeen = r.end;
      d.policy = r.policy;
    }

    for (const x of r.records) {
      const ok = passes(x);
      messages += x.count;
      if (ok) passed += x.count;
      if (x.disposition === 'quarantine') quarantined += x.count;
      if (x.disposition === 'reject') rejected += x.count;
      tb[ok ? 'passed' : 'failed'] += x.count;
      o.messages += x.count;
      if (!ok) o.failed += x.count;
      d.messages += x.count;
      d[ok ? 'passed' : 'failed'] += x.count;
      for (const reason of x.reasons) overrides.set(reason.type, (overrides.get(reason.type) ?? 0) + x.count);

      const s =
        sources.get(x.sourceIp) ??
        ({
          ip: x.sourceIp,
          ptr: null,
          messages: 0,
          passed: 0,
          failed: 0,
          spfAligned: 0,
          dkimAligned: 0,
          quarantined: 0,
          rejected: 0,
          headerFrom: [],
          envelopeFrom: [],
          dkimDomains: [],
          reporters: [],
          lastSeen: r.end,
          hf: new Set(),
          ef: new Set(),
          dd: new Set(),
          rep: new Set(),
        } satisfies SourceAcc);
      s.messages += x.count;
      s[ok ? 'passed' : 'failed'] += x.count;
      if (x.spf === 'pass') s.spfAligned += x.count;
      if (x.dkim === 'pass') s.dkimAligned += x.count;
      if (x.disposition === 'quarantine') s.quarantined += x.count;
      if (x.disposition === 'reject') s.rejected += x.count;
      s.hf.add(x.headerFrom);
      if (x.envelopeFrom) s.ef.add(x.envelopeFrom);
      for (const k of x.dkimResults)
        if (k.domain) s.dd.add(`${k.domain}${k.result === 'pass' ? '' : ` (${k.result})`}`);
      s.rep.add(r.org);
      if (r.end > s.lastSeen) s.lastSeen = r.end;
      sources.set(x.sourceIp, s);

      for (const k of x.dkimResults) {
        if (!k.selector || !k.domain) continue;
        const key = `${k.domain}\u0000${k.selector.toLowerCase()}`;
        const st = selectors.get(key) ?? { domain: k.domain, selector: k.selector.toLowerCase(), pass: 0, fail: 0 };
        if (k.result === 'pass') st.pass += x.count;
        else st.fail += x.count;
        selectors.set(key, st);
      }
    }
    series.set(b, tb);
    orgs.set(r.org, o);
    domains.set(r.domain, d);
  }

  const bySource = [...sources.values()]
    .map(({ hf, ef, dd, rep, ...s }) => ({
      ...s,
      ptr: ptr(s.ip),
      headerFrom: [...hf].sort(),
      envelopeFrom: [...ef].sort(),
      dkimDomains: [...dd].sort(),
      reporters: [...rep].sort(),
    }))
    .sort((a, b) => b.messages - a.messages || a.ip.localeCompare(b.ip));

  const overview: DmarcOverview = {
    range: { from, to },
    bucket,
    kpis: {
      reports: reports.length,
      reporters: orgs.size,
      domains: domains.size,
      sources: sources.size,
      messages,
      passed,
      failed: messages - passed,
      passRate: messages ? passed / messages : null,
      quarantined,
      rejected,
      lastReportEnd,
    },
    series: [...series.values()].sort((a, b) => a.start.localeCompare(b.start)),
    bySource,
    byOrg: [...orgs.values()].sort((a, b) => b.messages - a.messages || a.org.localeCompare(b.org)),
    byDomain: [...domains.values()].sort((a, b) => a.domain.localeCompare(b.domain)),
    selectors: [...selectors.values()].sort(
      (a, b) => a.domain.localeCompare(b.domain) || b.pass + b.fail - (a.pass + a.fail),
    ),
    insights: [],
  };
  overview.insights = dmarcInsights(overview, filters, now, overrides);
  return overview;
}

const pct = (n: number) => `${(n * 100).toFixed(n > 0.999 && n < 1 ? 2 : 1)}%`;
const n = (x: number) => x.toLocaleString('en');
const label = (s: DmarcSourceStat) => (s.ptr ? `${s.ip} (${s.ptr})` : s.ip);

/** Sources that pass for some messages and fail for others: usually a legitimate sender with a broken setup. */
export const partialSources = (o: DmarcOverview) =>
  o.bySource.filter((s) => s.passed > 0 && s.failed >= PARTIAL_MIN_FAILED);

/** Sources that authenticate (DKIM or SPF pass) but never align with the From: domain. */
export function unalignedSources(o: DmarcOverview): DmarcSourceStat[] {
  return o.bySource.filter((s) => s.passed === 0 && s.dkimDomains.some((d) => !d.includes('(')));
}

export function dmarcInsights(
  o: DmarcOverview,
  filters: Filters,
  now: Date,
  overrides = new Map<string, number>(),
): Insight[] {
  const out: Insight[] = [];
  const k = o.kpis;
  if (k.reports === 0) {
    out.push({
      level: 'info',
      title: 'No DMARC reports in this range',
      detail: 'Widen the date range, check the mailbox sync, or make sure rua= points to a mailbox MailWatch reads.',
      refs: [{ doc: 'rfc7489', section: '7.2' }],
    });
    return out;
  }
  if (k.failed === 0) {
    out.push({
      level: 'ok',
      title: 'Every reported message passed DMARC',
      detail: `${n(k.messages)} messages from ${k.sources} source${k.sources === 1 ? '' : 's'}, reported by ${k.reporters} reporter${k.reporters === 1 ? '' : 's'}.`,
    });
  } else {
    const failing = o.bySource.filter((s) => s.failed > 0);
    out.push({
      level: 'info',
      title: `${n(k.failed)} message${k.failed === 1 ? '' : 's'} failed DMARC (${pct(k.failed / k.messages)})`,
      detail: `From ${failing.length} source${failing.length === 1 ? '' : 's'}. Failures from unknown sources are usually spoofing that your policy handles; failures from your own services need fixing (see below). ${n(k.quarantined)} quarantined, ${n(k.rejected)} rejected.`,
      subjects: failing
        .slice(0, 40)
        .map((s) => ({ kind: 'ip' as const, value: s.ip, note: `${n(s.failed)}${s.ptr ? ` · ${s.ptr}` : ''}` })),
      refs: [{ doc: 'rfc7489', section: '6.6.2' }],
    });
  }

  const partial = partialSources(o);
  if (partial.length) {
    out.push({
      level: 'warning',
      title: `${partial.length} source${partial.length === 1 ? '' : 's'} pass${partial.length === 1 ? 'es' : ''} DMARC only partly`,
      detail:
        'These servers send mail that passes and mail that fails, which usually means a legitimate sender with a problem (an unsigned stream, a missing SPF include, a rotated DKIM key). ' +
        partial
          .slice(0, 5)
          .map((s) => `${label(s)}: ${n(s.failed)} of ${n(s.messages)} failed`)
          .join('; '),
      subjects: partial.map((s) => ({
        kind: 'ip' as const,
        value: s.ip,
        level: 'warning' as const,
        note: `${n(s.failed)} failed`,
      })),
      refs: [{ doc: 'rfc7489', section: '3.1' }],
    });
  }

  const unaligned = unalignedSources(o);
  if (unaligned.length) {
    out.push({
      level: 'warning',
      title: `${unaligned.length} source${unaligned.length === 1 ? '' : 's'} sign${unaligned.length === 1 ? 's' : ''} with another domain`,
      detail:
        'DKIM passes, but for a domain that is not aligned with the From: domain, so DMARC fails. This is typical for a mail service (newsletter, CRM, ticketing) sending as you: set up DKIM with your own domain there. ' +
        unaligned
          .slice(0, 5)
          .map((s) => `${label(s)} signs as ${s.dkimDomains.join(', ')}`)
          .join('; '),
      subjects: unaligned.map((s) => ({ kind: 'ip' as const, value: s.ip, note: s.dkimDomains[0] })),
      refs: [{ doc: 'rfc7489', section: '3.1.1' }],
    });
  }

  const none = o.byDomain.filter((d) => d.policy?.p === 'none' && d.failed > 0);
  if (none.length) {
    out.push({
      level: 'warning',
      title: `p=none: failing mail was delivered for ${none.length} domain${none.length === 1 ? '' : 's'}`,
      detail:
        'Receivers delivered mail that failed DMARC because the published policy is "none". Fix your own senders, then move to quarantine or reject.',
      subjects: none.map((d) => ({ kind: 'domain' as const, value: d.domain, note: `${n(d.failed)} failed` })),
      refs: [{ doc: 'rfc7489', section: '6.3' }],
    });
  }
  const pctBelow = o.byDomain.filter(
    (d) => d.policy?.pct !== null && d.policy?.pct !== undefined && d.policy.pct < 100,
  );
  if (pctBelow.length) {
    out.push({
      level: 'info',
      title: 'Policy applied to part of the mail only (pct below 100)',
      detail: pctBelow.map((d) => `${d.domain}: pct=${d.policy!.pct}`).join(', '),
      subjects: pctBelow.map((d) => ({ kind: 'domain' as const, value: d.domain })),
      refs: [{ doc: 'rfc7489', section: '6.6.4' }],
    });
  }

  const brokenSelectors = o.selectors.filter(
    (s) => s.fail > 0 && s.pass === 0 && o.byDomain.some((d) => d.domain === s.domain),
  );
  if (brokenSelectors.length) {
    out.push({
      level: 'warning',
      title: `DKIM fails for ${brokenSelectors.length} selector${brokenSelectors.length === 1 ? '' : 's'} of your domains`,
      detail: `${brokenSelectors.map((s) => `${s.selector}._domainkey.${s.domain} (${n(s.fail)} failed)`).join(', ')}. Check the key record (DKIM tab) and the signing configuration.`,
      refs: [{ doc: 'rfc6376', section: '6.1' }],
    });
  }

  const ov = [...overrides.entries()].filter(([t]) => t !== '');
  if (ov.length) {
    out.push({
      level: 'info',
      title: 'Receivers overrode the policy for some messages',
      detail:
        ov.map(([t, c]) => `${t}: ${n(c)}`).join(', ') +
        '. Forwarding and mailing lists commonly break SPF and DKIM; ARC helps receivers recognise them.',
      refs: [{ doc: 'rfc7489', section: '7.2' }, { doc: 'rfc8617' }],
    });
  }

  const today = now.toISOString().slice(0, 10);
  if (!filters.to || filters.to >= today) {
    const stale = o.byOrg
      .map((org) => ({ org: org.org, days: Math.floor((now.getTime() - Date.parse(org.lastReportEnd)) / DAY_MS) }))
      .filter((s) => s.days >= STALE_DAYS);
    if (stale.length) {
      const subjects: InsightSubject[] = stale
        .sort((a, b) => b.days - a.days)
        .map((s) => ({ kind: 'org', value: s.org, note: `${s.days} days` }));
      out.push({
        level: 'info',
        title:
          stale.length === 1
            ? `No report from ${stale[0]!.org} for ${stale[0]!.days} days`
            : `No report from ${stale.length} reporters for ${STALE_DAYS} days or more`,
        detail: 'Reporters only send reports for days on which they received mail from you, so this can be normal.',
        subjects,
      });
    }
  }
  return out;
}
