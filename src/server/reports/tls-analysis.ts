// Aggregation of stored SMTP TLS reports (RFC 8460) into the TLS-RPT tab. Ported from tlsrpt.
import type {
  FailureDetailStat,
  FailureTypeStat,
  Filters,
  Insight,
  Level,
  OrgStat,
  PolicyStat,
  TimeBucket,
  TlsOverview,
  TlsReportSummary,
} from '../../shared/types.ts';
import type { TlsPolicyRow, TlsReportRow } from '../db.ts';
import { RESULT_TYPES } from '../../shared/result-types.ts';

const DAY_MS = 86_400_000;
/** Ranges longer than this are bucketed per ISO week instead of per day. */
const MAX_DAILY_BUCKETS = 120;
/** A reporter that has been silent this long (while it reported before) is flagged. */
const STALE_DAYS = 7;

const toDay = (ms: number) => new Date(ms).toISOString().slice(0, 10);
const dayMs = (day: string) => Date.parse(`${day}T00:00:00Z`);

function weekStart(day: string): string {
  const ms = dayMs(day);
  const dow = (new Date(ms).getUTCDay() + 6) % 7; // Monday = 0
  return toDay(ms - dow * DAY_MS);
}

/**
 * Session totals of one report, deduplicated across policies.
 *
 * A reporter evaluating several policies for the same domain (e.g. Microsoft reports both
 * DANE/TLSA and MTA-STS) counts every session once per policy. Summing would double count,
 * so per domain we take the largest total and the largest failure count across its policies.
 */
export function reportSessions(policies: TlsPolicyRow[]): { sessions: number; failed: number } {
  const perDomain = new Map<string, { sessions: number; failed: number }>();
  for (const p of policies) {
    const cur = perDomain.get(p.domain) ?? { sessions: 0, failed: 0 };
    cur.sessions = Math.max(cur.sessions, p.successful + p.failed);
    cur.failed = Math.max(cur.failed, p.failed);
    perDomain.set(p.domain, cur);
  }
  let sessions = 0;
  let failed = 0;
  for (const v of perDomain.values()) {
    sessions += v.sessions;
    failed += v.failed;
  }
  return { sessions, failed };
}

export function summarizeReport(r: TlsReportRow): TlsReportSummary {
  const { sessions, failed } = reportSessions(r.policies);
  return {
    id: r.id,
    org: r.org,
    reportId: r.reportId,
    start: r.start,
    end: r.end,
    domains: [...new Set(r.policies.map((p) => p.domain))],
    policyTypes: [...new Set(r.policies.map((p) => p.type))],
    sessions,
    failed,
    receivedAt: r.receivedAt,
  };
}

export function buildTlsOverview(reports: TlsReportRow[], filters: Filters, now = new Date()): TlsOverview {
  const days = reports.map((r) => r.day).sort();
  const from = filters.from ?? days[0] ?? null;
  const to = filters.to ?? days.at(-1) ?? null;
  const spanDays = from && to ? Math.round((dayMs(to) - dayMs(from)) / DAY_MS) + 1 : 0;
  const bucket: 'day' | 'week' = spanDays > MAX_DAILY_BUCKETS ? 'week' : 'day';
  const bucketOf = (day: string) => (bucket === 'week' ? weekStart(day) : day);

  // Pre-fill buckets so days without reports show as gaps on the axis.
  const series = new Map<string, TimeBucket>();
  if (from && to) {
    const step = bucket === 'week' ? 7 * DAY_MS : DAY_MS;
    for (let ms = dayMs(bucketOf(from)); ms <= dayMs(to); ms += step) {
      const d = toDay(ms);
      series.set(d, { start: d, successful: 0, failed: 0, reports: 0 });
    }
  }

  const orgs = new Map<string, OrgStat>();
  const policies = new Map<string, PolicyStat>();
  const failureTypes = new Map<string, FailureTypeStat & { reportIds: Set<number> }>();
  const details = new Map<string, FailureDetailStat & { reporterSet: Set<string> }>();
  const domains = new Set<string>();
  let sessions = 0;
  let failed = 0;
  let lastReportEnd: string | null = null;

  for (const r of reports) {
    const s = reportSessions(r.policies);
    sessions += s.sessions;
    failed += s.failed;
    if (!lastReportEnd || r.end > lastReportEnd) lastReportEnd = r.end;

    const b = bucketOf(r.day);
    const tb = series.get(b) ?? { start: b, successful: 0, failed: 0, reports: 0 };
    tb.successful += s.sessions - s.failed;
    tb.failed += s.failed;
    tb.reports += 1;
    series.set(b, tb);

    const o = orgs.get(r.org) ?? { org: r.org, reports: 0, sessions: 0, failed: 0, lastReportEnd: r.end };
    o.reports += 1;
    o.sessions += s.sessions;
    o.failed += s.failed;
    if (r.end > o.lastReportEnd) o.lastReportEnd = r.end;
    orgs.set(r.org, o);

    for (const p of r.policies) {
      domains.add(p.domain);
      const key = `${p.domain}\u0000${p.type}`;
      const ps = policies.get(key) ?? {
        domain: p.domain,
        type: p.type,
        reports: 0,
        successful: 0,
        failed: 0,
        latestMode: null,
        latestMxHosts: [],
        latestPolicyString: [],
        lastSeen: '',
      };
      ps.reports += 1;
      ps.successful += p.successful;
      ps.failed += p.failed;
      // Reports are processed oldest first, so the last one wins.
      if (r.end >= ps.lastSeen) {
        ps.lastSeen = r.end;
        ps.latestMode = p.mode;
        if (p.mxHosts.length) ps.latestMxHosts = p.mxHosts;
        ps.latestPolicyString = p.policyString;
      }
      policies.set(key, ps);

      for (const f of p.failures) {
        const ft = failureTypes.get(f.resultType) ?? {
          resultType: f.resultType,
          sessions: 0,
          reports: 0,
          reportIds: new Set<number>(),
        };
        ft.sessions += f.failedSessionCount;
        ft.reportIds.add(r.id);
        failureTypes.set(f.resultType, ft);

        const dk = [
          p.domain,
          p.type,
          f.resultType,
          f.sendingMtaIp,
          f.receivingMxHostname,
          f.receivingIp,
          f.failureReasonCode,
        ].join('\u0000');
        const d = details.get(dk) ?? {
          domain: p.domain,
          policyType: p.type,
          resultType: f.resultType,
          sendingMtaIp: f.sendingMtaIp,
          receivingMxHostname: f.receivingMxHostname,
          receivingMxHelo: f.receivingMxHelo,
          receivingIp: f.receivingIp,
          failureReasonCode: f.failureReasonCode,
          additionalInformation: f.additionalInformation,
          sessions: 0,
          reporters: [],
          reporterSet: new Set<string>(),
          firstSeen: r.start,
          lastSeen: r.end,
        };
        d.sessions += f.failedSessionCount;
        d.reporterSet.add(r.org);
        if (r.start < d.firstSeen) d.firstSeen = r.start;
        if (r.end > d.lastSeen) d.lastSeen = r.end;
        d.receivingMxHelo ??= f.receivingMxHelo;
        d.additionalInformation ??= f.additionalInformation;
        details.set(dk, d);
      }
    }
  }

  const byPolicy = [...policies.values()].sort(
    (a, b) => a.domain.localeCompare(b.domain) || a.type.localeCompare(b.type),
  );
  const byOrg = [...orgs.values()].sort((a, b) => b.sessions - a.sessions || a.org.localeCompare(b.org));

  const overview: TlsOverview = {
    range: { from, to },
    bucket,
    kpis: {
      reports: reports.length,
      reporters: orgs.size,
      domains: domains.size,
      sessions,
      successful: sessions - failed,
      failed,
      successRate: sessions ? (sessions - failed) / sessions : null,
      lastReportEnd,
    },
    series: [...series.values()].sort((a, b) => a.start.localeCompare(b.start)),
    byOrg,
    byPolicy,
    failureTypes: [...failureTypes.values()]
      .map(({ reportIds, ...ft }) => ({ ...ft, reports: reportIds.size }))
      .sort((a, b) => b.sessions - a.sessions),
    failureDetails: [...details.values()]
      .map(({ reporterSet, ...d }) => ({ ...d, reporters: [...reporterSet].sort() }))
      .sort((a, b) => b.sessions - a.sessions || b.lastSeen.localeCompare(a.lastSeen)),
    insights: [],
  };
  overview.insights = buildInsights(overview, filters, now);
  return overview;
}

const pct = (n: number) => `${(n * 100).toFixed(n > 0.999 && n < 1 ? 2 : 1)}%`;

export function buildInsights(o: TlsOverview, filters: Filters, now: Date): Insight[] {
  const out: Insight[] = [];
  const { kpis } = o;

  if (kpis.reports === 0) {
    out.push({
      level: 'info',
      title: 'No reports in this range',
      detail: 'Widen the date range, or check the sync status if you expected reports.',
    });
    return out;
  }

  if (kpis.failed > 0) {
    const rate = kpis.failed / kpis.sessions;
    const top = o.failureTypes[0];
    out.push({
      level: rate >= 0.05 ? 'error' : 'warning',
      title: `${kpis.failed.toLocaleString('en')} failed TLS session${kpis.failed === 1 ? '' : 's'} (${pct(rate)})`,
      detail: top
        ? `Most common result: ${top.resultType}. ${RESULT_TYPES[top.resultType] ?? ''}`.trim()
        : 'Reporters did not include failure details.',
      refs: [{ doc: 'rfc8460', section: '4.3' }],
    });
  } else {
    out.push({
      level: 'ok',
      title: 'No TLS failures reported',
      detail: `All ${kpis.sessions.toLocaleString('en')} sessions reported by ${kpis.reporters} reporter${
        kpis.reporters === 1 ? '' : 's'
      } negotiated TLS successfully.`,
    });
  }

  // Per-domain and per-reporter findings are grouped, so many domains in the same state
  // produce one finding with a compact list instead of one line each.
  const testing = o.byPolicy.filter((p) => p.type === 'sts' && p.latestMode === 'testing');
  const modeNone = o.byPolicy.filter((p) => p.type === 'sts' && p.latestMode === 'none');
  const noPolicy = o.byPolicy.filter((p) => p.type === 'no-policy-found');

  // One finding for every domain still in MTA-STS testing mode. Domains with failures make it
  // a warning and are listed first, marked, since they must be fixed before enforcing.
  if (testing.length) {
    const failing = testing.filter((p) => p.failed > 0).sort((a, b) => b.failed - a.failed);
    const ok = testing.filter((p) => p.failed === 0).sort((a, b) => a.domain.localeCompare(b.domain));
    const level: Level = failing.length ? 'warning' : 'info';
    const fixFirst =
      'Senders still deliver without TLS when validation fails, so fix the failures before switching to "mode: enforce".';
    if (testing.length === 1) {
      const p = testing[0]!;
      out.push({
        level,
        title: `MTA-STS for ${p.domain} is in testing mode`,
        detail: p.failed
          ? `${p.failed.toLocaleString('en')} MTA-STS failure${p.failed === 1 ? '' : 's'} reported. ${fixFirst}`
          : `No MTA-STS failures in ${p.reports} report${p.reports === 1 ? '' : 's'}. Consider switching the policy to "mode: enforce" once you have enough history.`,
        refs: [{ doc: 'rfc8461', section: '5' }],
      });
    } else {
      out.push({
        level,
        title: `MTA-STS is in testing mode for ${testing.length} domains`,
        detail: failing.length
          ? `${failing.length} of them had failures (listed first). ${fixFirst} The others can be switched once you have enough history.`
          : 'No MTA-STS failures reported for these domains. Consider switching their policies to "mode: enforce" once you have enough history.',
        subjects: [
          ...failing.map((p) => ({
            kind: 'domain' as const,
            value: p.domain,
            level: 'warning' as const,
            note: `${p.failed.toLocaleString('en')} failed`,
          })),
          ...ok.map((p) => ({ kind: 'domain' as const, value: p.domain })),
        ],
        refs: [{ doc: 'rfc8461', section: '5' }],
      });
    }
  }
  if (modeNone.length) {
    out.push(
      grouped(
        'warning',
        modeNone,
        (d) => `MTA-STS for ${d} is set to mode "none"`,
        (n) => `MTA-STS is set to mode "none" for ${n} domains`,
        {
          detail: 'The policy is being withdrawn; senders do not apply it.',
        },
      ),
    );
  }
  if (noPolicy.length) {
    out.push(
      grouped(
        'info',
        noPolicy,
        (d) => `Reporters found no policy for ${d}`,
        (n) => `Reporters found no policy for ${n} domains`,
        {
          detail: `Neither MTA-STS nor DANE was found when delivering to ${noPolicy.length === 1 ? 'this domain' : 'these domains'}, so TLS is opportunistic only.`,
        },
      ),
    );
  }

  // Staleness only makes sense when the range reaches (close to) today.
  const today = now.toISOString().slice(0, 10);
  if (!filters.to || filters.to >= today) {
    const stale = o.byOrg
      .map((org) => ({ org: org.org, days: Math.floor((now.getTime() - Date.parse(org.lastReportEnd)) / DAY_MS) }))
      .filter((s) => s.days >= STALE_DAYS);
    const detail = 'Reporters only send a report on days they delivered mail to you, so this can be normal.';
    if (stale.length === 1) {
      out.push({ level: 'info', title: `No report from ${stale[0]!.org} for ${stale[0]!.days} days`, detail });
    } else if (stale.length > 1) {
      out.push({
        level: 'info',
        title: `No report from ${stale.length} reporters for ${STALE_DAYS} days or more`,
        detail,
        subjects: stale
          .sort((a, b) => b.days - a.days)
          .map((s) => ({ kind: 'org' as const, value: s.org, note: `${s.days} days` })),
      });
    }
  }

  return out;
}

/** One finding for a set of domains: named in the title when there is one, listed otherwise. */
function grouped(
  level: Level,
  policies: PolicyStat[],
  one: (domain: string) => string,
  many: (count: number) => string,
  { detail }: { detail: string },
): Insight {
  const domains = [...new Set(policies.map((p) => p.domain))].sort();
  if (domains.length === 1) return { level, title: one(domains[0]!), detail };
  return { level, title: many(domains.length), detail, subjects: domains.map((d) => ({ kind: 'domain', value: d })) };
}
