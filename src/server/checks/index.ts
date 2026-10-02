// Runs every check of one domain, in dependency order.
import type { CheckKind, CheckResult } from '../../shared/types.ts';
import type { Config } from '../config.ts';
import { DnsClient } from '../dns.ts';
import { checkBimi } from './bimi.ts';
import { checkDane } from './dane.ts';
import { checkDkim } from './dkim.ts';
import { checkDmarc } from './dmarc.ts';
import { checkDnsbl } from './dnsbl.ts';
import { checkDomain } from './domain.ts';
import { checkMtaSts } from './mtasts.ts';
import { checkMx } from './mx.ts';
import { checkSenders } from './senders.ts';
import { checkSpf } from './spf.ts';
import { ProbeCache } from './smtp.ts';
import { checkTlsRpt } from './tlsrpt-record.ts';
import { type CheckContext, type DomainCheckInput, type KnownFacts, Findings, result } from './util.ts';

export const CHECK_ORDER: CheckKind[] = [
  'domain',
  'mx',
  'spf',
  'dkim',
  'dmarc',
  'mta-sts',
  'tls-rpt',
  'dane',
  'bimi',
  'dnsbl',
  'senders',
];

const RUNNERS: Record<CheckKind, (ctx: CheckContext) => Promise<CheckResult>> = {
  domain: checkDomain,
  mx: checkMx,
  spf: checkSpf,
  dkim: checkDkim,
  dmarc: checkDmarc,
  'mta-sts': checkMtaSts,
  'tls-rpt': checkTlsRpt,
  dane: checkDane,
  bimi: checkBimi,
  dnsbl: checkDnsbl,
  senders: checkSenders,
};

export const NO_FACTS: KnownFacts = { reportSelectors: [], probeSelectors: [], probeIps: [], monitoredAddresses: [] };

/** What one check run shares between its domains: DNS answers (both resolver sets) and SMTP probes. */
export interface RunShared {
  dns: DnsClient;
  blocklistDns: DnsClient;
  probes: ProbeCache;
}

/**
 * Caches for one run over several domains. Created per run, so nothing is reused between runs:
 * every run sees current DNS and current servers.
 */
export function newRun(cfg: Config['checks']): RunShared {
  const dns = new DnsClient(cfg.resolvers, cfg.dnsTimeoutMs);
  const same = cfg.blocklistResolvers.join(',') === cfg.resolvers.join(',');
  return {
    dns,
    blocklistDns: same ? dns : new DnsClient(cfg.blocklistResolvers, cfg.dnsTimeoutMs),
    probes: new ProbeCache(),
  };
}

export async function runDomainChecks(
  domain: DomainCheckInput,
  cfg: Config['checks'],
  opts: { known?: KnownFacts; previous?: CheckResult[]; now?: Date } & Partial<RunShared> = {},
): Promise<CheckResult[]> {
  // Missing parts come from a fresh run of their own (e.g. a single-domain check).
  const fresh = opts.dns && opts.blocklistDns && opts.probes ? null : newRun(cfg);
  const ctx: CheckContext = {
    domain,
    dns: opts.dns ?? fresh!.dns,
    // Blocklists always use their own client: never fall back to `dns` when the resolvers differ.
    blocklistDns: opts.blocklistDns ?? fresh!.blocklistDns,
    probes: opts.probes ?? fresh!.probes,
    cfg,
    known: opts.known ?? NO_FACTS,
    now: opts.now ?? new Date(),
    previous: new Map((opts.previous ?? []).map((r) => [r.check, r])),
    current: new Map(),
  };
  const out: CheckResult[] = [];
  for (const check of CHECK_ORDER) {
    const started = performance.now();
    let r: CheckResult;
    try {
      r = await RUNNERS[check](ctx);
    } catch (e) {
      // A bug in one check must not stop the others.
      const f = new Findings();
      f.warning('internal-error', 'The check failed', (e as Error).stack ?? String(e));
      r = result(ctx, check, started, f, null);
    }
    ctx.current.set(check, r);
    out.push(r);
  }
  return out;
}
