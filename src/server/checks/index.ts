// Runs every check of one domain, in dependency order.
import type { CheckKind, CheckResult } from '../../shared/types.ts';
import type { Config } from '../config.ts';
import { DnsClient } from '../dns.ts';
import { checkBimi } from './bimi.ts';
import { checkDane } from './dane.ts';
import { checkDkim } from './dkim.ts';
import { checkDmarc } from './dmarc.ts';
import { checkDnsbl } from './dnsbl.ts';
import { checkMtaSts } from './mtasts.ts';
import { checkMx } from './mx.ts';
import { checkSpf } from './spf.ts';
import { checkTlsRpt } from './tlsrpt-record.ts';
import { type CheckContext, type DomainCheckInput, type KnownFacts, Findings, result } from './util.ts';

export const CHECK_ORDER: CheckKind[] = ['mx', 'spf', 'dkim', 'dmarc', 'mta-sts', 'tls-rpt', 'dane', 'bimi', 'dnsbl'];

const RUNNERS: Record<CheckKind, (ctx: CheckContext) => Promise<CheckResult>> = {
  mx: checkMx,
  spf: checkSpf,
  dkim: checkDkim,
  dmarc: checkDmarc,
  'mta-sts': checkMtaSts,
  'tls-rpt': checkTlsRpt,
  dane: checkDane,
  bimi: checkBimi,
  dnsbl: checkDnsbl,
};

export const NO_FACTS: KnownFacts = { reportSelectors: [], probeSelectors: [], probeIps: [], monitoredAddresses: [] };

export async function runDomainChecks(
  domain: DomainCheckInput,
  cfg: Config['checks'],
  opts: { known?: KnownFacts; previous?: CheckResult[]; now?: Date; dns?: DnsClient; blocklistDns?: DnsClient } = {},
): Promise<CheckResult[]> {
  const dns = opts.dns ?? new DnsClient(cfg.resolvers, cfg.dnsTimeoutMs);
  const sameResolvers = cfg.blocklistResolvers.join(',') === cfg.resolvers.join(',');
  const ctx: CheckContext = {
    domain,
    dns,
    blocklistDns:
      opts.blocklistDns ?? (sameResolvers || opts.dns ? dns : new DnsClient(cfg.blocklistResolvers, cfg.dnsTimeoutMs)),
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
