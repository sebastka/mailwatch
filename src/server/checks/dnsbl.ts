// DNS blocklists (RFC 5782): MX and sender IPs, and the domain itself.
import type { CheckResult, DnsblData, DnsblListing } from '../../shared/types.ts';
import { reverseName, type DnsClient } from '../dns.ts';
import { type CheckContext, Findings, isNonPublicIp, mapLimit, ref, result } from './util.ts';

/** Known meanings of Spamhaus return codes. */
const SPAMHAUS: Record<string, string> = {
  '127.0.0.2': 'SBL (spam source)',
  '127.0.0.3': 'CSS (snowshoe spam)',
  '127.0.0.4': 'XBL (exploited host)',
  '127.0.0.9': 'DROP (hijacked network)',
  '127.0.0.10': 'PBL (end-user range, ISP policy)',
  '127.0.0.11': 'PBL (end-user range, Spamhaus policy)',
  '127.0.1.2': 'DBL (spam domain)',
  '127.0.1.4': 'DBL (phishing domain)',
  '127.0.1.5': 'DBL (malware domain)',
  '127.0.1.6': 'DBL (botnet C&C domain)',
};

/**
 * 127.255.255.x (Spamhaus and others) and 127.0.0.1 are error codes, not listings: typically
 * "queries through public resolvers are refused" or "rate limited".
 */
export const isRefusal = (code: string) => code.startsWith('127.255.255.') || code === '127.0.0.1';

export async function lookupList(dns: DnsClient, name: string, zone: string): Promise<DnsblListing> {
  const r = await dns.a(name);
  const out: DnsblListing = { zone, listed: false, refused: false, codes: [], reason: null };
  if (r.rcode === 'NXDOMAIN' || (r.rcode === 'NOERROR' && !r.records.length)) return out;
  if (r.rcode !== 'NOERROR') {
    out.refused = true;
    out.reason = `lookup failed (${r.rcode})`;
    return out;
  }
  out.codes = r.records;
  if (r.records.every(isRefusal)) {
    out.refused = true;
    out.reason = 'the list refused the query (often: queries via public resolvers are blocked)';
    return out;
  }
  out.listed = true;
  const txt = await dns.txt(name);
  out.reason = txt.records[0] ?? r.records.map((c) => (zone.includes('spamhaus') ? (SPAMHAUS[c] ?? c) : c)).join(', ');
  return out;
}

export async function checkDnsbl(ctx: CheckContext): Promise<CheckResult<DnsblData>> {
  const started = performance.now();
  const f = new Findings();
  const { dns, domain, cfg } = ctx;

  const sources = new Map<string, Set<string>>();
  const add = (ip: string, src: string) => {
    if (isNonPublicIp(ip)) return;
    if (!sources.has(ip)) sources.set(ip, new Set());
    sources.get(ip)!.add(src);
  };
  for (const r of ctx.mx?.records ?? []) for (const a of r.addresses) add(a.ip, `MX ${r.exchange}`);
  for (const ip of domain.senderIps) add(ip, 'sender (configured)');
  for (const ip of ctx.known.probeIps) add(ip, 'sender (delivery tests)');

  const data: DnsblData = { ips: [], zones: [...cfg.ipZones, ...cfg.domainZones] };
  data.ips = await mapLimit([...sources.entries()], 4, async ([ip, src]) => ({
    ip,
    sources: [...src],
    listings: await Promise.all(cfg.ipZones.map((z) => lookupList(dns, reverseName(ip, z), z))),
  }));
  const domainListings = await Promise.all(cfg.domainZones.map((z) => lookupList(dns, `${domain.name}.${z}`, z)));
  data.ips.push({ ip: domain.name, sources: ['domain'], listings: domainListings });

  const refusedZones = new Set<string>();
  for (const entry of data.ips) {
    const isDomain = entry.sources.includes('domain');
    const isSender = entry.sources.some((s) => s.startsWith('sender'));
    for (const l of entry.listings) {
      if (l.refused) refusedZones.add(l.zone);
      if (!l.listed) continue;
      // PBL lists dynamic/end-user ranges: a problem for senders, not for receiving MX hosts.
      const pblOnly = l.codes.every((c) => c === '127.0.0.10' || c === '127.0.0.11');
      const level = isDomain || isSender ? 'error' : pblOnly ? 'info' : 'warning';
      f.add(
        level,
        isDomain ? 'dnsbl.domain-listed' : 'dnsbl.listed',
        `${entry.ip} is listed on ${l.zone}`,
        `${l.reason ?? l.codes.join(', ')}. ${isDomain ? 'Mail mentioning or sent from this domain may be rejected.' : `Used as: ${entry.sources.join(', ')}.`}`,
        { subject: `${entry.ip} ${l.zone}`, refs: [ref('rfc5782', '2')] },
      );
    }
  }
  for (const z of refusedZones) {
    f.info(
      'dnsbl.refused',
      `${z} did not answer the queries`,
      'Many lists refuse queries through public resolvers (DNS_RESOLVERS). Use your own recursive resolver, a list subscription, or remove the zone from DNSBL_ZONES.',
      { subject: z, refs: [ref('rfc5782', '2.1')] },
    );
  }
  if (!f.list.some((x) => x.level === 'error' || x.level === 'warning')) {
    f.ok(
      'dnsbl.ok',
      'Not listed',
      `${data.ips.length - 1} IP address${data.ips.length === 2 ? '' : 'es'} and the domain checked against ${data.zones.length - refusedZones.size} list${data.zones.length - refusedZones.size === 1 ? '' : 's'}.`,
      { refs: [ref('rfc5782')] },
    );
  }
  return result(ctx, 'dnsbl', started, f, data);
}
