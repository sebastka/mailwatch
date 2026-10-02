// The domain itself: its registration (RDAP, RFC 9083 with the IANA bootstrap of RFC 9224) and
// its nameservers (count, addresses, lame delegation, SOA serials, network diversity).
import type { CheckResult, DomainData, NameserverHost, NameserverProbe, RegistrationData } from '../../shared/types.ts';
import { answered, DnsClient } from '../dns.ts';
import { orgDomain } from './dmarc.ts';
import { type CheckContext, Findings, httpsGet, mapLimit, ref, result } from './util.ts';

const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const DAY_MS = 86_400_000;
/** RDAP answers are reused for a day (an hour after a failure): registries rate-limit. */
const RDAP_TTL_MS = DAY_MS;
const RDAP_RETRY_MS = 3_600_000;

let bootstrap: { at: number; services: [string[], string[]][] } | null = null;

/** The RDAP base URL of a TLD from the IANA bootstrap file (cached for a day); null when the registry has none. */
async function rdapBase(ctx: CheckContext, tld: string): Promise<string | null> {
  if (!bootstrap || Date.now() - bootstrap.at > DAY_MS) {
    const res = await httpsGet(BOOTSTRAP_URL, ctx.dns, ctx.cfg.httpTimeoutMs, 2 * 1024 * 1024);
    if (res.status !== 200) throw new Error(`IANA RDAP bootstrap: HTTP ${res.status}`);
    bootstrap = { at: Date.now(), services: (JSON.parse(res.body) as { services: [string[], string[]][] }).services };
  }
  const svc = bootstrap.services.find(([tlds]) => tlds.includes(tld));
  const url = svc?.[1].find((u) => u.startsWith('https://'));
  return url ? (url.endsWith('/') ? url : `${url}/`) : null;
}

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Reads the parts of an RDAP domain object we use (RFC 9083 §5.3). */
export function parseRdap(domain: string, server: string, j: unknown, fetchedAt: string): RegistrationData {
  const o = isObj(j) ? j : {};
  const events = (Array.isArray(o.events) ? o.events : []).filter(isObj);
  const event = (action: string) => {
    const e = events.find((x) => String(x.eventAction).toLowerCase() === action);
    return typeof e?.eventDate === 'string' ? new Date(e.eventDate).toISOString() : null;
  };
  const registrar = (Array.isArray(o.entities) ? o.entities : [])
    .filter(isObj)
    .find((e) => Array.isArray(e.roles) && e.roles.includes('registrar'));
  const vcard = Array.isArray(registrar?.vcardArray) ? (registrar.vcardArray[1] as unknown[][] | undefined) : undefined;
  const fn = vcard?.find((v) => Array.isArray(v) && v[0] === 'fn')?.[3];
  const secure = isObj(o.secureDNS) ? o.secureDNS : null;
  return {
    domain,
    server,
    fetchedAt,
    status: (Array.isArray(o.status) ? o.status : []).map((x) => String(x).toLowerCase()),
    registrar: typeof fn === 'string' ? fn : null,
    registered: event('registration'),
    expires: event('expiration'),
    lastChanged: event('last changed'),
    nameservers: (Array.isArray(o.nameservers) ? o.nameservers : [])
      .filter(isObj)
      .map((n) =>
        String(n.ldhName ?? '')
          .toLowerCase()
          .replace(/\.$/, ''),
      )
      .filter(Boolean)
      .sort(),
    delegationSigned: typeof secure?.delegationSigned === 'boolean' ? secure.delegationSigned : null,
    error: null,
  };
}

async function fetchRegistration(ctx: CheckContext, domain: string): Promise<RegistrationData | null> {
  const now = ctx.now.toISOString();
  const tld = domain.split('.').at(-1)!;
  const base = await rdapBase(ctx, tld);
  if (!base) return null;
  let url = `${base}domain/${domain}`;
  // A few registries redirect (to a regional server, or from a thin to a thick registry).
  for (let hop = 0; hop < 3; hop++) {
    const res = await httpsGet(url, ctx.dns, ctx.cfg.httpTimeoutMs, 512 * 1024);
    if (res.status >= 300 && res.status < 400 && res.location?.startsWith('https://')) {
      url = new URL(res.location, url).href;
      continue;
    }
    if (res.status === 404)
      return { ...parseRdap(domain, base, {}, now), error: 'the registry does not know the domain (HTTP 404)' };
    if (res.status !== 200) throw new Error(`HTTP ${res.status} from ${new URL(url).host}`);
    return parseRdap(domain, base, JSON.parse(res.body), now);
  }
  throw new Error('too many redirects');
}

const HOLD = ['client hold', 'server hold', 'clienthold', 'serverhold'];
const DYING = ['pending delete', 'redemption period', 'pendingdelete', 'redemptionperiod'];

function registrationFindings(ctx: CheckContext, f: Findings, r: RegistrationData) {
  const refs = [ref('rfc9083', '4.5')];
  if (r.error) {
    f.error('domain.not-registered', `${r.domain} is not registered`, `The registry answered: ${r.error}.`, { refs });
    return;
  }
  const hold = r.status.filter((s) => HOLD.includes(s));
  if (hold.length) {
    f.error(
      'domain.on-hold',
      `${r.domain} is on hold (${hold.join(', ')})`,
      'A domain on hold is removed from DNS: nothing resolves, so no mail is delivered. Contact the registrar.',
      {
        refs: [ref('rfc8056', '2')],
      },
    );
  }
  const dying = r.status.filter((s) => DYING.includes(s));
  if (dying.length) {
    f.error(
      'domain.pending-delete',
      `${r.domain} is being deleted (${dying.join(', ')})`,
      'The registration expired or was cancelled. Renew or restore it with the registrar now.',
      {
        refs: [ref('rfc8056', '2')],
      },
    );
  }
  if (r.expires) {
    const days = Math.floor((Date.parse(r.expires) - ctx.now.getTime()) / DAY_MS);
    const when = r.expires.slice(0, 10);
    if (days < 0)
      f.error(
        'domain.expired',
        `${r.domain} expired on ${when}`,
        'Renew it with the registrar now; the registry may delete it.',
        { refs },
      );
    else if (days < 7) {
      f.error(
        'domain.expiring',
        `${r.domain} expires in ${days} day${days === 1 ? '' : 's'}`,
        `Registered until ${when}. Make sure it renews (auto-renewal, payment method).`,
        { refs },
      );
    } else if (days < ctx.cfg.registrationWarnDays) {
      f.warning(
        'domain.expiring',
        `${r.domain} expires in ${days} days`,
        `Registered until ${when}. Make sure it renews (auto-renewal, payment method).`,
        { refs },
      );
    } else {
      f.ok(
        'domain.registered',
        `Registered until ${when}`,
        `${r.registrar ?? 'Unknown registrar'}${r.status.length ? ` · ${r.status.join(', ')}` : ''}`,
        { refs },
      );
    }
  } else {
    f.info(
      'domain.no-expiry',
      'The registry publishes no expiry date',
      `${r.server ? new URL(r.server).host : 'The registry'} does not include the expiry in RDAP (Norid, for example, never does). Check the renewal with the registrar ${r.registrar ?? ''}.`.trim(),
      { refs },
    );
  }
}

/** Queries one nameserver directly for the zone's SOA: is it authoritative, which serial? */
async function probeNameserver(ctx: CheckContext, zone: string, host: string, ip: string): Promise<NameserverProbe> {
  const r = await new DnsClient([ip], ctx.cfg.dnsTimeoutMs, 1).query<{ serial: number }>(zone, 'SOA');
  return {
    host,
    ip,
    rcode: r.rcode,
    authoritative: Boolean(r.authoritative),
    serial: r.records[0]?.serial ?? null,
  };
}

async function nameserverFindings(ctx: CheckContext, f: Findings, data: DomainData) {
  const { dns } = ctx;
  const zone = data.zone;
  const ns = await dns.query<string>(zone, 'NS');
  if (!answered(ns)) {
    f.lookupFailed('domain.ns-lookup-failed', 'the nameservers', ns);
    return;
  }
  const hosts = [...new Set(ns.records)].sort();
  data.nameservers = await mapLimit(hosts, 4, async (host): Promise<NameserverHost> => {
    const a = await dns.addresses(host);
    return { host, addresses: a.ips, probes: [] };
  });
  const refs1034 = [ref('rfc1034', '4.1')];
  if (hosts.length === 0) {
    f.error('domain.no-ns', `No NS records for ${zone}`, 'The zone has no nameservers in DNS.', { refs: refs1034 });
    return;
  }
  if (hosts.length < 2) {
    f.error(
      'domain.single-ns',
      'Only one nameserver',
      `${hosts[0]} is the only nameserver of ${zone}. A zone needs at least two, so that it still resolves when one is down.`,
      {
        refs: [ref('rfc1034', '4.1'), ref('rfc2182', '5')],
      },
    );
  }
  for (const h of data.nameservers.filter((x) => !x.addresses.length)) {
    f.error(
      'domain.ns-no-address',
      `Nameserver ${h.host} has no address`,
      `${h.host} does not resolve, so resolvers cannot use it (lame delegation).`,
      {
        subject: h.host,
        refs: [ref('rfc1912', '2.8')],
      },
    );
  }

  // The registry's delegation and the zone's own NS records should list the same servers.
  const delegated = data.registration?.nameservers ?? [];
  if (delegated.length) {
    const missing = hosts.filter((h) => !delegated.includes(h));
    const extra = delegated.filter((h) => !hosts.includes(h));
    if (missing.length || extra.length) {
      f.warning(
        'domain.ns-mismatch',
        'The registry delegates to other nameservers than the zone lists',
        `Registry: ${delegated.join(', ')}. Zone: ${hosts.join(', ')}. Resolvers may get different answers depending on which set they use; make both the same.`,
        { refs: [ref('rfc1034', '4.2.2')] },
      );
    }
  }

  // /24 (IPv4) diversity: all nameservers in one network fail together.
  const nets = new Set(
    data.nameservers.flatMap((h) =>
      h.addresses.filter((ip) => !ip.includes(':')).map((ip) => ip.split('.').slice(0, 3).join('.')),
    ),
  );
  if (nets.size === 1 && hosts.length > 1) {
    f.info(
      'domain.ns-one-network',
      'All nameservers are in one network',
      `Every nameserver address is in ${[...nets][0]}.0/24. Anycast providers are fine; otherwise one network outage takes the whole zone down.`,
      {
        refs: [ref('rfc2182', '3.1')],
      },
    );
  }

  if (!ctx.cfg.nsProbe) {
    if (!f.list.some((x) => x.code.startsWith('domain.ns') || x.code === 'domain.single-ns')) {
      f.ok(
        'domain.ns-ok',
        `${hosts.length} nameservers`,
        `${hosts.join(', ')} (not queried directly: NS_CHECK=false)`,
        {
          refs: refs1034,
        },
      );
    }
    return;
  }
  data.probed = true;
  // One IPv4 and one IPv6 address per nameserver.
  const targets = data.nameservers.flatMap((h) =>
    [h.addresses.find((ip) => !ip.includes(':')), h.addresses.find((ip) => ip.includes(':'))]
      .filter((ip): ip is string => Boolean(ip))
      .map((ip) => ({ host: h.host, ip })),
  );
  const probes = await mapLimit(targets, 6, (t) => probeNameserver(ctx, zone, t.host, t.ip));
  for (const p of probes) data.nameservers.find((h) => h.host === p.host)!.probes.push(p);

  const v4 = probes.filter((p) => !p.ip.includes(':'));
  if (v4.length && v4.every((p) => p.rcode === 'TIMEOUT')) {
    f.info(
      'domain.ns-unreachable-all',
      'The nameservers could not be queried directly',
      'No nameserver answered on port 53. If this shows for every domain, outbound DNS to arbitrary servers is blocked where MailWatch runs; set NS_CHECK=false there.',
    );
    return;
  }
  // IPv6 timing out everywhere while IPv4 answers: the monitoring host has no IPv6, one note.
  const v6 = probes.filter((p) => p.ip.includes(':'));
  const noLocalV6 = v6.length > 0 && v6.every((p) => p.rcode === 'TIMEOUT') && v4.some((p) => p.rcode !== 'TIMEOUT');
  if (noLocalV6) {
    f.info(
      'domain.ns-no-local-ipv6',
      'IPv6 addresses of the nameservers did not answer',
      `None of ${v6.map((p) => p.ip).join(', ')} answered while the IPv4 addresses did. Most likely the host MailWatch runs on has no IPv6 connectivity.`,
    );
  }
  for (const p of probes) {
    const subject = `${p.host} ${p.ip}`;
    if (noLocalV6 && p.ip.includes(':')) continue;
    if (p.rcode === 'TIMEOUT') {
      f.add(
        p.ip.includes(':') ? 'info' : 'warning',
        'domain.ns-unreachable',
        `Nameserver ${p.host} does not answer (${p.ip})`,
        p.ip.includes(':')
          ? 'This may be the IPv6 connectivity of the host MailWatch runs on.'
          : 'Resolvers retry with the other nameservers, which slows down every lookup.',
        {
          subject,
          refs: [ref('rfc2182', '5')],
        },
      );
    } else if (p.rcode !== 'NOERROR' || !p.authoritative) {
      f.error(
        'domain.lame',
        `Nameserver ${p.host} is not authoritative for ${zone}`,
        `${p.ip} answered ${p.rcode}${p.rcode === 'NOERROR' ? ' without the authoritative flag' : ''}: a lame delegation. Resolvers that pick it fail or time out.`,
        { subject, refs: [ref('rfc1912', '2.8')] },
      );
    }
  }
  const serials = [...new Set(probes.filter((p) => p.authoritative && p.serial !== null).map((p) => p.serial))];
  if (serials.length > 1) {
    f.warning(
      'domain.serial-mismatch',
      'The nameservers serve different versions of the zone',
      `SOA serials ${serials.join(', ')}: a secondary is not updated, so changes (e.g. to SPF or DKIM) reach only part of the resolvers.`,
      { refs: [ref('rfc1034', '4.3.5')] },
    );
  }
  if (
    !f.list.some(
      (x) =>
        (x.code.startsWith('domain.ns') && x.code !== 'domain.ns-no-local-ipv6') ||
        x.code === 'domain.lame' ||
        x.code === 'domain.serial-mismatch' ||
        x.code === 'domain.single-ns',
    )
  ) {
    f.ok(
      'domain.ns-ok',
      `${hosts.length} nameservers, all authoritative`,
      `${hosts.join(', ')}${serials.length === 1 ? ` · serial ${serials[0]}` : ''}`,
      { refs: refs1034 },
    );
  }
}

export async function checkDomain(ctx: CheckContext): Promise<CheckResult<DomainData>> {
  const started = performance.now();
  const f = new Findings();
  const zone = orgDomain(ctx.domain.name);
  const data: DomainData = { zone, registration: null, nameservers: [], probed: false };

  if (ctx.cfg.rdap) {
    const prev = (ctx.previous.get('domain')?.data as DomainData | undefined)?.registration;
    const age = prev ? ctx.now.getTime() - Date.parse(prev.fetchedAt) : Infinity;
    try {
      data.registration =
        prev && prev.domain === zone && age < (prev.error ? RDAP_RETRY_MS : RDAP_TTL_MS)
          ? prev
          : await fetchRegistration(ctx, zone);
      if (data.registration) registrationFindings(ctx, f, data.registration);
      else {
        f.info(
          'domain.no-rdap',
          `The .${zone.split('.').at(-1)} registry offers no RDAP`,
          'Registration data (expiry, status) cannot be looked up automatically for this TLD; check the renewal with the registrar.',
          {
            refs: [ref('rfc9224')],
          },
        );
      }
    } catch (e) {
      // Keep the last good registration data, so the expiry stays known during an outage.
      if (prev && prev.domain === zone && !prev.error) data.registration = prev;
      f.warning('domain.rdap-lookup-failed', 'Could not look up the registration', `RDAP: ${(e as Error).message}.`, {
        refs: [ref('rfc9083')],
      });
    }
  }
  await nameserverFindings(ctx, f, data);
  return result(ctx, 'domain', started, f, data);
}
