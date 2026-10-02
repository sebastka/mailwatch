// MX records, their addresses and reverse DNS, and the SMTP service on port 25.
import { isIP } from 'node:net';
import type { CheckResult, MxData, MxHost, SmtpProbe } from '../../shared/types.ts';
import { answered } from '../dns.ts';
import { probeSmtp } from './smtp.ts';
import { type CheckContext, certExpiry, Findings, isNonPublicIp, mapLimit, ref, result } from './util.ts';

/** Probes per MX host (one per address family is enough to see the service). */
const MAX_IPS_PER_HOST = 2;
const MAX_HOSTS = 6;

export async function checkMx(ctx: CheckContext): Promise<CheckResult<MxData>> {
  const started = performance.now();
  const f = new Findings();
  const { dns, domain } = ctx;
  const data: MxData = {
    records: [],
    nullMx: false,
    implicit: false,
    dnssec: false,
    smtp: [],
    probeEnabled: ctx.cfg.smtpProbe,
  };
  const done = () => {
    ctx.mx = data;
    return result(ctx, 'mx', started, f, data);
  };

  const q = await dns.mx(domain.name);
  data.dnssec = q.secure;
  if (!answered(q)) {
    f.lookupFailed('mx.lookup-failed', 'the MX records', q);
    return done();
  }
  if (q.rcode === 'NXDOMAIN') {
    f.error('mx.nxdomain', 'The domain does not exist', `${domain.name} does not exist in DNS (NXDOMAIN).`, {
      refs: [ref('rfc5321', '5.1')],
    });
    return done();
  }

  // Null MX (RFC 7505): a single MX of preference 0 pointing at the root.
  const nulls = q.records.filter((r) => r.exchange === '');
  if (nulls.length) {
    data.nullMx = true;
    if (q.records.length > nulls.length) {
      f.error(
        'mx.null-mixed',
        'Null MX published together with other MX records',
        'A domain that publishes a Null MX ("0 .") must not publish any other MX record. Remove the Null MX if the domain receives mail.',
        { refs: [ref('rfc7505', '3')] },
      );
    } else {
      if (nulls.some((r) => r.preference !== 0)) {
        f.warning('mx.null-preference', 'Null MX preference is not 0', 'A Null MX record should use preference 0.', {
          refs: [ref('rfc7505', '3')],
        });
      }
      f.info(
        'mx.null',
        'The domain does not accept mail (Null MX)',
        'Senders reject mail to this domain immediately instead of queueing it. This is correct for domains that never receive mail.',
        { refs: [ref('rfc7505')] },
      );
      return done();
    }
  }

  let hosts = q.records.filter((r) => r.exchange !== '').sort((a, b) => a.preference - b.preference);
  if (!hosts.length) {
    // Implicit MX: the domain's own address records (RFC 5321 §5.1).
    const own = await dns.addresses(domain.name);
    if (own.ips.length) {
      data.implicit = true;
      f.warning(
        'mx.implicit',
        'No MX record: mail is delivered to the domain’s own address',
        `${domain.name} has no MX record, so senders fall back to its A/AAAA records (${own.ips.join(', ')}). Publish an MX record, or a Null MX ("0 .") if the domain should not receive mail.`,
        { refs: [ref('rfc5321', '5.1'), ref('rfc7505')] },
      );
      hosts = [{ preference: 0, exchange: domain.name }];
    } else {
      f.error(
        'mx.none',
        'No MX record and no address: the domain cannot receive mail',
        'Publish MX records for the servers that receive mail for this domain, or a Null MX ("0 .") if it should not receive mail.',
        { refs: [ref('rfc5321', '5.1'), ref('rfc7505')] },
      );
      return done();
    }
  }

  const dupes = new Set<number>();
  for (const h of hosts) {
    if (hosts.filter((x) => x.preference === h.preference).length > 1) dupes.add(h.preference);
  }

  data.records = await Promise.all(
    hosts.map(async (h): Promise<MxHost> => {
      const host: MxHost = { preference: h.preference, exchange: h.exchange, cname: null, addresses: [] };
      if (isIP(h.exchange)) {
        f.error(
          'mx.ip-literal',
          `MX ${h.exchange} is an IP address`,
          'An MX record must name a host, not an address.',
          {
            subject: h.exchange,
            refs: [ref('rfc5321', '5.1')],
          },
        );
        return host;
      }
      const addr = await dns.addresses(h.exchange);
      if (addr.cnames.length) {
        host.cname = addr.cnames.at(-1)!;
        f.warning(
          'mx.cname',
          `MX ${h.exchange} is an alias (CNAME)`,
          `${h.exchange} is a CNAME for ${host.cname}. MX records must point at the canonical host name; most senders cope, some refuse.`,
          { subject: h.exchange, refs: [ref('rfc2181', '10.3'), ref('rfc5321', '5.1')] },
        );
      }
      if (addr.failed && !addr.ips.length) {
        f.warning('mx.host-lookup-failed', `Could not resolve MX ${h.exchange}`, 'The address lookup failed.', {
          subject: h.exchange,
        });
        return host;
      }
      if (!addr.ips.length) {
        f.error('mx.no-address', `MX ${h.exchange} has no address`, `${h.exchange} has no A or AAAA record.`, {
          subject: h.exchange,
          refs: [ref('rfc5321', '5.1')],
        });
        return host;
      }
      host.addresses = await Promise.all(
        addr.ips.map(async (ip) => {
          const rev = await dns.reverse(ip);
          return { ip, ptr: rev.ptr, fcrdns: rev.fcrdns };
        }),
      );
      for (const a of host.addresses) {
        if (isNonPublicIp(a.ip)) {
          f.error(
            'mx.private-ip',
            `MX ${h.exchange} resolves to a non-public address`,
            `${a.ip} is not reachable from the Internet.`,
            {
              subject: `${h.exchange} ${a.ip}`,
            },
          );
        } else if (!a.ptr && a.fcrdns === false) {
          f.warning(
            'mx.no-ptr',
            `No reverse DNS for ${a.ip}`,
            `${a.ip} (MX ${h.exchange}) has no PTR record. Hosts on the Internet should have one; some senders and filters penalise servers without.`,
            { subject: a.ip, refs: [ref('rfc1912', '2.1')] },
          );
        } else if (a.ptr && a.fcrdns === false) {
          f.info(
            'mx.ptr-mismatch',
            `Reverse DNS of ${a.ip} does not resolve back`,
            `${a.ip} points to ${a.ptr}, which does not resolve to ${a.ip} (no forward-confirmed reverse DNS).`,
            { subject: a.ip, refs: [ref('rfc1912', '2.1')] },
          );
        }
      }
      return host;
    }),
  );

  if (dupes.size === 0 && data.records.length === 1) {
    f.info(
      'mx.single',
      'Only one MX host',
      'That is fine: senders queue and retry when it is down. A second MX only helps if it is run independently.',
    );
  }
  const allIps = data.records.flatMap((r) => r.addresses.map((a) => a.ip));
  if (allIps.length && !allIps.some((ip) => ip.includes(':'))) {
    f.info(
      'mx.no-ipv6',
      'No IPv6 address for the MX hosts',
      'Senders that only have IPv6 cannot reach these MX hosts.',
    );
  }

  if (ctx.cfg.smtpProbe) await probeAll(ctx, f, data);
  if (!f.list.some((x) => x.level === 'error' || x.level === 'warning')) {
    f.ok(
      'mx.ok',
      `${data.records.length} MX host${data.records.length === 1 ? '' : 's'}`,
      data.records.map((r) => `${r.preference} ${r.exchange}`).join(', '),
      {
        refs: [ref('rfc5321', '5.1')],
      },
    );
  }
  return done();
}

async function probeAll(ctx: CheckContext, f: Findings, data: MxData): Promise<void> {
  // One IPv4 and one IPv6 address per host; a host shared with other domains is probed once per run.
  const probeHost = (r: MxHost) => {
    const v4 = r.addresses.find((a) => !a.ip.includes(':'));
    const v6 = r.addresses.find((a) => a.ip.includes(':'));
    const ips = [v4, v6]
      .filter((a) => a !== undefined && !isNonPublicIp(a.ip))
      .slice(0, MAX_IPS_PER_HOST)
      .map((a) => a!.ip);
    return Promise.all(
      ips.map((ip) =>
        probeSmtp(r.exchange, ip, { heloName: ctx.cfg.heloName, timeoutMs: ctx.cfg.smtpTimeoutMs, now: ctx.now }),
      ),
    );
  };
  const perHost = await mapLimit(data.records.slice(0, MAX_HOSTS), 3, (r) =>
    r.addresses.length ? ctx.probes.forHost(r.exchange, () => probeHost(r)) : Promise.resolve([]),
  );
  data.smtp = perHost.flat();
  if (data.smtp.length && data.smtp.every((p) => !p.connected)) {
    f.error(
      'smtp.unreachable-all',
      'No MX host accepted a connection on port 25',
      `${data.smtp.map((p) => `${p.host} (${p.ip}): ${p.error}`).join('; ')}. If every domain shows this, outbound port 25 is probably blocked where MailWatch runs; set SMTP_PROBE=false there.`,
      { refs: [ref('rfc5321', '5.1')] },
    );
    return;
  }
  // ENETUNREACH on IPv6 means the monitoring host has no IPv6 route: one note, not one per MX.
  const noLocalV6 = (p: SmtpProbe) =>
    v6(p) && !p.connected && /ENETUNREACH|EHOSTUNREACH|EADDRNOTAVAIL/.test(p.error ?? '');
  const skipped = data.smtp.filter(noLocalV6);
  if (skipped.length) {
    f.info(
      'smtp.no-local-ipv6',
      'IPv6 addresses of the MX hosts were not probed',
      `The host MailWatch runs on has no IPv6 connectivity, so ${skipped.map((p) => p.ip).join(', ')} could not be tested.`,
    );
  }
  for (const p of data.smtp) if (!noLocalV6(p)) smtpFindings(ctx, f, p);
}

/** Port 25 connections over IPv6 often fail on the monitoring host rather than at the MX. */
const v6 = (p: SmtpProbe) => p.ip.includes(':');

function smtpFindings(ctx: CheckContext, f: Findings, p: SmtpProbe): void {
  const subject = `${p.host} ${p.ip}`;
  if (!p.connected) {
    f.add(
      v6(p) ? 'info' : 'warning',
      'smtp.unreachable',
      `Could not connect to ${p.host} on port 25 (${p.ip})`,
      `${p.error ?? 'connection failed'}.${v6(p) ? ' This may be the IPv6 connectivity of the host MailWatch runs on.' : ''}`,
      { subject },
    );
    return;
  }
  if (p.error && !p.tls) {
    f.warning('smtp.session-failed', `SMTP session with ${p.host} failed`, p.error, {
      subject,
      refs: [ref('rfc5321')],
    });
    if (!p.starttls) return;
  }
  if (!p.starttls) {
    f.error(
      'smtp.no-starttls',
      `${p.host} does not offer STARTTLS`,
      'Mail to this server is sent unencrypted. STARTTLS is also required for MTA-STS and DANE.',
      { subject, refs: [ref('rfc3207'), ref('rfc8461', '4.2')] },
    );
    return;
  }
  if (!p.tls) {
    f.error('smtp.tls-failed', `TLS handshake with ${p.host} failed`, p.error ?? 'unknown error', {
      subject,
      refs: [ref('rfc3207')],
    });
    return;
  }
  const proto = p.tls.protocol ?? '';
  if (proto === 'TLSv1' || proto === 'TLSv1.1' || proto.startsWith('SSL')) {
    f.error(
      'smtp.old-tls',
      `${p.host} negotiates ${proto}`,
      'TLS 1.0 and 1.1 are deprecated and must not be used; the server does not support TLS 1.2 or 1.3.',
      { subject, refs: [ref('rfc8996')] },
    );
  }
  const leaf = p.tls.chain[0];
  if (!leaf) {
    f.error('smtp.no-cert', `${p.host} presented no certificate`, '', { subject });
    return;
  }
  if (!p.tls.hostnameMatch) {
    f.warning(
      'smtp.cert-name-mismatch',
      `The certificate of ${p.host} does not name it`,
      `The certificate is for ${leaf.sans.join(', ') || leaf.subject}. MTA-STS senders refuse to deliver to this host; DANE-EE (3 x x) records ignore names.`,
      { subject, refs: [ref('rfc9525', '6.3'), ref('rfc8461', '4.2')] },
    );
  } else if (!p.tls.authorized) {
    f.warning(
      'smtp.cert-untrusted',
      `The certificate of ${p.host} is not publicly trusted`,
      `${p.tls.authorizationError}. Opportunistic TLS still works, but MTA-STS senders refuse to deliver to this host.`,
      { subject, refs: [ref('rfc8461', '4.2')] },
    );
  }
  const before = f.list.length;
  certExpiry(f, 'smtp', leaf, ctx.cfg.certWarnDays, subject, `${p.host}`);
  if (f.list.length === before && p.tls.authorized && p.tls.hostnameMatch && !/^(TLSv1|TLSv1\.1)$/.test(proto)) {
    f.ok(
      'smtp.ok',
      `${p.host}: STARTTLS with ${proto}, valid certificate`,
      `${p.ip} · certificate by ${leaf.issuer.replace(/^.*CN=/, '')}, valid until ${leaf.validTo.slice(0, 10)}`,
      { subject, refs: [ref('rfc3207')] },
    );
  }
}
