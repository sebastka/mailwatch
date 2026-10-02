// The sending side of a domain: its outbound IPs (reverse DNS, SPF authorisation), its
// submission and IMAP servers (TLS), client autoconfiguration (RFC 6186, autoconfig), and a
// summary of the Gmail and Yahoo sender requirements.
import { connect as tlsConnect, type TLSSocket } from 'node:tls';
import type {
  CheckResult,
  DmarcData,
  SenderIp,
  SenderRequirement,
  SendersData,
  ServiceProbe,
  SpfData,
  SrvTarget,
} from '../../shared/types.ts';
import { answered } from '../dns.ts';
import { LENIENT_TLS, probeSmtp, tlsInfoOf } from './smtp.ts';
import { checkHost } from './spf-eval.ts';
import { type CheckContext, certExpiry, Findings, httpsGet, isNonPublicIp, mapLimit, ref, result } from './util.ts';

const SRV_NAMES = ['_submissions._tcp', '_submission._tcp', '_imaps._tcp', '_imap._tcp'];

/** Connects to an IMAP server over implicit TLS (993) and reads its greeting. */
function probeImap(host: string, ip: string, port: number, timeoutMs: number, now: Date): Promise<ServiceProbe> {
  const out: ServiceProbe = {
    service: 'imap',
    host,
    port,
    tlsMode: 'implicit',
    connected: false,
    banner: null,
    authBeforeTls: [],
    tls: null,
    error: null,
  };
  return new Promise((resolve) => {
    let sock: TLSSocket | null = null;
    const finish = (err?: Error) => {
      if (err && !out.error) out.error = err.message;
      clearTimeout(timer);
      sock?.end('a1 LOGOUT\r\n');
      setTimeout(() => sock?.destroy(), 200).unref();
      resolve(out);
    };
    const timer = setTimeout(
      () => finish(new Error(`no greeting within ${Math.round(timeoutMs / 1000)} s`)),
      timeoutMs,
    );
    sock = tlsConnect({ host: ip, port, servername: host, ...LENIENT_TLS });
    sock.once('secureConnect', () => {
      out.connected = true;
      out.tls = tlsInfoOf(sock!, host, now);
    });
    sock.once('data', (d: Buffer) => {
      out.banner = d.toString('latin1').split('\r\n')[0]!.slice(0, 200);
      finish();
    });
    sock.once('error', (e) => finish(e));
    sock.once('close', () => finish(new Error('connection closed')));
  });
}

function serviceFindings(ctx: CheckContext, f: Findings, p: ServiceProbe) {
  const what = p.service === 'submission' ? 'submission server' : 'IMAP server';
  const subject = `${p.host}:${p.port}`;
  if (!p.connected || !p.tls) {
    f.warning(
      `senders.${p.service}-unreachable`,
      `The ${what} ${subject} could not be checked`,
      `${p.error ?? 'no TLS connection'}.`,
      { subject, refs: [ref('rfc8314', '3')] },
    );
    return;
  }
  const proto = p.tls.protocol ?? '';
  if (proto === 'TLSv1' || proto === 'TLSv1.1' || proto.startsWith('SSL')) {
    f.error(
      `senders.${p.service}-old-tls`,
      `The ${what} ${subject} negotiates ${proto}`,
      'TLS 1.0 and 1.1 must not be used; enable TLS 1.2 and 1.3.',
      { subject, refs: [ref('rfc8996'), ref('rfc8314', '4.1')] },
    );
  }
  if (!p.tls.authorized || !p.tls.hostnameMatch) {
    f.error(
      `senders.${p.service}-cert`,
      `The ${what} ${subject} has no valid certificate for its name`,
      `${p.tls.authorizationError ?? `the certificate does not name ${p.host}`}. Mail clients warn or refuse to connect, and users learn to click warnings away.`,
      { subject, refs: [ref('rfc8314', '4.1'), ref('rfc9525')] },
    );
  }
  if (p.tls.chain[0]) certExpiry(f, `senders.${p.service}`, p.tls.chain[0], ctx.cfg.certWarnDays, subject, `${p.host}`);
  if (p.authBeforeTls.length) {
    f.error(
      'senders.auth-before-tls',
      `The submission server offers ${p.authBeforeTls.join(', ')} before STARTTLS`,
      'Clients may send the password unencrypted. Offer AUTH only after STARTTLS, or use implicit TLS on port 465.',
      { subject, refs: [ref('rfc8314', '3.3'), ref('rfc4954', '4')] },
    );
  }
  if (
    p.service === 'submission' &&
    p.tlsMode === 'starttls' &&
    !f.list.some((x) => x.subject === subject && x.level !== 'ok')
  ) {
    f.info(
      'senders.submission-starttls',
      `Submission on ${subject} uses STARTTLS`,
      'Implicit TLS on port 465 is preferred over STARTTLS on 587: no plaintext phase that can be stripped.',
      {
        subject,
        refs: [ref('rfc8314', '3.3')],
      },
    );
  }
  if (!f.list.some((x) => x.subject === subject && (x.level === 'warning' || x.level === 'error'))) {
    f.ok(
      `senders.${p.service}-ok`,
      `The ${what} ${subject}: ${proto}, valid certificate`,
      `Valid until ${p.tls.chain[0]?.validTo.slice(0, 10) ?? '?'}.`,
      { subject, refs: [ref('rfc8314')] },
    );
  }
}

async function addressOf(ctx: CheckContext, host: string): Promise<string | null> {
  const a = await ctx.dns.addresses(host);
  return a.ips.find((ip) => !ip.includes(':')) ?? a.ips[0] ?? null;
}

export async function checkSenders(ctx: CheckContext): Promise<CheckResult<SendersData>> {
  const started = performance.now();
  const f = new Findings();
  const { dns, domain, known } = ctx;
  const envelopeDomain = domain.from?.split('@').pop()?.toLowerCase() ?? domain.name;
  const sender = domain.from ?? `postmaster@${domain.name}`;
  const data: SendersData = { envelopeDomain, ips: [], services: [], srv: [], autoconfig: null, requirements: [] };

  // --- Sending IPs: configured ones and those seen by recipients of the delivery tests ---
  const sources = new Map<string, Set<string>>();
  const add = (ip: string, src: string) => {
    if (isNonPublicIp(ip)) return;
    if (!sources.has(ip)) sources.set(ip, new Set());
    sources.get(ip)!.add(src);
  };
  for (const ip of domain.senderIps) add(ip, 'configured');
  for (const ip of known.probeIps) add(ip, 'delivery tests');
  data.ips = await mapLimit([...sources], 4, async ([ip, src]): Promise<SenderIp> => {
    const [rev, spf] = await Promise.all([
      dns.reverse(ip),
      checkHost(dns, ip, envelopeDomain, sender, ctx.cfg.heloName),
    ]);
    return { ip, sources: [...src].sort(), ptr: rev.ptr, fcrdns: rev.fcrdns, spf: spf.result, spfDetail: spf.detail };
  });
  for (const s of data.ips) {
    const subject = s.ip;
    if (s.fcrdns === false && !s.ptr) {
      f.error(
        'senders.no-ptr',
        `Sending IP ${s.ip} has no reverse DNS`,
        'Gmail, Yahoo and Microsoft require a PTR record for sending IPs and reject or spam-folder mail without one. Ask the provider of the IP to set one.',
        {
          subject,
          refs: [ref('gmail-senders'), ref('rfc1912', '2.1')],
        },
      );
    } else if (s.fcrdns === false) {
      f.error(
        'senders.no-fcrdns',
        `Reverse DNS of sending IP ${s.ip} does not resolve back`,
        `${s.ip} points to ${s.ptr}, which does not resolve to ${s.ip}. Gmail requires forward-confirmed reverse DNS for senders.`,
        {
          subject,
          refs: [ref('gmail-senders'), ref('rfc1912', '2.1')],
        },
      );
    }
    const spfRefs = [ref('rfc7208', '2.6')];
    if (s.spf === 'fail' || s.spf === 'permerror') {
      f.error(
        'senders.spf-fail',
        `SPF of ${envelopeDomain} does not allow ${s.ip} (${s.spf})`,
        `${s.spfDetail}. Mail from this IP fails SPF; add it (or its provider's include) to the SPF record.`,
        { subject, refs: spfRefs },
      );
    } else if (s.spf === 'softfail' || s.spf === 'neutral' || s.spf === 'none') {
      f.warning(
        'senders.spf-not-pass',
        `SPF of ${envelopeDomain} does not authorise ${s.ip} (${s.spf})`,
        `${s.spfDetail}. DMARC then depends on DKIM alone for this IP.`,
        { subject, refs: spfRefs },
      );
    } else if (s.spf === 'temperror') {
      f.warning('senders.spf-lookup-failed', `Could not evaluate SPF for ${s.ip}`, `${s.spfDetail}.`, {
        subject,
        refs: [ref('rfc7208', '2.6.6')],
      });
    }
  }
  if (
    data.ips.length &&
    !f.list.some((x) => x.code.startsWith('senders.') && (x.level === 'error' || x.level === 'warning'))
  ) {
    f.ok(
      'senders.ips-ok',
      `${data.ips.length} sending IP${data.ips.length === 1 ? '' : 's'}: reverse DNS and SPF pass`,
      data.ips.map((s) => `${s.ip} (${s.ptr})`).join(', '),
      {
        refs: [ref('rfc7208'), ref('gmail-senders')],
      },
    );
  }

  // --- The domain's own servers ---
  if (domain.submission) {
    const s = domain.submission;
    const ip = await addressOf(ctx, s.host);
    if (!ip) {
      data.services.push({
        service: 'submission',
        host: s.host,
        port: s.port,
        tlsMode: s.secure ? 'implicit' : 'starttls',
        connected: false,
        banner: null,
        authBeforeTls: [],
        tls: null,
        error: `${s.host} does not resolve`,
      });
    } else {
      const p = await probeSmtp(s.host, ip, {
        heloName: ctx.cfg.heloName,
        timeoutMs: ctx.cfg.smtpTimeoutMs,
        port: s.port,
        now: ctx.now,
        implicitTls: s.secure,
      });
      data.services.push({
        service: 'submission',
        host: s.host,
        port: s.port,
        tlsMode: s.secure ? 'implicit' : 'starttls',
        connected: p.connected,
        banner: p.banner,
        authBeforeTls: (p.extensionsBeforeTls ?? [])
          .filter((e) => e.startsWith('AUTH'))
          .flatMap((e) => e.split(/[\s=]+/).slice(1))
          .filter((m) => ['PLAIN', 'LOGIN'].includes(m)),
        tls: p.tls,
        error: p.error,
      });
    }
  }
  if (domain.imap) {
    const ip = await addressOf(ctx, domain.imap.host);
    data.services.push(
      ip
        ? await probeImap(domain.imap.host, ip, domain.imap.port, ctx.cfg.smtpTimeoutMs, ctx.now)
        : {
            service: 'imap',
            host: domain.imap.host,
            port: domain.imap.port,
            tlsMode: 'implicit',
            connected: false,
            banner: null,
            authBeforeTls: [],
            tls: null,
            error: `${domain.imap.host} does not resolve`,
          },
    );
  }
  for (const p of data.services) serviceFindings(ctx, f, p);

  // --- Client autoconfiguration (RFC 6186 SRV, RFC 8314 §5.1; Thunderbird autoconfig) ---
  data.srv = await Promise.all(
    SRV_NAMES.map(async (n): Promise<SrvTarget> => {
      const r = await dns.query<{ target: string; port: number }>(`${n}.${domain.name}`, 'SRV');
      const rec = answered(r) ? r.records[0] : undefined;
      return {
        name: `${n}.${domain.name}`,
        target: rec ? rec.target.replace(/\.$/, '') || '.' : null,
        port: rec?.port ?? null,
        found: Boolean(rec),
      };
    }),
  );
  if (domain.submission || domain.imap) {
    try {
      const url = `https://autoconfig.${domain.name}/mail/config-v1.1.xml`;
      const res = await httpsGet(url, dns, ctx.cfg.httpTimeoutMs, 128 * 1024);
      data.autoconfig = { url, status: res.status, error: null };
    } catch (e) {
      data.autoconfig = {
        url: `https://autoconfig.${domain.name}/mail/config-v1.1.xml`,
        status: null,
        error: (e as Error).message,
      };
    }
    if (!data.srv.some((s) => s.found) && data.autoconfig.status !== 200) {
      f.info(
        'senders.no-autoconfig',
        'Mail clients cannot configure themselves',
        `No SRV records (_submissions._tcp, _imaps._tcp, …) and no autoconfig file. Publish them so that clients find ${domain.submission?.host ?? domain.imap?.host} by themselves.`,
        { refs: [ref('rfc6186', '3'), ref('rfc8314', '5.1')] },
      );
    }
    if (domain.submission) {
      const sub =
        data.srv.find((s) => s.name.startsWith('_submissions.') && s.found) ??
        data.srv.find((s) => s.name.startsWith('_submission.') && s.found);
      if (sub && sub.target !== '.' && sub.target !== domain.submission.host.toLowerCase()) {
        f.info(
          'senders.srv-other-host',
          `${sub.name} points to ${sub.target}`,
          `Delivery tests use ${domain.submission.host}. Clients configuring themselves get the SRV target instead.`,
          {
            refs: [ref('rfc6186', '3')],
          },
        );
      }
    }
  }

  // --- Gmail / Yahoo sender requirements (2024) ---
  data.requirements = requirements(ctx, data);
  const unmet = data.requirements.filter((r) => r.status === 'fail');
  // Spam rate and unsubscribe handling are never visible from here; they do not make it "unknown".
  const unknown = data.requirements.filter((r) => r.status === 'unknown' && r.id !== 'spam-rate');
  if (data.ips.length || known.probeResults?.length) {
    const refs = [ref('gmail-senders'), ref('yahoo-senders')];
    if (unmet.length) {
      f.info(
        'senders.requirements',
        `${unmet.length} Gmail/Yahoo sender requirement${unmet.length === 1 ? '' : 's'} not met`,
        `${unmet.map((r) => r.label).join('; ')}. The individual problems are reported (and alerted) by their own checks.`,
        { refs },
      );
    } else if (unknown.length) {
      f.info(
        'senders.requirements',
        'No Gmail/Yahoo sender requirement is known to be unmet',
        `Not verifiable yet: ${unknown.map((r) => r.label).join('; ')}. Delivery tests (DOMAIN_n_SMTP… and RECIPIENT_n) show what receivers see.`,
        { refs },
      );
    } else {
      f.ok(
        'senders.requirements',
        'Gmail and Yahoo sender requirements met',
        'As far as MailWatch can see: authentication, reverse DNS, TLS and DMARC. Spam rate and unsubscribe handling cannot be checked from here.',
        { refs },
      );
    }
  } else {
    f.info(
      'senders.unknown',
      'No sending IPs known yet',
      'Configure DOMAIN_n_SENDER_IPS, or delivery tests (DOMAIN_n_SMTP…), to check the IPs this domain sends from.',
    );
  }
  return result(ctx, 'senders', started, f, data);
}

function requirements(ctx: CheckContext, data: SendersData): SenderRequirement[] {
  const spf = ctx.current.get('spf')?.data as SpfData | undefined;
  const dmarc = ctx.current.get('dmarc')?.data as DmarcData | undefined;
  const probes = ctx.known.probeResults ?? [];
  const seen = (pick: (a: NonNullable<(typeof probes)[number]['auth']>) => string | boolean | null | undefined) =>
    probes.map((p) => (p.auth ? pick(p.auth) : null)).filter((x) => x !== null && x !== undefined);
  const recipients = probes.map((p) => p.recipient).join(', ');
  const spfAt = seen((a) => a.spf);
  const dkimAt = seen((a) => a.dkim);
  const dmarcAt = seen((a) => a.dmarc);
  const tlsAt = seen((a) => a.tls);
  const allPass = (xs: (string | boolean)[]) => xs.length > 0 && xs.every((x) => x === 'pass');
  const status = (ok: boolean | null): SenderRequirement['status'] => (ok === null ? 'unknown' : ok ? 'ok' : 'fail');
  const fromProbes = (xs: (string | boolean)[], what: string) =>
    xs.length ? `${what} at ${recipients}: ${xs.join(', ')}` : 'no delivery test result yet';

  // What receivers saw wins; otherwise SPF for the known sending IPs. DKIM cannot be judged
  // from DNS alone (selectors are not listable), so without delivery tests it stays unknown.
  const ipSpf = data.ips.map((s) => s.spf).filter((x): x is string => x !== null && x !== 'temperror');
  const spfOk = spfAt.length ? allPass(spfAt) : !spf?.record ? false : ipSpf.length ? allPass(ipSpf) : null;
  const dkimOk = dkimAt.length ? allPass(dkimAt) : null;
  const fcrdnsKnown = data.ips.filter((s) => s.fcrdns !== null);
  return [
    {
      id: 'auth',
      label: 'SPF or DKIM passes',
      scope: 'all',
      status: status(spfOk === true || dkimOk === true ? true : spfOk === false && dkimOk === false ? false : null),
      detail: `SPF: ${spfAt.length || !ipSpf.length ? fromProbes(spfAt, 'spf') : `for the sending IPs: ${ipSpf.join(', ')}`}; DKIM: ${fromProbes(dkimAt, 'dkim')}`,
    },
    {
      id: 'spf-and-dkim',
      label: 'SPF and DKIM both pass',
      scope: 'bulk',
      status: status(spfOk === true && dkimOk === true ? true : spfOk === false || dkimOk === false ? false : null),
      detail: 'Required for bulk senders (5,000+ messages a day to Gmail).',
    },
    {
      id: 'fcrdns',
      label: 'Sending IPs have forward-confirmed reverse DNS',
      scope: 'all',
      status: status(fcrdnsKnown.length ? fcrdnsKnown.every((s) => s.fcrdns) : null),
      detail: data.ips.length ? data.ips.map((s) => `${s.ip}: ${s.ptr ?? 'no PTR'}`).join(', ') : 'no sending IP known',
    },
    {
      id: 'tls',
      label: 'Mail is transmitted over TLS',
      scope: 'all',
      status: status(tlsAt.length ? tlsAt.every((x) => x === true) : null),
      detail: tlsAt.length
        ? `received over TLS at ${recipients}: ${tlsAt.map((x) => (x ? 'yes' : 'no')).join(', ')}`
        : 'no delivery test with a Received header yet',
    },
    {
      id: 'dmarc',
      label: 'A DMARC policy is published (p=none or stricter)',
      scope: 'bulk',
      status: status(dmarc ? Boolean(dmarc.record && dmarc.tags.p) : null),
      detail: dmarc?.record ?? 'no DMARC record',
    },
    {
      id: 'alignment',
      label: 'The From: domain is aligned (DMARC passes)',
      scope: 'bulk',
      status: status(dmarcAt.length ? allPass(dmarcAt) : null),
      detail: fromProbes(dmarcAt, 'dmarc'),
    },
    {
      id: 'unsubscribe',
      label: 'Marketing mail has one-click unsubscribe',
      scope: 'bulk',
      status: 'n/a',
      detail:
        'List-Unsubscribe-Post (RFC 8058) on marketing and subscribed mail; MailWatch does not see those messages.',
    },
    {
      id: 'spam-rate',
      label: 'Spam complaint rate below 0.3 %',
      scope: 'all',
      status: 'unknown',
      detail: 'Visible in Google Postmaster Tools and Yahoo Sender Hub, not from here.',
    },
  ];
}
