// DANE for SMTP (RFC 7672): DNSSEC on the MX records, TLSA records at _25._tcp.<mx>, and whether
// they match the certificates the MX hosts present (RFC 6698 §2.1).
import type { CertInfo, CheckResult, DaneData, DaneHost, SmtpProbe, TlsaRecord } from '../../shared/types.ts';
import { answered } from '../dns.ts';
import { type CheckContext, Findings, ref, result } from './util.ts';

const USAGES: Record<number, string> = { 0: 'PKIX-TA', 1: 'PKIX-EE', 2: 'DANE-TA', 3: 'DANE-EE' };

/** Does a TLSA record match a certificate (selector 0 = full cert, 1 = SPKI; matching 0/1/2)? */
export function tlsaMatchesCert(t: Pick<TlsaRecord, 'selector' | 'matchingType' | 'data'>, c: CertInfo): boolean {
  const data = t.data.toLowerCase();
  if (t.selector === 0) {
    if (t.matchingType === 0) return data === c.certDer;
    if (t.matchingType === 1) return data === c.certSha256;
    if (t.matchingType === 2) return data === c.certSha512;
  } else if (t.selector === 1) {
    if (t.matchingType === 0) return data === c.spkiDer;
    if (t.matchingType === 1) return data === c.spkiSha256;
    if (t.matchingType === 2) return data === c.spkiSha512;
  }
  return false;
}

/** RFC 7672 §3.1: DANE-EE matches the leaf; DANE-TA matches a certificate above it in the chain. */
export function tlsaMatchesProbe(t: TlsaRecord, p: SmtpProbe): boolean {
  const chain = p.tls?.chain ?? [];
  if (!chain.length) return false;
  if (t.usage === 3) return tlsaMatchesCert(t, chain[0]!);
  if (t.usage === 2) return chain.slice(1).some((c) => tlsaMatchesCert(t, c)) && p.tls!.hostnameMatch;
  return false;
}

export async function checkDane(ctx: CheckContext): Promise<CheckResult<DaneData>> {
  const started = performance.now();
  const f = new Findings();
  const { dns, domain } = ctx;
  const mx = ctx.mx;
  const soa = await dns.query(domain.name, 'SOA');
  const data: DaneData = { mxSecure: mx?.dnssec ?? false, zoneSigned: answered(soa) && soa.secure, hosts: [] };
  const done = () => result(ctx, 'dane', started, f, data);

  if (!data.zoneSigned) {
    f.info(
      'dane.no-dnssec',
      'The domain is not signed with DNSSEC',
      'DANE needs DNSSEC on the domain and on the MX hosts’ zones. Without it, use MTA-STS to protect inbound TLS.',
      { refs: [ref('rfc4033'), ref('rfc7672', '2.2')] },
    );
  } else {
    f.ok('dane.dnssec', 'The domain is signed with DNSSEC', 'Answers for the domain validate.', {
      refs: [ref('rfc4033')],
    });
  }
  if (!mx || !mx.records.length || mx.nullMx) return done();

  data.hosts = await Promise.all(
    mx.records.map(async (r): Promise<DaneHost> => {
      const [tlsa, addr] = await Promise.all([dns.tlsa(`_25._tcp.${r.exchange}`), dns.addresses(r.exchange)]);
      const probes = mx.smtp.filter((p) => p.host === r.exchange && p.tls);
      const records: TlsaRecord[] = tlsa.records.map((t) => {
        const rec: TlsaRecord = {
          usage: t.usage,
          selector: t.selector,
          matchingType: t.matchingType,
          data: Buffer.from(t.data).toString('hex'),
          matched: null,
        };
        if (probes.length) rec.matched = probes.some((p) => tlsaMatchesProbe(rec, p));
        return rec;
      });
      // Every address must match some usable record (they may present different certificates).
      const usable = records.filter((t) => t.usage === 2 || t.usage === 3);
      const unmatchedIps = probes.filter((p) => !usable.some((t) => tlsaMatchesProbe(t, p))).map((p) => p.ip);
      return {
        mx: r.exchange,
        addressSecure: addr.secure,
        tlsa: records,
        tlsaSecure: tlsa.secure,
        tlsaFailed: answered(tlsa) ? null : tlsa.rcode,
        probed: probes.length > 0,
        unmatchedIps,
      };
    }),
  );

  for (const h of data.hosts.filter((x) => x.tlsaFailed)) {
    f.error(
      'dane.tlsa-servfail',
      `The TLSA lookup for ${h.mx} fails (${h.tlsaFailed})`,
      `_25._tcp.${h.mx} does not resolve. Senders that use DANE cannot tell whether TLSA records exist and defer delivery to this MX until the lookup works again (often a DNSSEC problem in the MX host's zone).`,
      { subject: h.mx, refs: [ref('rfc7672', '2.2')] },
    );
  }
  const withTlsa = data.hosts.filter((h) => h.tlsa.length);
  if (!withTlsa.length) {
    if (data.zoneSigned && data.mxSecure) {
      f.info(
        'dane.not-deployed',
        'No TLSA records for the MX hosts',
        'The MX records are DNSSEC-signed, so DANE is possible: publish "3 1 1" TLSA records at _25._tcp.<mx> (in the MX hosts’ zones).',
        { refs: [ref('rfc7672', '2.2'), ref('rfc7671', '5.1')] },
      );
    }
    return done();
  }
  if (!data.mxSecure) {
    f.error(
      'dane.mx-insecure',
      'TLSA records exist, but the MX records are not DNSSEC-validated',
      'Senders only use DANE when the MX lookup validates; sign the domain (and publish the DS record at the parent).',
      { refs: [ref('rfc7672', '2.2.1')] },
    );
  }
  for (const h of data.hosts) {
    const subject = h.mx;
    if (h.tlsaFailed) continue; // reported above
    if (!h.tlsa.length) {
      f.warning(
        'dane.partial',
        `MX ${h.mx} has no TLSA records`,
        'Other MX hosts use DANE; mail delivered to this one is not protected by it.',
        {
          subject,
          refs: [ref('rfc7672', '2.2')],
        },
      );
      continue;
    }
    if (!h.tlsaSecure) {
      f.error(
        'dane.tlsa-insecure',
        `TLSA records for ${h.mx} are not DNSSEC-validated`,
        'Senders ignore unsigned TLSA records.',
        {
          subject,
          refs: [ref('rfc7672', '2.2')],
        },
      );
    }
    if (!h.addressSecure) {
      f.warning(
        'dane.address-insecure',
        `The address records of ${h.mx} are not DNSSEC-validated`,
        'RFC 7672 expects the MX host’s addresses to be secure as well.',
        {
          subject,
          refs: [ref('rfc7672', '2.2.2')],
        },
      );
    }
    for (const t of h.tlsa) {
      const label = `${t.usage} ${t.selector} ${t.matchingType}`;
      if (t.usage === 0 || t.usage === 1) {
        f.warning(
          'dane.pkix-usage',
          `TLSA ${label} for ${h.mx} uses ${USAGES[t.usage]}`,
          'SMTP senders treat PKIX-TA(0) and PKIX-EE(1) records as unusable. Use DANE-EE(3) or DANE-TA(2).',
          {
            subject,
            refs: [ref('rfc7672', '3.1.3')],
          },
        );
      } else if (!(t.usage in USAGES) || t.selector > 1 || t.matchingType > 2) {
        f.error(
          'dane.invalid',
          `TLSA ${label} for ${h.mx} is not a valid combination`,
          'Usage 0–3, selector 0–1 and matching type 0–2 are defined.',
          {
            subject,
            refs: [ref('rfc6698', '2.1')],
          },
        );
      } else if (t.matchingType === 0) {
        f.info(
          'dane.full-match',
          `TLSA ${label} for ${h.mx} publishes the full data`,
          'SHA-256 digests (matching type 1) are recommended.',
          {
            subject,
            refs: [ref('rfc7671', '10.1.2')],
          },
        );
      }
    }
    if (h.probed) {
      const usable = h.tlsa.filter((t) => t.usage === 2 || t.usage === 3);
      if (usable.length && h.unmatchedIps?.length) {
        f.error(
          'dane.mismatch',
          `No TLSA record of ${h.mx} matches its certificate${h.unmatchedIps.length > 1 || !usable.some((t) => t.matched) ? '' : ` at ${h.unmatchedIps[0]}`}`,
          'Senders that use DANE do not deliver to this MX. Publish a TLSA record for the current certificate (and the next one before rolling the key).',
          { subject, refs: [ref('rfc7672', '3.1'), ref('rfc6698', '2.1')] },
        );
      } else if (usable.some((t) => t.matched)) {
        const unmatched = usable.filter((t) => !t.matched).length;
        f.ok(
          'dane.match',
          `${h.mx}: the certificate matches its TLSA record`,
          `${usable.length} usable TLSA record${usable.length === 1 ? '' : 's'}${unmatched ? `, ${unmatched} for another key (e.g. the next one)` : ''}.`,
          {
            subject,
            refs: [ref('rfc7672', '3.1')],
          },
        );
        if (usable.length === 1 && usable[0]!.usage === 3) {
          f.info(
            'dane.single-record',
            `${h.mx} has a single DANE-EE record`,
            'Publish the next key’s record ahead of a certificate change so that delivery does not break during the rollover.',
            {
              subject,
              refs: [ref('rfc7671', '8.1')],
            },
          );
        }
      }
    }
  }
  return done();
}
