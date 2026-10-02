// DANE for SMTP (RFC 7672): DNSSEC on the MX records, TLSA records at _25._tcp.<mx>, and whether
// they match the certificates the MX hosts present (RFC 6698 §2.1).
import type {
  CertInfo,
  CheckResult,
  DaneData,
  DaneHost,
  DnssecSignature,
  SmtpProbe,
  TlsaRecord,
} from '../../shared/types.ts';
import { ALGORITHMS, DEPRECATED_ALGORITHMS } from '../../shared/dnssec.ts';
import { answered, type DnsResult, type RrsigRecord } from '../dns.ts';
import { orgDomain } from './dmarc.ts';
import { type DnskeyRecord, type DsRecord, dsMatches, keyTag, signatureUrgency } from './dnssec.ts';
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

function signatureFindings(ctx: CheckContext, f: Findings, data: DaneData, sigs: RrsigRecord[]) {
  const nowS = Math.floor(ctx.now.getTime() / 1000);
  for (const s of sigs) {
    const entry: DnssecSignature = {
      name: s.name,
      type: s.typeCovered,
      signer: s.signersName,
      keyTag: s.keyTag,
      inception: new Date(s.inception * 1000).toISOString(),
      expiration: new Date(s.expiration * 1000).toISOString(),
    };
    data.signatures = [...(data.signatures ?? []), entry];
    const urgency = signatureUrgency(s.inception, s.expiration, nowS, ctx.cfg.dnssecWarnDays);
    if (!urgency) continue;
    const subject = `${s.name} ${s.typeCovered}`;
    const left = Math.max(0, s.expiration - nowS);
    const leftText = left >= 86_400 ? `${Math.floor(left / 86_400)} days` : `${Math.floor(left / 3600)} hours`;
    if (urgency === 'expired') {
      f.error(
        'dane.sig-expired',
        `The DNSSEC signature of ${subject} has expired`,
        `It expired on ${entry.expiration}. Validating resolvers reject the answer (SERVFAIL): the signer (${s.signersName}) stopped re-signing.`,
        {
          subject,
          refs: [ref('rfc4034', '3.1.5'), ref('rfc4035', '5.3.1')],
        },
      );
    } else {
      f.add(
        urgency,
        'dane.sig-expiring',
        `The DNSSEC signature of ${subject} expires in ${leftText}`,
        `Valid until ${entry.expiration}, and it is not being refreshed: check the signer of ${s.signersName}. Once it expires, validating resolvers reject the zone's answers.`,
        { subject, refs: [ref('rfc4034', '3.1.5')] },
      );
    }
  }
}

/** DS ↔ DNSKEY chain, algorithms, and the signatures of the zone's SOA, MX and DNSKEY sets. */
async function dnssecFindings(ctx: CheckContext, f: Findings, data: DaneData, soa: DnsResult<unknown>) {
  const { dns } = ctx;
  const zone = orgDomain(ctx.domain.name);
  data.zone = zone;
  const [keys, ds, mxq] = await Promise.all([
    dns.query<DnskeyRecord>(zone, 'DNSKEY'),
    dns.query<DsRecord>(zone, 'DS'),
    dns.mx(ctx.domain.name),
  ]);
  data.keys = keys.records.map((k) => ({
    keyTag: keyTag(k),
    algorithm: k.algorithm,
    flags: k.flags,
    matchedByDs: ds.records.some((d) => dsMatches(zone, d, k) === true),
  }));
  data.ds = ds.records.map((d) => {
    const results = keys.records.map((k) => dsMatches(zone, d, k));
    return {
      keyTag: d.keyTag,
      algorithm: d.algorithm,
      digestType: d.digestType,
      matches: results.includes(true)
        ? true
        : keys.records.some((k) => keyTag(k) === d.keyTag)
          ? results.includes(null)
            ? null
            : false
          : null,
    };
  });

  if (!keys.records.length) {
    f.info(
      'dane.no-dnssec',
      'The domain is not signed with DNSSEC',
      'DANE needs DNSSEC on the domain and on the MX hosts’ zones. Without it, use MTA-STS to protect inbound TLS.',
      {
        refs: [ref('rfc4033'), ref('rfc7672', '2.2')],
      },
    );
    return;
  }
  if (!ds.records.length) {
    f.info(
      'dane.no-ds',
      'The zone is signed, but the parent has no DS record',
      `${zone} has DNSKEY records, but the registry publishes no DS for it, so resolvers cannot validate the signatures. Publish the DS record through the registrar to enable DNSSEC.`,
      { refs: [ref('rfc4035', '5'), ref('rfc4034', '5')] },
    );
  } else if (!data.ds.some((d) => d.matches === true)) {
    f.error(
      'dane.ds-mismatch',
      'No DS record at the parent matches a key of the zone',
      `DS key tags ${data.ds.map((d) => d.keyTag).join(', ')}; DNSKEY key tags ${data.keys.map((k) => k.keyTag).join(', ')}. Validating resolvers treat the zone as bogus and refuse its answers (SERVFAIL): update the DS through the registrar, or put the old key back.`,
      { refs: [ref('rfc4035', '5'), ref('rfc4034', '5.2')] },
    );
  } else if (!data.zoneSigned) {
    f.warning(
      'dane.not-validating',
      'The DS matches, but answers do not validate',
      'A key and DS match, yet the resolvers do not mark the answers as validated. Check the signatures (expired?) and the chain above the domain.',
      {
        refs: [ref('rfc4035', '5')],
      },
    );
  } else {
    const ksk = data.keys.find((k) => k.matchedByDs);
    f.ok(
      'dane.dnssec',
      'The domain is signed with DNSSEC',
      `DS at the parent matches key ${ksk?.keyTag ?? '?'} (${ALGORITHMS[ksk?.algorithm ?? 0] ?? `algorithm ${ksk?.algorithm}`}); answers validate.`,
      {
        refs: [ref('rfc4033'), ref('rfc4035', '5')],
      },
    );
  }
  const old = [...new Set(data.keys.filter((k) => DEPRECATED_ALGORITHMS.has(k.algorithm)).map((k) => k.algorithm))];
  if (old.length) {
    f.warning(
      'dane.old-algorithm',
      `Deprecated DNSSEC algorithm ${old.map((a) => ALGORITHMS[a] ?? a).join(', ')}`,
      'Validators are dropping support; re-sign the zone with ECDSAP256SHA256 (13) or ED25519 (15), with an algorithm rollover.',
      {
        refs: [ref('rfc8624', '3.1')],
      },
    );
  }
  if (data.ds.length && data.ds.every((d) => d.digestType === 1)) {
    f.warning(
      'dane.sha1-ds',
      'The DS record uses SHA-1 only',
      'Publish a DS with digest type 2 (SHA-256); SHA-1 DS records must not be used.',
      { refs: [ref('rfc8624', '3.3')] },
    );
  }
  // The signer of the zone signs these; the DS set is signed by the parent.
  signatureFindings(ctx, f, data, [...(soa.sigs ?? []), ...(mxq.sigs ?? []), ...(keys.sigs ?? []), ...(ds.sigs ?? [])]);
}

export async function checkDane(ctx: CheckContext): Promise<CheckResult<DaneData>> {
  const started = performance.now();
  const f = new Findings();
  const { dns, domain } = ctx;
  const mx = ctx.mx;
  const soa = await dns.query(orgDomain(domain.name), 'SOA');
  const data: DaneData = { mxSecure: mx?.dnssec ?? false, zoneSigned: answered(soa) && soa.secure, hosts: [] };
  const done = () => result(ctx, 'dane', started, f, data);

  await dnssecFindings(ctx, f, data, soa);
  if (!mx || !mx.records.length || mx.nullMx) return done();

  data.hosts = await Promise.all(
    mx.records.map(async (r): Promise<DaneHost> => {
      // (TLSA signatures are checked below, with the zone's.)
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
  // TLSA records are signed in the MX hosts' zones: their signatures matter for DANE as well.
  const tlsaSigs = (await Promise.all(data.hosts.map((h) => dns.tlsa(`_25._tcp.${h.mx}`)))).flatMap((t) =>
    t.records.length ? (t.sigs ?? []) : [],
  );
  signatureFindings(ctx, f, data, tlsaSigs);
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
