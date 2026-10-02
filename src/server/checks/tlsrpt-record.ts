// The TLS-RPT policy record (RFC 8460 §3): where senders send their SMTP TLS reports.
import type { CheckResult, MtaStsData, TlsRptData } from '../../shared/types.ts';
import { parseUris } from './dmarc.ts';
import { type CheckContext, Findings, parseTags, prefixedTxt, ref, result } from './util.ts';

const RPT_RE = /^v\s*=\s*TLSRPTv1\s*(;|$)/i;

export async function checkTlsRpt(ctx: CheckContext): Promise<CheckResult<TlsRptData>> {
  const started = performance.now();
  const f = new Findings();
  const { dns, domain } = ctx;
  const data: TlsRptData = { record: null, records: [], rua: [] };
  const done = () => result(ctx, 'tls-rpt', started, f, data);

  const sel = await prefixedTxt(dns, `_smtp._tls.${domain.name}`, RPT_RE);
  if (sel.failed) {
    f.lookupFailed('tls-rpt.lookup-failed', 'the TLS-RPT record', sel.result);
    return done();
  }
  data.records = sel.matching;
  const sts = ctx.current.get('mta-sts')?.data as MtaStsData | undefined;
  const hasPolicy = Boolean(sts?.record) || (ctx.mx?.dnssec ?? false);
  if (!sel.matching.length) {
    f.add(
      sts?.record ? 'warning' : 'info',
      'tls-rpt.missing',
      'No TLS-RPT record',
      sts?.record
        ? 'MTA-STS is deployed, but without _smtp._tls you never hear about senders that fail to deliver over TLS. Publish "v=TLSRPTv1; rua=mailto:…".'
        : `Publish _smtp._tls.${domain.name} "v=TLSRPTv1; rua=mailto:…" to receive daily reports on TLS failures when senders deliver to you.`,
      { refs: [ref('rfc8460', '3')] },
    );
    return done();
  }
  if (sel.matching.length > 1) {
    f.error(
      'tls-rpt.multiple',
      `${sel.matching.length} TLS-RPT records`,
      'With more than one record, senders send no reports. Keep exactly one.',
      {
        refs: [ref('rfc8460', '3')],
      },
    );
    return done();
  }
  const record = sel.matching[0]!;
  data.record = record;
  const { tags, errors } = parseTags(record);
  for (const e of errors) f.error('tls-rpt.syntax', 'Malformed TLS-RPT record', e, { refs: [ref('rfc8460', '3')] });
  const rua = parseUris(tags.rua, ctx.known.monitoredAddresses);
  data.rua = rua.uris;
  for (const u of rua.uris.filter((x) => x.problem)) {
    f.warning(
      'tls-rpt.invalid-uri',
      `Invalid report destination "${u.uri}"`,
      `${u.problem![0]!.toUpperCase()}${u.problem!.slice(1)}. Senders ignore this destination, so it gets no reports.`,
      { subject: u.uri, refs: [ref('rfc8460', '3')] },
    );
  }
  if (rua.uris.length && rua.uris.every((x) => x.problem)) {
    f.error(
      'tls-rpt.no-valid-rua',
      'No usable report destination',
      'Every rua= destination is invalid, so no TLS reports are sent.',
      {
        refs: [ref('rfc8460', '3')],
      },
    );
  }
  if (!tags.rua) {
    f.error('tls-rpt.no-rua', 'The TLS-RPT record has no rua=', 'rua= (mailto: or https:) is required.', {
      refs: [ref('rfc8460', '3')],
    });
  }
  for (const u of rua.uris) {
    if (!u.problem && u.scheme !== 'mailto' && u.scheme !== 'https') {
      f.error('tls-rpt.bad-scheme', `Unsupported destination "${u.uri}"`, 'Only mailto: and https: are defined.', {
        refs: [ref('rfc8460', '3')],
      });
    }
  }
  if (rua.uris.length && !rua.uris.some((u) => u.monitored)) {
    f.info(
      'tls-rpt.unmonitored',
      'MailWatch does not read the TLS report mailbox',
      `Reports go to ${rua.uris.map((u) => u.address ?? u.uri).join(', ')}. Configure that mailbox as MAILBOX_n to analyse them on the TLS-RPT tab.`,
    );
  }
  if (!hasPolicy) {
    f.info(
      'tls-rpt.no-policy',
      'TLS-RPT without MTA-STS or DANE',
      'Reports are most useful with a policy; without one, senders report "no-policy-found".',
      {
        refs: [ref('rfc8460', '4.3')],
      },
    );
  }
  if (!f.list.some((x) => x.level === 'error' || x.level === 'warning')) {
    f.ok('tls-rpt.ok', 'TLS-RPT record found', record, { refs: [ref('rfc8460', '3')] });
  }
  return done();
}
