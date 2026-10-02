// BIMI (draft-brand-indicators-for-message-identification): the default._bimi record, the logo,
// the mark certificate, and the DMARC enforcement BIMI requires.
import type { BimiData, CheckResult, DmarcData } from '../../shared/types.ts';
import { type CheckContext, Findings, httpsGet, parseTags, prefixedTxt, ref, result } from './util.ts';

const BIMI_RE = /^v\s*=\s*BIMI1\s*(;|$)/i;
/** Logos larger than this are refused by some mailbox providers. */
const LOGO_MAX_BYTES = 32 * 1024;

export async function checkBimi(ctx: CheckContext): Promise<CheckResult<BimiData>> {
  const started = performance.now();
  const f = new Findings();
  const { dns, domain } = ctx;
  const data: BimiData = { record: null, records: [], tags: {}, logo: null, authority: null };
  const done = () => result(ctx, 'bimi', started, f, data);

  const sel = await prefixedTxt(dns, `default._bimi.${domain.name}`, BIMI_RE);
  if (sel.failed) {
    f.lookupFailed('bimi.lookup-failed', 'the BIMI record', sel.result);
    return done();
  }
  data.records = sel.matching;
  if (!sel.matching.length) {
    f.info(
      'bimi.missing',
      'BIMI is not set up',
      'Optional: BIMI shows your logo next to authenticated mail in supporting mailboxes. It requires DMARC enforcement.',
      {
        refs: [ref('bimi')],
      },
    );
    return done();
  }
  if (sel.matching.length > 1) {
    f.error('bimi.multiple', `${sel.matching.length} BIMI records`, 'Publish exactly one record at default._bimi.', {
      refs: [ref('bimi')],
    });
    return done();
  }
  const record = sel.matching[0]!;
  data.record = record;
  const { tags, errors } = parseTags(record);
  data.tags = tags;
  for (const e of errors) f.error('bimi.syntax', 'Malformed BIMI record', e, { refs: [ref('bimi')] });

  // BIMI only applies to mail under an enforcing DMARC policy (quarantine or reject, at 100%).
  const dmarc = ctx.current.get('dmarc')?.data as DmarcData | undefined;
  const p = (dmarc?.inherited ? (dmarc.tags.sp ?? dmarc.tags.p) : dmarc?.tags.p)?.toLowerCase();
  const pct = dmarc?.tags.pct ?? '100';
  if (!dmarc?.record || !p || p === 'none' || pct !== '100') {
    f.error(
      'bimi.dmarc-not-enforced',
      'BIMI requires an enforcing DMARC policy',
      `Mailbox providers ignore BIMI unless DMARC is p=quarantine or p=reject at pct=100 (currently ${dmarc?.record ? `p=${p ?? '?'}, pct=${pct}` : 'no DMARC record'}).`,
      { refs: [ref('bimi'), ref('rfc7489', '6.3')] },
    );
  }

  const l = tags.l ?? '';
  const a = tags.a ?? '';
  if (!l && !a) {
    f.info('bimi.declined', 'The record declines BIMI', 'Empty l= and a= tell providers not to show a logo.', {
      refs: [ref('bimi')],
    });
    return done();
  }
  if (l) {
    data.logo = { url: l, status: null, contentType: null, bytes: null, error: null };
    if (!l.startsWith('https://')) {
      data.logo.error = 'not an https:// URL';
      f.error('bimi.logo-url', 'The logo URL is not https://', l, { refs: [ref('bimi')] });
    } else {
      try {
        const res = await httpsGet(l, ctx.cfg.httpTimeoutMs, 512 * 1024);
        Object.assign(data.logo, { status: res.status, contentType: res.contentType, bytes: res.bytes });
        if (!res.authorized)
          f.error('bimi.logo-cert', 'The logo host’s certificate is not valid', String(res.authorizationError), {
            refs: [ref('bimi')],
          });
        if (res.status !== 200) {
          f.error('bimi.logo-http', `The logo URL returns HTTP ${res.status}`, l, { refs: [ref('bimi')] });
        } else {
          const ct = (res.contentType ?? '').split(';')[0]!.trim().toLowerCase();
          if (ct !== 'image/svg+xml' || !/<svg[\s>]/i.test(res.body)) {
            f.error(
              'bimi.logo-format',
              'The logo is not an SVG image',
              `Content type "${res.contentType ?? 'none'}". BIMI logos must be SVG Tiny Portable/Secure.`,
              {
                refs: [ref('bimi')],
              },
            );
          } else if (!/baseProfile\s*=\s*["']tiny-ps["']/i.test(res.body)) {
            f.warning(
              'bimi.logo-profile',
              'The SVG is not SVG Tiny PS',
              'BIMI requires the SVG Tiny Portable/Secure profile (baseProfile="tiny-ps"); providers reject other SVGs.',
              {
                refs: [ref('bimi')],
              },
            );
          }
          if (/<script[\s>]/i.test(res.body)) {
            f.error('bimi.logo-script', 'The SVG contains scripts', 'SVG Tiny PS forbids scripts.', {
              refs: [ref('bimi')],
            });
          }
          if (res.bytes > LOGO_MAX_BYTES) {
            f.warning('bimi.logo-size', `The logo is ${Math.round(res.bytes / 1024)} KB`, 'Keep it under 32 KB.', {
              refs: [ref('bimi')],
            });
          }
        }
      } catch (e) {
        data.logo.error = (e as Error).message;
        f.error('bimi.logo-fetch', 'The logo cannot be fetched', `${l}: ${data.logo.error}`, { refs: [ref('bimi')] });
      }
    }
  }
  if (a) {
    data.authority = { url: a, status: null, error: null };
    try {
      const res = await httpsGet(a, ctx.cfg.httpTimeoutMs, 256 * 1024);
      data.authority.status = res.status;
      if (res.status !== 200 || !res.body.includes('-----BEGIN CERTIFICATE-----')) {
        f.error(
          'bimi.vmc',
          'The mark certificate (a=) cannot be used',
          `HTTP ${res.status}; expected a PEM certificate chain.`,
          { refs: [ref('bimi')] },
        );
      }
    } catch (e) {
      data.authority.error = (e as Error).message;
      f.error('bimi.vmc-fetch', 'The mark certificate cannot be fetched', `${a}: ${data.authority.error}`, {
        refs: [ref('bimi')],
      });
    }
  } else {
    f.info(
      'bimi.no-vmc',
      'No mark certificate (a=)',
      'Gmail and Apple Mail only show logos backed by a Verified Mark Certificate (VMC) or Common Mark Certificate (CMC).',
      {
        refs: [ref('bimi')],
      },
    );
  }
  if (!f.list.some((x) => x.level === 'error' || x.level === 'warning')) {
    f.ok('bimi.ok', 'BIMI record and logo are valid', record, { refs: [ref('bimi')] });
  }
  return done();
}
