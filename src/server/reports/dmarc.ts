// DMARC aggregate reports (RFC 7489 §7.2 and Appendix C; DMARCbis aggregate reporting).
import { XMLParser } from 'fast-xml-parser';
import { gunzipSync } from 'node:zlib';
import { unzipSync } from 'fflate';
import type { DmarcAuthResult, DmarcPolicyPublished, DmarcRecordRow } from '../../shared/types.ts';

export class DmarcFormatError extends Error {}

export interface NormalizedDmarcReport {
  orgName: string;
  reportId: string;
  email: string | null;
  extraContact: string | null;
  begin: string;
  end: string;
  errors: string[];
  policy: DmarcPolicyPublished;
  records: DmarcRecordRow[];
}

const MAX_XML_BYTES = 50 * 1024 * 1024;

/**
 * Decompresses a report attachment: gzip, zip (the first .xml entry, or the only entry) or
 * plain bytes. Returns the payload as bytes; the caller sniffs JSON (TLS-RPT) or XML (DMARC).
 */
export function decompress(buf: Buffer): Buffer {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    return gunzipSync(buf, { maxOutputLength: MAX_XML_BYTES });
  }
  if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
    let picked: string | null = null;
    const files = unzipSync(new Uint8Array(buf), {
      filter: (f) => {
        if (f.originalSize > MAX_XML_BYTES) return false;
        if (picked === null && (/\.(xml|json)$/i.test(f.name) || !f.name.endsWith('/'))) {
          picked = f.name;
          return true;
        }
        return false;
      },
    });
    const data = picked ? files[picked] : undefined;
    if (!data) throw new DmarcFormatError('the zip archive contains no report');
    return Buffer.from(data);
  }
  return buf;
}

const parser = new XMLParser({
  ignoreAttributes: true,
  removeNSPrefix: true,
  parseTagValue: false,
  trimValues: true,
  processEntities: true,
  isArray: (_name, jpath) =>
    [
      'feedback.record',
      'feedback.record.auth_results.dkim',
      'feedback.record.auth_results.spf',
      'feedback.record.row.policy_evaluated.reason',
      'feedback.report_metadata.error',
    ].includes(String(jpath)),
});

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const s = (v: unknown): string | null => {
  if (typeof v === 'string') return v.trim() || null;
  if (typeof v === 'number') return String(v);
  if (isObj(v) && typeof v['#text'] === 'string') return v['#text'].trim() || null;
  return null;
};
const lower = (v: unknown) => s(v)?.toLowerCase() ?? null;
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined || v === null || v === '' ? [] : [v]);

function epoch(v: unknown, field: string): string {
  const n = Number(s(v));
  if (!Number.isFinite(n) || n <= 0) throw new DmarcFormatError(`invalid or missing ${field}`);
  return new Date(n * 1000).toISOString();
}

/** Parses the XML of an aggregate report into rows. Throws DmarcFormatError on unusable input. */
export function parseAggregate(xml: string): NormalizedDmarcReport {
  let doc: Obj;
  try {
    doc = parser.parse(xml.replace(/^\uFEFF/, '')) as Obj;
  } catch (e) {
    throw new DmarcFormatError(`invalid XML: ${(e as Error).message}`);
  }
  const fb = doc.feedback;
  if (!isObj(fb)) throw new DmarcFormatError('no <feedback> element');
  const meta = isObj(fb.report_metadata) ? fb.report_metadata : {};
  const pp = isObj(fb.policy_published) ? fb.policy_published : {};
  const orgName = s(meta.org_name);
  const reportId = s(meta.report_id);
  if (!orgName) throw new DmarcFormatError('missing report_metadata.org_name');
  if (!reportId) throw new DmarcFormatError('missing report_metadata.report_id');
  const range = isObj(meta.date_range) ? meta.date_range : {};
  const domain = lower(pp.domain)?.replace(/\.$/, '');
  if (!domain) throw new DmarcFormatError('missing policy_published.domain');
  const pct = s(pp.pct);

  const records: DmarcRecordRow[] = arr(fb.record)
    .filter(isObj)
    .map((r) => {
      const row = isObj(r.row) ? r.row : {};
      const pe = isObj(row.policy_evaluated) ? row.policy_evaluated : {};
      const ids = isObj(r.identifiers) ? r.identifiers : {};
      const auth = isObj(r.auth_results) ? r.auth_results : {};
      const dkim: DmarcAuthResult[] = arr(auth.dkim)
        .filter(isObj)
        .map((d) => ({ domain: lower(d.domain) ?? '', selector: s(d.selector), result: lower(d.result) ?? 'none' }));
      const spf: DmarcAuthResult[] = arr(auth.spf)
        .filter(isObj)
        .map((d) => ({ domain: lower(d.domain) ?? '', scope: lower(d.scope), result: lower(d.result) ?? 'none' }));
      const count = Number(s(row.count) ?? 0);
      return {
        sourceIp: s(row.source_ip) ?? 'unknown',
        count: Number.isFinite(count) && count > 0 ? Math.floor(count) : 0,
        disposition: lower(pe.disposition) ?? 'none',
        dkim: lower(pe.dkim) ?? 'fail',
        spf: lower(pe.spf) ?? 'fail',
        reasons: arr(pe.reason)
          .filter(isObj)
          .map((x) => ({ type: lower(x.type) ?? 'other', comment: s(x.comment) })),
        headerFrom: lower(ids.header_from) ?? domain,
        envelopeFrom: lower(ids.envelope_from),
        envelopeTo: lower(ids.envelope_to),
        dkimResults: dkim,
        spfResults: spf,
      };
    });

  return {
    orgName,
    reportId,
    email: s(meta.email),
    extraContact: s(meta.extra_contact_info),
    begin: epoch(range.begin, 'date_range.begin'),
    end: epoch(range.end, 'date_range.end'),
    errors: arr(meta.error)
      .map(s)
      .filter((x): x is string => Boolean(x)),
    policy: {
      domain,
      adkim: lower(pp.adkim),
      aspf: lower(pp.aspf),
      p: lower(pp.p),
      sp: lower(pp.sp),
      np: lower(pp.np),
      pct: pct !== null && Number.isFinite(Number(pct)) ? Number(pct) : null,
      fo: s(pp.fo),
    },
    records,
  };
}

/** A record passes DMARC when the aligned DKIM or SPF result (policy_evaluated) is pass. */
export const passes = (r: Pick<DmarcRecordRow, 'dkim' | 'spf'>) => r.dkim === 'pass' || r.spf === 'pass';
