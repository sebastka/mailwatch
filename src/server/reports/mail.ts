// Extracts the reports from a raw RFC 822 message: TLS-RPT (JSON), DMARC aggregate (XML) and
// DMARC failure reports (ARF). One mailbox may receive all three kinds.
import { createHash } from 'node:crypto';
import { simpleParser, type Attachment } from 'mailparser';
import { type NormalizedFailureReport, parseArf } from './arf.ts';
import { decompress, type NormalizedDmarcReport, parseAggregate } from './dmarc.ts';
import { decodePayload, normalizeReport, type NormalizedReport } from './tlsrpt.ts';

export interface ExtractedMessage {
  messageId: string | null;
  from: string | null;
  subject: string | null;
  date: string | null;
  tls: { filename: string | null; raw: unknown; report: NormalizedReport }[];
  dmarc: { filename: string | null; xml: string; report: NormalizedDmarcReport }[];
  failure: (NormalizedFailureReport & { key: string }) | null;
  errors: string[];
}

const REPORT_TYPES = [
  'application/tlsrpt+gzip',
  'application/tlsrpt+json',
  'application/gzip',
  'application/x-gzip',
  'application/zip',
  'application/x-zip-compressed',
  'application/xml',
  'text/xml',
  'application/json',
  'application/octet-stream',
];

function candidate(a: Attachment): boolean {
  const type = a.contentType.toLowerCase();
  const name = (a.filename ?? '').toLowerCase();
  return REPORT_TYPES.includes(type) || /\.(json|xml)(\.gz)?$|\.(gz|zip)$/.test(name);
}

export async function extractReports(source: Buffer): Promise<ExtractedMessage> {
  const mail = await simpleParser(source, { skipHtmlToText: true, skipTextToHtml: true, skipImageLinks: true });
  const out: ExtractedMessage = {
    messageId: mail.messageId ?? null,
    from: mail.from?.value[0]?.address?.toLowerCase() ?? null,
    subject: mail.subject ?? null,
    date: mail.date ? mail.date.toISOString() : null,
    tls: [],
    dmarc: [],
    failure: null,
    errors: [],
  };

  const arf = parseArf(mail.attachments);
  if (arf) {
    // Reports have no id of their own: the Message-ID, or a digest of the report fields.
    const key = out.messageId ?? createHash('sha256').update(JSON.stringify(arf.fields)).digest('hex');
    out.failure = { ...arf, key: key.slice(0, 191) };
    return out;
  }

  for (const a of mail.attachments.filter(candidate)) {
    const label = a.filename ?? a.contentType;
    try {
      const bytes = decompress(a.content);
      const head = bytes
        .subarray(0, 64)
        .toString('utf8')
        .replace(/^\uFEFF/, '')
        .trimStart();
      if (head.startsWith('{')) {
        const raw = decodePayload(bytes);
        out.tls.push({ filename: a.filename ?? null, raw, report: normalizeReport(raw) });
      } else if (head.startsWith('<')) {
        const xml = bytes.toString('utf8');
        out.dmarc.push({ filename: a.filename ?? null, xml, report: parseAggregate(xml) });
      } else if (a.contentType.toLowerCase() !== 'application/octet-stream') {
        out.errors.push(`${label}: neither JSON nor XML`);
      }
    } catch (e) {
      out.errors.push(`${label}: ${(e as Error).message}`);
    }
  }
  return out;
}
