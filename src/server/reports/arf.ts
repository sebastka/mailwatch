// DMARC failure reports ("ruf"): Abuse Reporting Format messages (RFC 5965) with
// Feedback-Type auth-failure (RFC 6591).
import type { Attachment } from 'mailparser';

export interface NormalizedFailureReport {
  fields: [string, string][];
  feedbackType: string | null;
  authFailure: string | null;
  reportedDomain: string | null;
  sourceIp: string | null;
  arrivalDate: string | null;
  originalMailFrom: string | null;
  originalRcptTo: string | null;
  dkimDomain: string | null;
  dkimSelector: string | null;
  deliveryResult: string | null;
  identityAlignment: string | null;
  authenticationResults: string | null;
  /** Header section of the original message (bodies are never stored). */
  headers: string | null;
  headerFrom: string | null;
  subject: string | null;
}

const MAX_HEADERS = 16 * 1024;

/** Parses "Name: value" header-style fields with continuation lines (RFC 5965 §3.1). */
export function parseFields(text: string): [string, string][] {
  const out: [string, string][] = [];
  for (const line of text.replace(/\r\n/g, '\n').split('\n')) {
    if (!line.trim()) {
      if (out.length) break; // end of the field block
      continue;
    }
    if (/^[ \t]/.test(line) && out.length) {
      out[out.length - 1]![1] += ` ${line.trim()}`;
      continue;
    }
    const i = line.indexOf(':');
    if (i > 0) out.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
  }
  return out;
}

const field = (fields: [string, string][], name: string) =>
  fields.find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1] ?? null;

const unbracket = (v: string | null) => v?.replace(/^<|>$/g, '').trim() || null;

/** The header section of an embedded message (message/rfc822 or text/rfc822-headers). */
function headerSection(a: Attachment): string {
  const text = a.content.toString('utf8').replace(/\r\n/g, '\n');
  const end = text.indexOf('\n\n');
  return (end >= 0 ? text.slice(0, end) : text).slice(0, MAX_HEADERS);
}

/**
 * Finds the machine-readable part of a feedback report among the attachments mailparser
 * produced. Returns null when the message is not an auth-failure report.
 */
export function parseArf(attachments: Attachment[]): NormalizedFailureReport | null {
  const report = attachments.find((a) => a.contentType.toLowerCase() === 'message/feedback-report');
  if (!report) return null;
  const fields = parseFields(report.content.toString('utf8'));
  const feedbackType = field(fields, 'Feedback-Type')?.toLowerCase() ?? null;
  if (feedbackType !== 'auth-failure') return null;
  const original = attachments.find((a) =>
    ['message/rfc822', 'text/rfc822-headers', 'message/rfc822-headers'].includes(a.contentType.toLowerCase()),
  );
  const headers = original ? headerSection(original) : null;
  const orig = headers ? parseFields(headers) : [];
  return {
    fields,
    feedbackType,
    authFailure: field(fields, 'Auth-Failure')?.toLowerCase() ?? null,
    reportedDomain: field(fields, 'Reported-Domain')?.toLowerCase().replace(/\.$/, '') ?? null,
    sourceIp: field(fields, 'Source-IP'),
    arrivalDate: field(fields, 'Arrival-Date'),
    originalMailFrom: unbracket(field(fields, 'Original-Mail-From')),
    originalRcptTo: unbracket(field(fields, 'Original-Rcpt-To')),
    dkimDomain: field(fields, 'DKIM-Domain')?.toLowerCase() ?? null,
    dkimSelector: field(fields, 'DKIM-Selector'),
    deliveryResult: field(fields, 'Delivery-Result')?.toLowerCase() ?? null,
    identityAlignment: field(fields, 'Identity-Alignment')?.toLowerCase() ?? null,
    authenticationResults: field(fields, 'Authentication-Results'),
    headers,
    headerFrom: field(orig, 'From'),
    subject: field(orig, 'Subject'),
  };
}
