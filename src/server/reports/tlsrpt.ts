// Parsing and normalisation of SMTP TLS Reporting (RFC 8460) JSON reports.
import { gunzipSync } from 'node:zlib';

export interface NormalizedFailure {
  resultType: string;
  sendingMtaIp: string | null;
  receivingMxHostname: string | null;
  receivingMxHelo: string | null;
  receivingIp: string | null;
  failedSessionCount: number;
  additionalInformation: string | null;
  failureReasonCode: string | null;
}

export interface NormalizedPolicy {
  type: string;
  domain: string;
  policyString: string[];
  mxHosts: string[];
  /** MTA-STS mode parsed from the policy string (sts policies only). */
  mode: string | null;
  successful: number;
  failed: number;
  failures: NormalizedFailure[];
}

export interface NormalizedReport {
  organizationName: string;
  reportId: string;
  contactInfo: string | null;
  start: string;
  end: string;
  policies: NormalizedPolicy[];
}

export class ReportFormatError extends Error {}

type Json = Record<string, unknown>;

const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
const optStr = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);
const strList = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : typeof v === 'string' ? [v] : [];

function count(v: unknown): number {
  const n = typeof v === 'string' ? Number(v) : v;
  return typeof n === 'number' && Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function isoDate(v: unknown, field: string): string {
  const s = optStr(v);
  const d = s ? new Date(s) : null;
  if (!d || Number.isNaN(d.getTime())) throw new ReportFormatError(`invalid or missing ${field}`);
  return d.toISOString();
}

export function stsMode(policyString: string[]): string | null {
  for (const line of policyString) {
    const m = /^\s*mode\s*:\s*(\S+)/i.exec(line);
    if (m) return m[1]!.toLowerCase();
  }
  return null;
}

/** Validates the parts of a report we rely on and normalises the rest leniently. */
export function normalizeReport(input: unknown): NormalizedReport {
  if (!isObj(input)) throw new ReportFormatError('report is not a JSON object');
  const organizationName = optStr(input['organization-name']);
  const reportId = optStr(input['report-id']);
  const range = input['date-range'];
  const policies = input['policies'];
  if (!organizationName) throw new ReportFormatError('missing organization-name');
  if (!reportId) throw new ReportFormatError('missing report-id');
  if (!isObj(range)) throw new ReportFormatError('missing date-range');
  if (!Array.isArray(policies)) throw new ReportFormatError('missing policies');

  return {
    organizationName,
    reportId,
    contactInfo: optStr(input['contact-info']),
    start: isoDate(range['start-datetime'], 'date-range.start-datetime'),
    end: isoDate(range['end-datetime'], 'date-range.end-datetime'),
    policies: policies.filter(isObj).map((p) => {
      const pol = isObj(p['policy']) ? p['policy'] : {};
      const summary = isObj(p['summary']) ? p['summary'] : {};
      const type = optStr(pol['policy-type'])?.toLowerCase() ?? 'unknown';
      const policyString = strList(pol['policy-string']);
      return {
        type,
        domain: (optStr(pol['policy-domain']) ?? 'unknown').toLowerCase().replace(/\.$/, ''),
        policyString,
        mxHosts: strList(pol['mx-host']),
        mode: type === 'sts' ? stsMode(policyString) : null,
        successful: count(summary['total-successful-session-count']),
        failed: count(summary['total-failure-session-count']),
        failures: (Array.isArray(p['failure-details']) ? p['failure-details'] : []).filter(isObj).map((f) => ({
          resultType: optStr(f['result-type'])?.toLowerCase() ?? 'unknown',
          sendingMtaIp: optStr(f['sending-mta-ip']),
          receivingMxHostname: optStr(f['receiving-mx-hostname'])?.toLowerCase().replace(/\.$/, '') ?? null,
          receivingMxHelo: optStr(f['receiving-mx-helo']),
          receivingIp: optStr(f['receiving-ip']),
          failedSessionCount: count(f['failed-session-count']),
          additionalInformation: optStr(f['additional-information']),
          failureReasonCode: optStr(f['failure-reason-code']),
        })),
      };
    }),
  };
}

/** Decodes a report payload that may be gzip-compressed or plain JSON. */
export function decodePayload(buf: Buffer): unknown {
  let data = buf;
  if (data.length >= 2 && data[0] === 0x1f && data[1] === 0x8b) {
    data = gunzipSync(data, { maxOutputLength: 50 * 1024 * 1024 });
  } else if (data.length >= 2 && data[0] === 0x50 && data[1] === 0x4b) {
    throw new ReportFormatError('zip archives are not supported (RFC 8460 mandates gzip)');
  }
  const text = data
    .toString('utf8')
    .replace(/^\uFEFF/, '')
    .trim();
  if (!text.startsWith('{')) throw new ReportFormatError('payload is not JSON');
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new ReportFormatError(`invalid JSON: ${(e as Error).message}`);
  }
}
