// What the receiving provider recorded about a delivered probe: Authentication-Results
// (RFC 8601), Received-SPF (RFC 7208 §9.1), Microsoft's compauth and spam confidence level,
// and the DKIM selectors of the signatures.
import type { ProbeAuth } from '../shared/types.ts';
import { parseFields } from './reports/arf.ts';

export interface ParsedHeaders {
  fields: [string, string][];
  auth: ProbeAuth;
  clientIp: string | null;
  /** Selectors of the DKIM signatures made by the sender domain. */
  dkimSelectors: string[];
}

/** Splits on `sep` outside comments "(…)" and quoted strings. */
function splitTop(s: string, sep: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quoted = false;
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === '\\' && i + 1 < s.length) {
      cur += c + s[++i];
      continue;
    }
    if (c === '"') quoted = !quoted;
    else if (!quoted && c === '(') depth++;
    else if (!quoted && c === ')') depth = Math.max(0, depth - 1);
    if (c === sep && depth === 0 && !quoted) {
      out.push(cur);
      cur = '';
    } else cur += c;
  }
  out.push(cur);
  return out;
}

const stripComments = (s: string) => {
  let out = '';
  let depth = 0;
  for (const c of s) {
    if (c === '(') depth++;
    else if (c === ')') depth = Math.max(0, depth - 1);
    else if (depth === 0) out += c;
  }
  return out;
};

export interface AuthResult {
  method: string;
  result: string;
  props: Record<string, string>;
  /** The resinfo text including comments (Microsoft puts the sender IP there). */
  raw: string;
}

/** Parses one Authentication-Results value: "authserv-id; spf=pass smtp.mailfrom=…; dkim=pass header.d=…". */
export function parseAuthResults(value: string): { authservId: string; results: AuthResult[] } {
  const parts = splitTop(value, ';');
  const authservId =
    stripComments(parts[0] ?? '')
      .trim()
      .split(/\s+/)[0] ?? '';
  const results: AuthResult[] = [];
  for (const part of parts.slice(1)) {
    const clean = stripComments(part).trim();
    if (!clean || clean.toLowerCase() === 'none') continue;
    const tokens = clean.split(/\s+/);
    const m = /^([a-z0-9_.-]+)=([a-z0-9_-]+)/i.exec(tokens[0] ?? '');
    if (!m) continue;
    const props: Record<string, string> = {};
    for (const t of tokens.slice(1)) {
      const p = /^([a-z0-9_.-]+)=(.*)$/i.exec(t);
      if (p) props[p[1]!.toLowerCase()] = p[2]!.replace(/^"|"$/g, '');
    }
    results.push({ method: m[1]!.toLowerCase(), result: m[2]!.toLowerCase(), props, raw: part.trim() });
  }
  return { authservId, results };
}

const get = (fields: [string, string][], name: string) =>
  fields.filter(([k]) => k.toLowerCase() === name).map(([, v]) => v);

const ipIn = (s: string): string | null =>
  /\b(?:client-ip|sender IP is|smtp\.remote-ip=)\s*=?\s*\[?([0-9a-f:.]{7,45})\]?/i.exec(s)?.[1] ?? null;

/**
 * Reads the auth results the recipient's provider added. The topmost Authentication-Results
 * header is the one the receiving boundary added (RFC 8601 §5: headers are prepended).
 */
export function parseProbeHeaders(headerBlock: string, senderDomain: string): ParsedHeaders {
  const fields = parseFields(headerBlock.replace(/\r\n/g, '\n').split('\n\n')[0] ?? '');
  const ar = get(fields, 'authentication-results');
  const top = ar[0] ? parseAuthResults(ar[0]) : null;
  const first = (method: string) => top?.results.find((r) => r.method === method) ?? null;

  // With several DKIM signatures, report the one aligned with the sender domain when present.
  const aligned = (d: string | undefined) => !!d && (d === senderDomain || d.endsWith(`.${senderDomain}`));
  const dkims = top?.results.filter((r) => r.method === 'dkim') ?? [];
  const dkim =
    dkims.find((r) => r.result === 'pass' && aligned(r.props['header.d'] ?? r.props['header.i']?.split('@').pop())) ??
    dkims[0] ??
    null;
  const compauth = first('compauth');
  const spf = first('spf');

  let scl: number | null = null;
  const sclHeader = get(fields, 'x-ms-exchange-organization-scl')[0];
  const forefront = get(fields, 'x-forefront-antispam-report')[0];
  const sclMatch = sclHeader?.trim() ?? /\bSCL:(-?\d+)/.exec(forefront ?? '')?.[1];
  if (sclMatch !== undefined && /^-?\d+$/.test(sclMatch)) scl = Number(sclMatch);

  const receivedSpf = get(fields, 'received-spf')[0] ?? '';
  const clientIp = ipIn(receivedSpf) ?? (spf ? ipIn(spf.raw) : null) ?? (top ? ipIn(ar[0]!) : null);

  const selectors = new Set<string>();
  for (const sig of get(fields, 'dkim-signature')) {
    const tags = Object.fromEntries(
      sig
        .split(';')
        .map((t) => t.trim().split('='))
        .filter((kv) => kv.length >= 2)
        .map(([k, ...v]) => [k!.trim().toLowerCase(), v.join('=').replace(/\s+/g, '')]),
    );
    if (tags.s && tags.d && aligned(tags.d.toLowerCase())) selectors.add(tags.s.toLowerCase());
  }

  return {
    fields,
    auth: {
      spf: spf?.result ?? (receivedSpf ? (receivedSpf.trim().split(/\s/)[0]?.toLowerCase() ?? null) : null),
      dkim: dkim?.result ?? null,
      dmarc: first('dmarc')?.result ?? null,
      arc: first('arc')?.result ?? null,
      compauth: compauth
        ? `${compauth.result}${compauth.props.reason ? ` reason=${compauth.props.reason}` : ''}`
        : null,
      scl,
    },
    clientIp,
    dkimSelectors: [...selectors],
  };
}
