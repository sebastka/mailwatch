// SPF evaluation (RFC 7208 §4 check_host): is this IP allowed to send for this domain?
import { isIPv4, isIPv6 } from 'node:net';
import { answered, type DnsClient, expandIPv6 } from '../dns.ts';
import { parseSpf, type ParsedTerm } from './spf.ts';

export type SpfResult = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'permerror' | 'temperror';

const SPF_RE = /^v=spf1(?:\s|$)/i;
const QUALIFIER: Record<string, SpfResult> = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };

class SpfError extends Error {
  readonly result: 'permerror' | 'temperror';
  constructor(result: 'permerror' | 'temperror', message: string) {
    super(message);
    this.result = result;
  }
}

interface Eval {
  dns: DnsClient;
  ip: string;
  sender: string;
  helo: string;
  lookups: number;
  voids: number;
}

// --- Addresses ------------------------------------------------------------------------

const v4ToInt = (ip: string) => ip.split('.').reduce((n, o) => (n << 8n) | BigInt(Number(o)), 0n);
const v6ToInt = (ip: string) => BigInt(`0x${expandIPv6(ip).replace(/:/g, '')}`);

/** Is `ip` within `net`/`bits` (same family only)? */
export function inCidr(ip: string, net: string, bits: number | null): boolean {
  if (isIPv4(ip) && isIPv4(net)) {
    const b = BigInt(bits ?? 32);
    const mask = b === 0n ? 0n : ((1n << 32n) - 1n) ^ ((1n << (32n - b)) - 1n);
    return (v4ToInt(ip) & mask) === (v4ToInt(net) & mask);
  }
  if (isIPv6(ip) && isIPv6(net)) {
    const b = BigInt(bits ?? 128);
    const mask = b === 0n ? 0n : ((1n << 128n) - 1n) ^ ((1n << (128n - b)) - 1n);
    return (v6ToInt(ip) & mask) === (v6ToInt(net) & mask);
  }
  return false;
}

// --- Macros (RFC 7208 §7) ----------------------------------------------------------------

/** Expands the macros of a domain-spec. */
export function expandMacros(spec: string, e: Pick<Eval, 'ip' | 'sender' | 'helo'>, domain: string): string {
  const [local, senderDomain] = e.sender.includes('@')
    ? [e.sender.split('@')[0]!, e.sender.split('@').pop()!]
    : ['postmaster', e.sender];
  const ipDots = isIPv6(e.ip) ? expandIPv6(e.ip).replace(/:/g, '').split('').join('.') : e.ip;
  return spec.replace(
    /%(?:\{([slodiphcrtv])(\d*)(r?)([.\-+,/_=]*)\}|%|_|-)/gi,
    (m, letter?: string, digits?: string, rev?: string, delims?: string) => {
      if (m === '%%') return '%';
      if (m === '%_') return ' ';
      if (m === '%-') return '%20';
      const values: Record<string, string> = {
        s: e.sender,
        l: local,
        o: senderDomain,
        d: domain,
        i: ipDots,
        p: 'unknown',
        v: isIPv6(e.ip) ? 'ip6' : 'in-addr',
        h: e.helo,
      };
      const value = values[letter!.toLowerCase()] ?? '';
      const sep = delims ? new RegExp(`[${delims.replace(/[-\\]/g, '\\$&')}]`) : /\./;
      let parts = value.split(sep);
      if (rev) parts = parts.reverse();
      if (digits) parts = parts.slice(-Math.max(1, Number(digits)));
      return parts.join('.');
    },
  );
}

// --- Evaluation ---------------------------------------------------------------------------

async function addresses(e: Eval, name: string): Promise<string[]> {
  const r = await (isIPv6(e.ip) ? e.dns.aaaa(name) : e.dns.a(name));
  if (!answered(r)) throw new SpfError('temperror', `lookup of ${name} failed (${r.rcode})`);
  if (!r.records.length && ++e.voids > 2) throw new SpfError('permerror', 'more than 2 void lookups');
  return r.records;
}

function countLookup(e: Eval) {
  if (++e.lookups > 10) throw new SpfError('permerror', 'more than 10 DNS lookups');
}

const cidrFor = (e: Eval, t: ParsedTerm) => (isIPv6(e.ip) ? t.cidr6 : t.cidr4);

async function matches(e: Eval, t: ParsedTerm, domain: string): Promise<boolean> {
  const target = () => (t.value ? expandMacros(t.value, e, domain) : domain);
  switch (t.kind) {
    case 'all':
      return true;
    case 'ip4':
      return isIPv4(e.ip) && inCidr(e.ip, t.value!, t.cidr4);
    case 'ip6':
      return isIPv6(e.ip) && inCidr(e.ip, t.value!, t.cidr6);
    case 'a': {
      countLookup(e);
      return (await addresses(e, target())).some((a) => inCidr(e.ip, a, cidrFor(e, t)));
    }
    case 'mx': {
      countLookup(e);
      const name = target();
      const r = await e.dns.mx(name);
      if (!answered(r)) throw new SpfError('temperror', `MX lookup of ${name} failed (${r.rcode})`);
      if (!r.records.length && ++e.voids > 2) throw new SpfError('permerror', 'more than 2 void lookups');
      if (r.records.length > 10) throw new SpfError('permerror', `${name} has more than 10 MX records`);
      for (const mx of r.records) {
        if (mx.exchange && (await addresses(e, mx.exchange)).some((a) => inCidr(e.ip, a, cidrFor(e, t)))) return true;
      }
      return false;
    }
    case 'ptr': {
      countLookup(e);
      const name = target().toLowerCase();
      const r = await e.dns.ptr(e.ip);
      for (const ptr of r.records.slice(0, 10)) {
        if (ptr !== name && !ptr.endsWith(`.${name}`)) continue;
        const fwd = await (isIPv6(e.ip) ? e.dns.aaaa(ptr) : e.dns.a(ptr));
        if (fwd.records.some((a) => inCidr(e.ip, a, null))) return true;
      }
      return false;
    }
    case 'exists': {
      countLookup(e);
      const name = target();
      const r = await e.dns.a(name);
      if (!answered(r)) throw new SpfError('temperror', `lookup of ${name} failed (${r.rcode})`);
      if (!r.records.length && ++e.voids > 2) throw new SpfError('permerror', 'more than 2 void lookups');
      return r.records.length > 0;
    }
    case 'include': {
      countLookup(e);
      const r = await evaluate(e, target(), true);
      if (r.result === 'pass') return true;
      if (r.result === 'temperror') throw new SpfError('temperror', r.detail);
      if (r.result === 'permerror' || r.result === 'none')
        throw new SpfError('permerror', `include:${target()}: ${r.detail}`);
      return false;
    }
    default:
      return false;
  }
}

async function evaluate(e: Eval, domain: string, nested: boolean): Promise<{ result: SpfResult; detail: string }> {
  const r = await e.dns.txt(domain);
  if (!answered(r)) return { result: 'temperror', detail: `TXT lookup of ${domain} failed (${r.rcode})` };
  const records = r.records.filter((t) => SPF_RE.test(t));
  if (!records.length) {
    if (nested && !r.records.length && ++e.voids > 2)
      return { result: 'permerror', detail: 'more than 2 void lookups' };
    return { result: 'none', detail: `${domain} has no SPF record` };
  }
  if (records.length > 1) return { result: 'permerror', detail: `${domain} has ${records.length} SPF records` };
  const { terms, errors } = parseSpf(records[0]!);
  if (errors.length) return { result: 'permerror', detail: `${domain}: ${errors[0]}` };
  const mechanisms = terms.filter((t) => !t.kind.startsWith('modifier:') && t.kind !== 'redirect' && t.kind !== 'exp');
  try {
    for (const t of mechanisms) {
      if (await matches(e, t, domain)) {
        return { result: QUALIFIER[t.qualifier ?? '+']!, detail: `matched "${t.raw}" in ${domain}` };
      }
    }
    const redirect = terms.find((t) => t.kind === 'redirect');
    if (redirect && !terms.some((t) => t.kind === 'all')) {
      countLookup(e);
      const target = expandMacros(redirect.value!, e, domain);
      const res = await evaluate(e, target, true);
      return res.result === 'none' ? { result: 'permerror', detail: `redirect=${target}: no SPF record` } : res;
    }
  } catch (err) {
    if (err instanceof SpfError) return { result: err.result, detail: err.message };
    throw err;
  }
  return { result: 'neutral', detail: `no mechanism of ${domain} matched` };
}

/**
 * check_host(ip, domain, sender): the SPF result for mail from `sender` (MAIL FROM) whose
 * envelope domain is `domain`, sent from `ip`.
 */
export function checkHost(dns: DnsClient, ip: string, domain: string, sender: string, helo = 'unknown') {
  return evaluate({ dns, ip, sender, helo, lookups: 0, voids: 0 }, domain, false);
}
