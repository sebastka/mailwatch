// SPF (RFC 7208): record selection, syntax, the DNS lookup limits and the include/redirect tree.
import { isIPv4, isIPv6 } from 'node:net';
import type { CheckResult, SpfData, SpfNode, SpfTerm } from '../../shared/types.ts';
import { answered, type DnsClient } from '../dns.ts';
import { type CheckContext, Findings, prefixedTxt, ref, result } from './util.ts';

const MECHANISMS = new Set(['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists']);
/** Mechanisms and modifiers that cause a DNS query (RFC 7208 §4.6.4). */
const LOOKUP_TERMS = new Set(['include', 'a', 'mx', 'ptr', 'exists', 'redirect']);
const MAX_LOOKUPS = 10;
const MAX_VOID = 2;
const SPF_RE = /^v=spf1(?:\s|$)/i;

export interface ParsedTerm extends SpfTerm {
  /** For a, mx, ip4, ip6: the prefix lengths given. */
  cidr4: number | null;
  cidr6: number | null;
  /** The domain-spec contains macros (%{…}) and cannot be followed without a message. */
  macro: boolean;
  error: string | null;
}

const MACRO_RE = /%(?:\{[slodiphcrtv]\d*r?[.\-+,/_=]*\}|[%_-])/gi;

/** Parses one SPF record into terms (RFC 7208 §4.6.1, §12). Never throws. */
export function parseSpf(record: string): { terms: ParsedTerm[]; errors: string[] } {
  const errors: string[] = [];
  const terms: ParsedTerm[] = [];
  const parts = record.trim().split(/\s+/);
  if (!parts[0] || parts[0].toLowerCase() !== 'v=spf1') {
    errors.push('the record does not start with "v=spf1"');
    return { terms, errors };
  }
  for (const raw of parts.slice(1)) {
    const t: ParsedTerm = {
      raw,
      qualifier: null,
      kind: '',
      value: null,
      lookups: 0,
      cidr4: null,
      cidr6: null,
      macro: false,
      error: null,
    };
    const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(raw);
    if (mod) {
      t.kind = mod[1]!.toLowerCase();
      t.value = mod[2]!;
      if (t.kind === 'redirect' || t.kind === 'exp') {
        if (!t.value) t.error = `${t.kind}= needs a domain`;
        t.macro = t.value.includes('%');
      } else {
        t.kind = `modifier:${t.kind}`; // unknown modifiers are ignored (§6)
      }
    } else {
      let rest = raw;
      if (/^[+\-~?]/.test(rest)) {
        t.qualifier = rest[0] as SpfTerm['qualifier'];
        rest = rest.slice(1);
      }
      const m = /^([a-z0-9]+)(?::(.*?))?((?:\/\d+)?(?:\/\/\d+)?)$/i.exec(rest);
      const name = m?.[1]?.toLowerCase() ?? rest.toLowerCase();
      t.kind = name;
      if (!m || !MECHANISMS.has(name)) {
        t.error = `unknown mechanism "${rest}"`;
      } else {
        t.value = m[2] ?? null;
        const cidr = m[3] ?? '';
        const c = /^(?:\/(\d+))?(?:\/\/(\d+))?$/.exec(cidr);
        if (c?.[1]) t.cidr4 = Number(c[1]);
        if (c?.[2]) t.cidr6 = Number(c[2]);
        t.macro = (t.value ?? '').includes('%');
        if (name === 'all' && (t.value !== null || cidr)) t.error = '"all" takes no argument';
        if ((name === 'include' || name === 'exists') && !t.value) t.error = `${name}: needs a domain`;
        if (name === 'ip4') {
          if (!t.value || !isIPv4(t.value)) t.error = `"${raw}" is not a valid IPv4 address`;
          t.cidr4 = t.cidr4 ?? (/\/(\d+)$/.exec(raw) ? Number(/\/(\d+)$/.exec(raw)![1]) : null);
        }
        if (name === 'ip6') {
          // ip6: values contain ":", so take the prefix from the raw term.
          const v = /^[+\-~?]?ip6:([^/]+)(?:\/(\d+))?$/i.exec(raw);
          t.value = v?.[1] ?? null;
          t.cidr6 = v?.[2] ? Number(v[2]) : null;
          t.cidr4 = null;
          if (!t.value || !isIPv6(t.value)) t.error = `"${raw}" is not a valid IPv6 address`;
        }
        if (t.cidr4 !== null && t.cidr4 > 32) t.error = `invalid IPv4 prefix length /${t.cidr4}`;
        if (t.cidr6 !== null && t.cidr6 > 128) t.error = `invalid IPv6 prefix length //${t.cidr6}`;
        if ((name === 'include' || name === 'all' || name === 'exists' || name === 'ptr') && cidr) {
          t.error = `${name} does not take a prefix length`;
        }
      }
    }
    if (t.macro && t.value) {
      const stripped = t.value.replace(MACRO_RE, '');
      if (stripped.includes('%')) t.error = `invalid macro in "${raw}"`;
    }
    if (t.error) errors.push(t.error);
    t.lookups = LOOKUP_TERMS.has(t.kind) ? 1 : 0;
    terms.push(t);
  }
  const count = (k: string) => terms.filter((t) => t.kind === k).length;
  if (count('redirect') > 1) errors.push('"redirect=" appears more than once');
  if (count('exp') > 1) errors.push('"exp=" appears more than once');
  return { terms, errors };
}

interface Walk {
  lookups: number;
  voids: number;
  ip4: Set<string>;
  ip6: Set<string>;
  /** Permanent errors found anywhere in the tree (permerror). */
  errors: string[];
  /** DNS failures (temperror): the result cannot be determined. */
  temp: string[];
  usesPtr: string[];
  macros: string[];
}

/** Expands the d macro so that common forms like "exists:%{d}._spf…" can still be counted. */
const expandD = (spec: string, domain: string) => spec.replace(/%\{d\}/gi, domain);

async function expand(
  dns: DnsClient,
  domain: string,
  record: string,
  depth: number,
  w: Walk,
  seen: Set<string>,
): Promise<SpfNode> {
  const { terms, errors } = parseSpf(record);
  const node: SpfNode = { domain, record, terms, error: errors[0] ?? null };
  for (const e of errors) w.errors.push(`${domain}: ${e}`);
  const hasAll = terms.some((t) => t.kind === 'all');

  for (const t of terms as ParsedTerm[]) {
    if (t.error) continue;
    if (t.kind === 'ip4' && t.value) w.ip4.add(t.cidr4 !== null ? `${t.value}/${t.cidr4}` : t.value);
    if (t.kind === 'ip6' && t.value) w.ip6.add(t.cidr6 !== null ? `${t.value}/${t.cidr6}` : t.value);
    if (!LOOKUP_TERMS.has(t.kind)) continue;
    if (t.kind === 'redirect' && hasAll) continue; // ignored when "all" is present (§6.1)
    w.lookups++;
    if (w.lookups > MAX_LOOKUPS * 3) continue; // far past the limit: stop querying
    if (t.kind === 'ptr') w.usesPtr.push(domain);
    const target = t.value ? expandD(t.value, domain) : domain;
    if (target.includes('%')) {
      w.macros.push(`${domain}: ${t.raw}`);
      continue;
    }

    if (t.kind === 'include' || t.kind === 'redirect') {
      const key = target.toLowerCase();
      if (seen.has(key)) {
        w.errors.push(`${domain}: ${t.raw} creates a loop`);
        continue;
      }
      if (depth >= 10) {
        w.errors.push(`${domain}: includes nested too deeply`);
        continue;
      }
      const sel = await prefixedTxt(dns, target, SPF_RE);
      if (sel.failed) {
        w.temp.push(`${target}: ${sel.result.rcode}`);
        continue;
      }
      if (!sel.result.records.length) w.voids++;
      if (sel.matching.length !== 1) {
        w.errors.push(
          sel.matching.length
            ? `${target} (${t.raw}) has ${sel.matching.length} SPF records`
            : `${target} (${t.raw}) has no SPF record`,
        );
        t.child = {
          domain: target,
          record: null,
          terms: [],
          error: sel.matching.length ? 'multiple SPF records' : 'no SPF record',
        };
        continue;
      }
      t.child = await expand(dns, target, sel.matching[0]!, depth + 1, w, new Set([...seen, key]));
    } else if (t.kind === 'a') {
      const r = await dns.addresses(target);
      if (r.failed) w.temp.push(`${target}: address lookup failed`);
      else if (!r.ips.length) w.voids++;
      for (const ip of r.ips) (ip.includes(':') ? w.ip6 : w.ip4).add(ip);
    } else if (t.kind === 'mx') {
      const r = await dns.mx(target);
      if (!answered(r)) {
        w.temp.push(`${target}: MX lookup failed`);
        continue;
      }
      if (!r.records.length) w.voids++;
      if (r.records.length > 10) w.errors.push(`${domain}: ${t.raw} has more than 10 MX hosts (§4.6.4)`);
      for (const mx of r.records.slice(0, 10)) {
        if (!mx.exchange) continue;
        const a = await dns.addresses(mx.exchange);
        for (const ip of a.ips) (ip.includes(':') ? w.ip6 : w.ip4).add(ip);
      }
    } else if (t.kind === 'exists') {
      const r = await dns.a(target);
      if (!answered(r)) w.temp.push(`${target}: lookup failed`);
      else if (!r.records.length) w.voids++;
    }
  }
  return node;
}

export async function checkSpf(ctx: CheckContext): Promise<CheckResult<SpfData>> {
  const started = performance.now();
  const f = new Findings();
  const { dns, domain } = ctx;
  const data: SpfData = {
    record: null,
    records: [],
    tree: null,
    lookups: 0,
    voidLookups: 0,
    ip4: [],
    ip6: [],
    allQualifier: null,
  };
  const done = () => result(ctx, 'spf', started, f, data);

  const sel = await prefixedTxt(dns, domain.name, SPF_RE);
  if (sel.failed) {
    f.lookupFailed('spf.lookup-failed', 'the SPF record', sel.result);
    return done();
  }
  data.records = sel.matching;
  // "v=spf1" must be followed by a space or the end; "v=spf10" is not an SPF record.
  const nearMiss = sel.result.records.filter((t) => /^\s*v\s*=\s*spf1/i.test(t) && !SPF_RE.test(t));
  if (nearMiss.length && !sel.matching.length) {
    f.error(
      'spf.malformed-version',
      'Malformed SPF record',
      `The TXT record "${nearMiss[0]}" looks like SPF but does not start with exactly "v=spf1".`,
      {
        refs: [ref('rfc7208', '4.5')],
      },
    );
  }
  if (!sel.matching.length) {
    const nullMx = ctx.mx?.nullMx ?? false;
    f.warning(
      'spf.missing',
      'No SPF record',
      nullMx
        ? 'The domain does not send or receive mail: publish "v=spf1 -all" so that nobody can send in its name.'
        : 'Receivers cannot tell which servers may send for this domain (result "none"). DMARC then depends on DKIM alone.',
      { refs: [ref('rfc7208', '4.5')] },
    );
    return done();
  }
  if (sel.matching.length > 1) {
    f.error(
      'spf.multiple',
      `${sel.matching.length} SPF records`,
      'A domain must publish exactly one SPF record. With several, every receiver returns "permerror" and SPF fails. Merge them into one.',
      { refs: [ref('rfc7208', '3.2'), ref('rfc7208', '4.5')] },
    );
    return done();
  }

  const record = sel.matching[0]!;
  data.record = record;
  const w: Walk = {
    lookups: 0,
    voids: 0,
    ip4: new Set(),
    ip6: new Set(),
    errors: [],
    temp: [],
    usesPtr: [],
    macros: [],
  };
  data.tree = await expand(dns, domain.name, record, 0, w, new Set([domain.name]));
  data.lookups = w.lookups;
  data.voidLookups = w.voids;
  data.ip4 = [...w.ip4];
  data.ip6 = [...w.ip6];

  const top = data.tree.terms;
  const all = top.find((t) => t.kind === 'all');
  data.allQualifier = all ? (all.qualifier ?? '+') : null;

  if (w.errors.length) {
    f.error(
      'spf.permerror',
      'SPF evaluation ends in a permanent error',
      `${w.errors.slice(0, 5).join('; ')}${w.errors.length > 5 ? ` (and ${w.errors.length - 5} more)` : ''}. Receivers treat the record as broken ("permerror"), which fails DMARC's SPF leg.`,
      { refs: [ref('rfc7208', '4.6'), ref('rfc7208', '2.6.7')] },
    );
  }
  if (w.temp.length) {
    f.warning('spf.temperror', 'Part of the SPF record could not be resolved', `${w.temp.slice(0, 5).join('; ')}.`, {
      refs: [ref('rfc7208', '2.6.6')],
    });
  }
  if (w.lookups > MAX_LOOKUPS) {
    f.error(
      'spf.too-many-lookups',
      `${w.lookups} DNS lookups: more than the limit of ${MAX_LOOKUPS}`,
      'Receivers stop after 10 mechanisms that need DNS (include, a, mx, ptr, exists, redirect), counted across all includes, and return "permerror". Replace includes by ip4/ip6 ranges or drop unused ones.',
      { refs: [ref('rfc7208', '4.6.4')] },
    );
  } else if (w.lookups >= 8) {
    f.warning(
      'spf.near-lookup-limit',
      `${w.lookups} of ${MAX_LOOKUPS} DNS lookups used`,
      'Close to the limit: a provider adding one include to its record would make yours fail.',
      { refs: [ref('rfc7208', '4.6.4')] },
    );
  }
  if (w.voids > MAX_VOID) {
    f.error(
      'spf.too-many-void-lookups',
      `${w.voids} lookups return nothing (limit ${MAX_VOID})`,
      'Mechanisms whose name does not exist or has no records count as "void lookups"; more than two is a permerror.',
      { refs: [ref('rfc7208', '4.6.4')] },
    );
  } else if (w.voids > 0) {
    f.warning(
      'spf.void-lookup',
      `${w.voids} lookup${w.voids === 1 ? '' : 's'} return nothing`,
      'A mechanism points at a name without records. Remove it.',
      {
        refs: [ref('rfc7208', '4.6.4')],
      },
    );
  }
  if (w.usesPtr.length) {
    f.warning(
      'spf.ptr',
      'The "ptr" mechanism is used',
      `"ptr" is slow, unreliable and should not be used (in ${[...new Set(w.usesPtr)].join(', ')}). Some receivers ignore it.`,
      { refs: [ref('rfc7208', '5.5')] },
    );
  }
  if (w.macros.length) {
    f.info(
      'spf.macros',
      'The record uses macros',
      `These terms depend on the message and are not evaluated here: ${w.macros.join('; ')}.`,
      {
        refs: [ref('rfc7208', '7')],
      },
    );
  }

  const redirect = top.find((t) => t.kind === 'redirect');
  if (all) {
    const idx = top.indexOf(all);
    const after = top.slice(idx + 1).filter((t) => MECHANISMS.has(t.kind));
    if (after.length) {
      f.warning(
        'spf.after-all',
        'Mechanisms after "all" are never used',
        `${after.map((t) => t.raw).join(' ')} come after ${all.raw}.`,
        {
          refs: [ref('rfc7208', '5.1')],
        },
      );
    }
    if (redirect) {
      f.warning(
        'spf.redirect-ignored',
        '"redirect=" is ignored because the record has "all"',
        `${redirect.raw} has no effect.`,
        {
          refs: [ref('rfc7208', '6.1')],
        },
      );
    }
    if (data.allQualifier === '+') {
      f.error(
        'spf.pass-all',
        '"+all" lets every server on the Internet send for this domain',
        'Use "-all" (fail) or "~all" (softfail).',
        {
          refs: [ref('rfc7208', '5.1')],
        },
      );
    } else if (data.allQualifier === '?') {
      f.warning(
        'spf.neutral-all',
        '"?all" says nothing about other servers',
        'Mail from unlisted servers gets a neutral result. Use "-all" or "~all".',
        {
          refs: [ref('rfc7208', '5.1'), ref('rfc7208', '8.2')],
        },
      );
    }
  } else if (!redirect) {
    f.warning(
      'spf.no-all',
      'The record does not end with "all"',
      'Without "all" (or "redirect="), mail from unlisted servers gets a neutral result. End the record with "-all" or "~all".',
      { refs: [ref('rfc7208', '4.7')] },
    );
  }

  // RFC 7208 §3.4: keep the DNS answer small enough for 512-byte UDP.
  const size = record.length;
  if (size > 450) {
    f.info(
      'spf.long',
      `The record is ${size} characters long`,
      'Long records can make the DNS answer exceed 512 bytes and need TCP; keep SPF records short.',
      {
        refs: [ref('rfc7208', '3.4')],
      },
    );
  }

  if (!f.list.some((x) => x.level === 'error' || x.level === 'warning')) {
    const q = data.allQualifier === '-' ? '-all (fail)' : data.allQualifier === '~' ? '~all (softfail)' : 'redirect';
    f.ok('spf.ok', `Valid SPF record, ${w.lookups} of ${MAX_LOOKUPS} lookups, ${q}`, record, {
      refs: [ref('rfc7208')],
    });
  }
  return done();
}
