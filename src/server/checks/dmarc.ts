// DMARC policy records (RFC 7489 §6, with notes from DMARCbis) and their report destinations.
import type { CheckResult, DmarcData, DmarcUri } from '../../shared/types.ts';
import { isHostname } from '../config.ts';
import type { DnsClient } from '../dns.ts';
import { type CheckContext, Findings, parseTags, prefixedTxt, ref, result } from './util.ts';

const DMARC_RE = /^v\s*=\s*DMARC1\s*(;|$)/i;
const POLICIES = ['none', 'quarantine', 'reject'];
const KNOWN_TAGS = new Set(['v', 'p', 'sp', 'np', 'pct', 'adkim', 'aspf', 'fo', 'rf', 'ri', 'rua', 'ruf', 't', 'psd']);

/**
 * An approximation of the organisational domain without a Public Suffix List: the last two
 * labels, or three under common second-level registries (co.uk, com.au, …).
 */
export function orgDomain(d: string): string {
  const labels = d.toLowerCase().split('.');
  const sld = labels.at(-2) ?? '';
  const three = labels.length >= 3 && labels.at(-1)!.length === 2 && /^(co|com|net|org|gov|ac|edu|ne|or|go)$/.test(sld);
  return labels.slice(three ? -3 : -2).join('.');
}

/** Report destinations within the same organisational domain need no authorisation (RFC 7489 §7.1). */
export const related = (a: string, b: string) => orgDomain(a) === orgDomain(b);

// RFC 5322 §3.2.3 dot-atom (atext excludes specials such as ":" and "@"), or a quoted string.
const DOT_ATOM = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/i;
const QUOTED = /^"(?:[^"\\\r\n]|\\.)*"$/;

/** Why an addr-spec cannot receive mail, or null when it is valid. */
export function addressProblem(addr: string): string | null {
  const at = addr.lastIndexOf('@');
  if (at <= 0) return 'no "@"';
  const local = addr.slice(0, at);
  const domain = addr.slice(at + 1);
  if (!DOT_ATOM.test(local) && !QUOTED.test(local)) {
    return `"${local}" is not a valid local part (characters such as ":" are only allowed in quotes)`;
  }
  if (!isHostname(domain)) return `"${domain}" is not a valid domain`;
  return null;
}

/**
 * Parses a comma-separated list of report URIs (RFC 7489 §6.2): "mailto:a@b!10m". Invalid
 * entries are kept, with `problem` set, so that they can be shown and reported.
 */
export function parseUris(v: string | undefined, monitored: string[]): { uris: DmarcUri[] } {
  const uris: DmarcUri[] = [];
  for (const raw of (v ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)) {
    const u: DmarcUri = {
      uri: raw,
      scheme: '',
      address: null,
      domain: null,
      authorized: null,
      monitored: false,
      problem: null,
    };
    uris.push(u);
    const m = /^([a-z][a-z0-9+.-]*):(.*)$/i.exec(raw);
    if (!m) {
      u.problem = 'not a URI (expected e.g. mailto:dmarc@example.com)';
      continue;
    }
    u.scheme = m[1]!.toLowerCase();
    if (u.scheme === 'mailto') {
      let addr = m[2]!.replace(/!\d+[kmgt]?$/i, '').split('?')[0]!;
      try {
        addr = decodeURIComponent(addr);
      } catch {
        // invalid %-escape: validated as is below
      }
      addr = addr.toLowerCase();
      // A common typo: the scheme twice ("mailto:mailto:a@b").
      const problem = /^mailto:/i.test(addr) ? '"mailto:" appears twice' : addressProblem(addr);
      if (problem) {
        u.problem = problem;
        continue;
      }
      u.address = addr;
      u.domain = addr.split('@').pop()!;
      u.monitored = monitored.includes(addr);
    } else if (u.scheme === 'https') {
      try {
        u.domain = new URL(raw).hostname.toLowerCase();
      } catch {
        u.problem = 'not a valid URL';
      }
    }
  }
  return { uris };
}

/** RFC 7489 §7.1: a destination outside the domain must publish <domain>._report._dmarc.<dest>. */
async function verifyExternal(dns: DnsClient, policyDomain: string, uris: DmarcUri[]): Promise<void> {
  await Promise.all(
    uris.map(async (u) => {
      if (!u.domain || u.scheme !== 'mailto' || related(u.domain, policyDomain)) return;
      const sel = await prefixedTxt(dns, `${policyDomain}._report._dmarc.${u.domain}`, DMARC_RE);
      u.authorized = sel.failed ? null : sel.matching.length > 0;
    }),
  );
}

export async function checkDmarc(ctx: CheckContext): Promise<CheckResult<DmarcData>> {
  const started = performance.now();
  const f = new Findings();
  const { dns, domain } = ctx;
  const data: DmarcData = { name: null, record: null, records: [], inherited: false, tags: {}, rua: [], ruf: [] };
  const done = () => result(ctx, 'dmarc', started, f, data);

  // Policy discovery: the domain itself, then its parents (DMARCbis tree walk, without the TLD).
  const labels = domain.name.split('.');
  let sel = await prefixedTxt(dns, `_dmarc.${domain.name}`, DMARC_RE);
  if (sel.failed) {
    f.lookupFailed('dmarc.lookup-failed', 'the DMARC record', sel.result);
    return done();
  }
  data.name = domain.name;
  for (let i = 1; !sel.matching.length && i < labels.length - 1 && i < 8; i++) {
    const parent = labels.slice(i).join('.');
    const p = await prefixedTxt(dns, `_dmarc.${parent}`, DMARC_RE);
    if (p.failed) {
      // Unknown, not "missing": the parent might have the policy that applies.
      f.lookupFailed('dmarc.lookup-failed', `the DMARC record of ${parent}`, p.result);
      return done();
    }
    if (p.matching.length) {
      sel = p;
      data.name = parent;
      data.inherited = true;
    }
  }
  data.records = sel.matching;
  if (!sel.matching.length) {
    data.name = null;
    f.error(
      'dmarc.missing',
      'No DMARC record',
      `Publish a record at _dmarc.${domain.name}, e.g. "v=DMARC1; p=none; rua=mailto:dmarc@${domain.name}" to start collecting reports, then move to p=quarantine or p=reject.`,
      { refs: [ref('rfc7489', '6.1'), ref('rfc7489', '6.6.3')] },
    );
    return done();
  }
  if (sel.matching.length > 1) {
    f.error(
      'dmarc.multiple',
      `${sel.matching.length} DMARC records at _dmarc.${data.name}`,
      'With more than one record, receivers apply no DMARC policy at all. Keep exactly one.',
      { refs: [ref('rfc7489', '6.6.3')] },
    );
    return done();
  }

  const record = sel.matching[0]!;
  data.record = record;
  const { tags, order, errors } = parseTags(record);
  data.tags = tags;
  if (data.inherited) {
    f.info(
      'dmarc.inherited',
      `No own record: the policy of ${data.name} applies`,
      `Receivers use the subdomain policy (sp=${tags.sp ?? tags.p ?? '?'}) of _dmarc.${data.name}. Reports go to that domain's addresses.`,
      { refs: [ref('rfc7489', '6.6.3'), ref('dmarcbis')] },
    );
  }
  for (const e of errors) f.error('dmarc.syntax', 'Malformed DMARC record', e, { refs: [ref('rfc7489', '6.4')] });
  if (order[0] !== 'v') {
    f.error('dmarc.version-first', '"v=DMARC1" must be the first tag', record, { refs: [ref('rfc7489', '6.4')] });
  }

  const pol = (k: 'p' | 'sp' | 'np') => {
    const v = tags[k]?.toLowerCase();
    if (v !== undefined && !POLICIES.includes(v)) {
      f.error('dmarc.invalid-policy', `Invalid ${k}=${tags[k]}`, `${k}= must be none, quarantine or reject.`, {
        refs: [ref('rfc7489', '6.3')],
      });
      return null;
    }
    return v ?? null;
  };
  const p = pol('p');
  const sp = pol('sp');
  pol('np');
  const effective = data.inherited ? (sp ?? p) : p;
  if (tags.p === undefined) {
    f.error(
      'dmarc.no-policy',
      'The record has no "p=" tag',
      tags.rua
        ? 'Receivers treat it as p=none (monitoring only), because a report address is given.'
        : 'Without p= and rua=, receivers ignore the record.',
      { refs: [ref('rfc7489', '6.6.3')] },
    );
  } else if (effective === 'none') {
    f.warning(
      'dmarc.p-none',
      'Policy is "none": spoofed mail is still delivered',
      'p=none only collects reports. Once the reports show that all legitimate mail passes, move to p=quarantine and then p=reject.',
      { refs: [ref('rfc7489', '6.3'), ref('rfc7489', '6.7')] },
    );
  } else if (effective === 'quarantine') {
    f.info(
      'dmarc.p-quarantine',
      'Policy is "quarantine"',
      'Failing mail goes to spam. p=reject gives the strongest protection.',
      {
        refs: [ref('rfc7489', '6.3')],
      },
    );
  }
  if (!data.inherited && p && p !== 'none' && sp === 'none') {
    f.warning(
      'dmarc.sp-none',
      'Subdomains are not protected (sp=none)',
      `Spoofed mail from any subdomain of ${domain.name} is delivered.`,
      {
        refs: [ref('rfc7489', '6.3')],
      },
    );
  }

  if (tags.pct !== undefined) {
    const n = Number(tags.pct);
    if (!/^\d{1,3}$/.test(tags.pct) || n > 100) {
      f.error('dmarc.invalid-pct', `Invalid pct=${tags.pct}`, 'pct= must be an integer from 0 to 100.', {
        refs: [ref('rfc7489', '6.3')],
      });
    } else if (n < 100) {
      f.warning(
        'dmarc.pct',
        `The policy applies to ${n}% of failing mail`,
        `The rest gets the next weaker policy. DMARCbis replaces pct= by t= (testing); use pct=100 (or leave it out).`,
        { refs: [ref('rfc7489', '6.6.4'), ref('dmarcbis')] },
      );
    }
  }
  for (const k of ['adkim', 'aspf'] as const) {
    if (tags[k] !== undefined && !['r', 's'].includes(tags[k]!.toLowerCase())) {
      f.error('dmarc.invalid-alignment', `Invalid ${k}=${tags[k]}`, `${k}= must be r (relaxed) or s (strict).`, {
        refs: [ref('rfc7489', '6.3')],
      });
    }
  }
  if (
    tags.fo !== undefined &&
    !tags.fo.split(':').every((x) => ['0', '1', 'd', 's'].includes(x.trim().toLowerCase()))
  ) {
    f.warning('dmarc.invalid-fo', `Invalid fo=${tags.fo}`, 'fo= is a colon-separated list of 0, 1, d and s.', {
      refs: [ref('rfc7489', '6.3')],
    });
  }
  if (tags.ri !== undefined && !/^\d+$/.test(tags.ri)) {
    f.warning('dmarc.invalid-ri', `Invalid ri=${tags.ri}`, 'ri= is the report interval in seconds.', {
      refs: [ref('rfc7489', '6.3')],
    });
  }
  if (tags.rf !== undefined && tags.rf.toLowerCase() !== 'afrf') {
    f.warning('dmarc.invalid-rf', `Unsupported rf=${tags.rf}`, 'The only defined failure report format is "afrf".', {
      refs: [ref('rfc7489', '6.3')],
    });
  }
  const unknown = order.filter((k) => !KNOWN_TAGS.has(k));
  if (unknown.length) {
    f.info(
      'dmarc.unknown-tags',
      `Unknown tag${unknown.length === 1 ? '' : 's'}: ${unknown.join(', ')}`,
      'Receivers ignore unknown tags; check for typos.',
      {
        refs: [ref('rfc7489', '6.3')],
      },
    );
  }

  // Report destinations.
  const rua = parseUris(tags.rua, ctx.known.monitoredAddresses);
  const ruf = parseUris(tags.ruf, ctx.known.monitoredAddresses);
  data.rua = rua.uris;
  data.ruf = ruf.uris;
  for (const u of [...rua.uris, ...ruf.uris]) {
    if (u.problem) {
      // A warning, not an error: the policy works; only this destination gets no reports.
      f.warning(
        'dmarc.invalid-uri',
        `Invalid report address "${u.uri}"`,
        `${u.problem[0]!.toUpperCase()}${u.problem.slice(1)}. Receivers ignore this destination, so it gets no reports.`,
        { subject: u.uri, refs: [ref('rfc7489', '6.2'), ref('rfc5322', '3.4.1')] },
      );
      continue;
    }
    if (u.scheme !== 'mailto') {
      f.warning(
        'dmarc.non-mailto',
        `Report URI "${u.uri}" is not mailto:`,
        'Receivers are only required to support mailto: report addresses.',
        {
          refs: [ref('rfc7489', '6.2')],
        },
      );
    }
  }
  const policyDomain = data.name!;
  await verifyExternal(dns, policyDomain, [...data.rua, ...data.ruf]);
  for (const u of [...data.rua, ...data.ruf]) {
    if (u.authorized === false) {
      f.error(
        'dmarc.external-unauthorized',
        `${u.domain} has not authorised reports for ${policyDomain}`,
        `Receivers only send reports to ${u.address} if ${policyDomain}._report._dmarc.${u.domain} has a TXT record "v=DMARC1". Without it, these reports are not sent.`,
        { subject: u.address ?? u.uri, refs: [ref('rfc7489', '7.1')] },
      );
    }
  }
  const validRua = data.rua.filter((u) => !u.problem);
  if (!validRua.length) {
    f.info(
      'dmarc.no-rua',
      data.rua.length ? 'No usable aggregate report address (rua=)' : 'No aggregate report address (rua=)',
      'Without rua= you get no DMARC reports, so failures go unnoticed. Add rua=mailto:… and let MailWatch read that mailbox.',
      {
        refs: [ref('rfc7489', '7.2')],
      },
    );
  } else if (!validRua.some((u) => u.monitored)) {
    f.info(
      'dmarc.rua-unmonitored',
      'MailWatch does not read the aggregate report mailbox',
      `Reports go to ${validRua.map((u) => u.address ?? u.uri).join(', ')}. Configure that mailbox as MAILBOX_n (and MAILBOX_n_ADDRESS) to analyse them here.`,
    );
  }
  if (data.ruf.some((u) => !u.problem) && !data.ruf.some((u) => u.monitored)) {
    f.info(
      'dmarc.ruf-unmonitored',
      'MailWatch does not read the failure report mailbox',
      `Failure reports go to ${data.ruf
        .filter((u) => !u.problem)
        .map((u) => u.address ?? u.uri)
        .join(', ')}.`,
    );
  }

  if (!f.list.some((x) => x.level === 'error' || x.level === 'warning')) {
    f.ok(
      'dmarc.ok',
      `DMARC policy "${effective}"${tags.pct && tags.pct !== '100' ? ` (pct=${tags.pct})` : ''}`,
      record,
      { refs: [ref('rfc7489', '6.3')] },
    );
  }
  return done();
}
