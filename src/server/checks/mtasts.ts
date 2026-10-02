// MTA-STS (RFC 8461): the _mta-sts TXT record, the HTTPS policy, and whether every MX is covered.
import { createHash } from 'node:crypto';
import type { CheckResult, MtaStsData } from '../../shared/types.ts';
import { type CheckContext, certExpiry, Findings, httpsGet, parseTags, prefixedTxt, ref, result } from './util.ts';

const STS_RE = /^v\s*=\s*STSv1\s*(;|$)/i;
const MAX_AGE_LIMIT = 31_557_600;

export interface ParsedPolicy {
  version: string | null;
  mode: string | null;
  maxAge: number | null;
  mx: string[];
  errors: string[];
}

/** Parses a policy file (RFC 8461 §3.2): "key: value" lines, CRLF or LF. */
export function parsePolicy(text: string): ParsedPolicy {
  const out: ParsedPolicy = { version: null, mode: null, maxAge: null, mx: [], errors: [] };
  const seen = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const m = /^([a-z_]+)\s*:\s*(.*)$/i.exec(line);
    if (!m) {
      out.errors.push(`"${line}" is not a "key: value" line`);
      continue;
    }
    const k = m[1]!.toLowerCase();
    const v = m[2]!.trim();
    if (k !== 'mx' && seen.has(k)) out.errors.push(`"${k}" appears more than once`);
    seen.add(k);
    if (k === 'version') out.version = v;
    else if (k === 'mode') out.mode = v.toLowerCase();
    else if (k === 'max_age') {
      if (!/^\d{1,10}$/.test(v)) out.errors.push(`max_age "${v}" is not a number`);
      else out.maxAge = Number(v);
    } else if (k === 'mx') out.mx.push(v.toLowerCase().replace(/\.$/, ''));
  }
  if (out.version !== 'STSv1')
    out.errors.push(out.version ? `unsupported version "${out.version}"` : 'version is missing');
  if (!out.mode) out.errors.push('mode is missing');
  else if (!['enforce', 'testing', 'none'].includes(out.mode)) out.errors.push(`invalid mode "${out.mode}"`);
  if (out.maxAge === null) out.errors.push('max_age is missing');
  else if (out.maxAge > MAX_AGE_LIMIT) out.errors.push(`max_age ${out.maxAge} exceeds ${MAX_AGE_LIMIT}`);
  if (out.mode && out.mode !== 'none' && !out.mx.length) out.errors.push('no mx patterns');
  return out;
}

/** "*.example.com" matches exactly one extra leftmost label (RFC 8461 §4.1). */
export function mxMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  if (p.startsWith('*.')) {
    const rest = p.slice(2);
    const dot = h.indexOf('.');
    return dot > 0 && h.slice(dot + 1) === rest;
  }
  return p === h;
}

export async function checkMtaSts(ctx: CheckContext): Promise<CheckResult<MtaStsData>> {
  const started = performance.now();
  const f = new Findings();
  const { dns, domain } = ctx;
  const policyUrl = `https://mta-sts.${domain.name}/.well-known/mta-sts.txt`;
  const data: MtaStsData = {
    record: null,
    records: [],
    id: null,
    policyUrl,
    fetch: null,
    raw: null,
    policy: null,
    coverage: [],
  };
  const done = () => result(ctx, 'mta-sts', started, f, data);

  const sel = await prefixedTxt(dns, `_mta-sts.${domain.name}`, STS_RE);
  if (sel.failed) {
    f.lookupFailed('mta-sts.lookup-failed', 'the MTA-STS record', sel.result);
    return done();
  }
  data.records = sel.matching;
  if (!sel.matching.length) {
    f.info(
      'mta-sts.missing',
      'MTA-STS is not deployed',
      'Without MTA-STS (or DANE), senders fall back to unencrypted delivery when STARTTLS is stripped by an attacker. Publish _mta-sts TXT and a policy at ' +
        `${policyUrl}, starting in "mode: testing".`,
      { refs: [ref('rfc8461', '3')] },
    );
    return done();
  }
  if (sel.matching.length > 1) {
    f.error(
      'mta-sts.multiple',
      `${sel.matching.length} MTA-STS records`,
      'With more than one record, senders assume there is no policy. Keep exactly one.',
      {
        refs: [ref('rfc8461', '3.1')],
      },
    );
    return done();
  }
  const record = sel.matching[0]!;
  data.record = record;
  const { tags, errors } = parseTags(record);
  data.id = tags.id ?? null;
  for (const e of errors) f.error('mta-sts.syntax', 'Malformed MTA-STS record', e, { refs: [ref('rfc8461', '3.1')] });
  if (!tags.id) {
    f.error(
      'mta-sts.no-id',
      'The MTA-STS record has no "id"',
      'id= (1 to 32 letters and digits) tells senders when the policy changes; without it the record is invalid.',
      {
        refs: [ref('rfc8461', '3.1')],
      },
    );
  } else if (!/^[a-z0-9]{1,32}$/i.test(tags.id)) {
    f.error('mta-sts.bad-id', `Invalid id "${tags.id}"`, 'id= must be 1 to 32 letters and digits.', {
      refs: [ref('rfc8461', '3.1')],
    });
  }

  // The policy, over HTTPS with a valid certificate and without redirects (§3.3).
  try {
    const res = await httpsGet(policyUrl, dns, ctx.cfg.httpTimeoutMs, 64 * 1024);
    data.fetch = {
      status: res.status,
      contentType: res.contentType,
      redirect: res.location,
      error: null,
      cert: res.cert,
    };
    if (!res.authorized) {
      f.error(
        'mta-sts.policy-cert',
        'The policy host’s certificate is not valid',
        `${res.authorizationError}. Senders refuse to use the policy (sts-webpki-invalid).`,
        { subject: `mta-sts.${domain.name}`, refs: [ref('rfc8461', '3.3')] },
      );
    }
    if (res.cert)
      certExpiry(f, 'mta-sts', res.cert, ctx.cfg.certWarnDays, `mta-sts.${domain.name}`, `mta-sts.${domain.name}`);
    if (res.status >= 300 && res.status < 400) {
      f.error(
        'mta-sts.redirect',
        'The policy URL redirects',
        `HTTP ${res.status} to ${res.location ?? '?'}. Senders must not follow redirects, so they find no policy.`,
        {
          refs: [ref('rfc8461', '3.3')],
        },
      );
    } else if (res.status !== 200) {
      f.error(
        'mta-sts.http-status',
        `The policy URL returns HTTP ${res.status}`,
        `Senders find no policy at ${policyUrl} (sts-policy-fetch-error).`,
        {
          refs: [ref('rfc8461', '3.3')],
        },
      );
    } else {
      data.raw = res.body;
      const ct = (res.contentType ?? '').split(';')[0]!.trim().toLowerCase();
      if (ct !== 'text/plain') {
        f.warning(
          'mta-sts.content-type',
          `The policy is served as "${res.contentType ?? 'no content type'}"`,
          'The policy must be served as text/plain; some senders reject other types.',
          {
            refs: [ref('rfc8461', '3.2')],
          },
        );
      }
    }
  } catch (e) {
    const msg = (e as Error).message;
    data.fetch = { status: null, contentType: null, redirect: null, error: msg, cert: null };
    f.error(
      'mta-sts.fetch-failed',
      'The policy cannot be fetched',
      `${policyUrl}: ${msg}. Senders treat this as "no policy" (sts-policy-fetch-error).`,
      {
        refs: [ref('rfc8461', '3.3')],
      },
    );
  }

  if (data.raw !== null) {
    const pol = parsePolicy(data.raw);
    data.policy = { version: pol.version, mode: pol.mode, maxAge: pol.maxAge, mx: pol.mx };
    for (const e of pol.errors)
      f.error('mta-sts.policy-invalid', 'Invalid MTA-STS policy', e, { refs: [ref('rfc8461', '3.2')] });
    if (pol.mode === 'testing') {
      f.info(
        'mta-sts.testing',
        'MTA-STS is in testing mode',
        'Senders report failures (TLS-RPT) but still deliver. Switch to "mode: enforce" once the TLS reports show no failures.',
        { refs: [ref('rfc8461', '5')] },
      );
    } else if (pol.mode === 'none') {
      f.warning(
        'mta-sts.mode-none',
        'MTA-STS mode is "none"',
        'The policy is being withdrawn: senders do not apply it.',
        { refs: [ref('rfc8461', '5')] },
      );
    }
    if (pol.maxAge !== null && pol.maxAge < 86_400) {
      f.warning(
        'mta-sts.short-max-age',
        `max_age is only ${pol.maxAge} seconds`,
        'Senders refetch constantly and an attacker blocking the fetch can bypass the policy sooner. Use weeks (e.g. 604800 or more).',
        {
          refs: [ref('rfc8461', '3.2')],
        },
      );
    } else if (pol.maxAge !== null && pol.maxAge < 604_800) {
      const days = Math.round(pol.maxAge / 86_400);
      f.info(
        'mta-sts.max-age',
        `max_age is ${days} day${days === 1 ? '' : 's'}`,
        'Values of weeks or more are recommended once the policy is stable.',
        {
          refs: [ref('rfc8461', '3.2')],
        },
      );
    }

    // Every MX must match a pattern and present a valid certificate (§4.1, §4.2).
    const enforce = pol.mode === 'enforce';
    const mxHosts = (ctx.mx?.records ?? []).map((r) => r.exchange);
    for (const mx of mxHosts) {
      const probes = (ctx.mx?.smtp ?? []).filter((p) => p.host === mx && p.tls);
      const certValid = probes.length ? probes.every((p) => p.tls!.authorized && p.tls!.hostnameMatch) : null;
      const matched = pol.mx.some((p) => mxMatches(p, mx));
      data.coverage.push({ mx, matched, certValid });
      if (pol.mode === 'none') continue;
      if (!matched) {
        f.add(
          enforce ? 'error' : 'warning',
          'mta-sts.mx-not-covered',
          `MX ${mx} is not in the MTA-STS policy`,
          `${enforce ? 'Senders that apply the policy do not deliver to this MX.' : 'In enforce mode, senders would not deliver to this MX.'} Policy mx: ${pol.mx.join(', ') || '(none)'}.`,
          { subject: mx, refs: [ref('rfc8461', '4.1')] },
        );
      }
      if (certValid === false) {
        f.add(
          enforce ? 'error' : 'warning',
          'mta-sts.mx-cert',
          `MX ${mx} has no valid certificate for its name`,
          `${enforce ? 'Senders that apply the policy do not deliver to this MX.' : 'In enforce mode, senders would not deliver to this MX.'}`,
          { subject: mx, refs: [ref('rfc8461', '4.2')] },
        );
      }
    }
    const unused = pol.mx.filter((p) => !mxHosts.some((h) => mxMatches(p, h)));
    if (unused.length && mxHosts.length) {
      f.info(
        'mta-sts.unused-pattern',
        'Policy patterns that match no MX',
        `${unused.join(', ')} match none of the current MX hosts.`,
        { refs: [ref('rfc8461', '3.2')] },
      );
    }

    // A changed policy needs a new id, otherwise senders keep their cached copy (§3.1). The
    // policy first seen under the current id is remembered, so the warning lasts until the id
    // changes, not just for the one check that saw the edit.
    const prev = ctx.previous.get('mta-sts')?.data as MtaStsData | undefined;
    const hash = createHash('sha256').update(normalise(data.raw)).digest('hex');
    const known =
      prev?.idPolicy ??
      (prev?.id && prev.raw
        ? { id: prev.id, hash: createHash('sha256').update(normalise(prev.raw)).digest('hex') }
        : null);
    data.idPolicy = known && data.id && known.id === data.id ? known : data.id ? { id: data.id, hash } : null;
    if (data.idPolicy && data.idPolicy.hash !== hash) {
      f.warning(
        'mta-sts.id-unchanged',
        'The policy changed but the id did not',
        `Senders only refetch the policy when the id in _mta-sts.${domain.name} changes, so they keep using the previous policy until max_age expires. Update id=.`,
        { refs: [ref('rfc8461', '3.1')] },
      );
    }
  }

  if (!f.list.some((x) => x.level === 'error' || x.level === 'warning')) {
    f.ok(
      'mta-sts.ok',
      `MTA-STS policy "${data.policy?.mode ?? '?'}" covers every MX`,
      `id=${data.id}, max_age=${data.policy?.maxAge ?? '?'}`,
      {
        refs: [ref('rfc8461')],
      },
    );
  }
  return done();
}

const normalise = (s: string) => s.replace(/\r/g, '').trim();
