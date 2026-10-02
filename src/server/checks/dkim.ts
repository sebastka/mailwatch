// DKIM key records (RFC 6376 §3.6.1), key algorithms and sizes (RFC 8301, RFC 8463).
import { createHash, createPublicKey } from 'node:crypto';
import type { CheckResult, DkimData, DkimSelector, DkimSource, SpfData } from '../../shared/types.ts';
import { answered } from '../dns.ts';
import { type CheckContext, Findings, mapLimit, parseTags, ref, result } from './util.ts';

const SELECTOR_RE = /^[a-z0-9](?:[a-z0-9._-]{0,62})$/i;

/** RSA modulus length or Ed25519 size of a p= value; null when the key cannot be parsed. */
export function keyBits(type: string, p: string): number | null {
  const der = Buffer.from(p.replace(/\s+/g, ''), 'base64');
  if (!der.length) return null;
  if (type === 'ed25519') return der.length === 32 ? 256 : null;
  for (const t of ['spki', 'pkcs1'] as const) {
    try {
      const key = createPublicKey({ key: der, format: 'der', type: t });
      return key.asymmetricKeyDetails?.modulusLength ?? null;
    } catch {
      // try the other encoding
    }
  }
  return null;
}

export function analyseKey(record: string): Omit<DkimSelector, 'selector' | 'sources' | 'name' | 'found' | 'cname'> & {
  problems: {
    level: 'error' | 'warning' | 'info';
    code: string;
    title: string;
    detail: string;
    section: [string, string];
  }[];
} {
  const { tags, order, errors } = parseTags(record);
  const problems: ReturnType<typeof analyseKey>['problems'] = [];
  for (const e of errors) {
    problems.push({
      level: 'error',
      code: 'dkim.syntax',
      title: 'Malformed key record',
      detail: e,
      section: ['rfc6376', '3.6.1'],
    });
  }
  if (tags.v !== undefined && (tags.v !== 'DKIM1' || order[0] !== 'v')) {
    problems.push({
      level: 'error',
      code: 'dkim.version',
      title: 'Invalid "v=" tag',
      detail: '"v=" must be "DKIM1" and the first tag of the record.',
      section: ['rfc6376', '3.6.1'],
    });
  }
  const keyType = (tags.k ?? 'rsa').toLowerCase();
  const p = tags.p;
  const revoked = p !== undefined && p.trim() === '';
  let bits: number | null = null;
  if (p === undefined) {
    problems.push({
      level: 'error',
      code: 'dkim.no-key',
      title: 'No "p=" tag',
      detail: 'The public key (p=) is required.',
      section: ['rfc6376', '3.6.1'],
    });
  } else if (!revoked) {
    if (keyType !== 'rsa' && keyType !== 'ed25519') {
      problems.push({
        level: 'error',
        code: 'dkim.key-type',
        title: `Unknown key type "${keyType}"`,
        detail: 'Verifiers support "rsa" and "ed25519".',
        section: ['rfc8463', '4.2'],
      });
    } else {
      bits = keyBits(keyType, p);
      if (bits === null) {
        problems.push({
          level: 'error',
          code: 'dkim.bad-key',
          title: 'The public key cannot be decoded',
          detail: 'p= is not a valid base64 DER public key.',
          section: ['rfc6376', '3.6.1'],
        });
      } else if (keyType === 'rsa' && bits < 1024) {
        problems.push({
          level: 'error',
          code: 'dkim.weak-key',
          title: `${bits}-bit RSA key`,
          detail: 'RSA keys must have at least 1024 bits; verifiers reject smaller ones.',
          section: ['rfc8301', '3.2'],
        });
      } else if (keyType === 'rsa' && bits < 2048) {
        problems.push({
          level: 'warning',
          code: 'dkim.short-key',
          title: `${bits}-bit RSA key`,
          detail: 'Signers should use RSA keys of at least 2048 bits.',
          section: ['rfc8301', '3.2'],
        });
      }
    }
  }
  if (tags.h !== undefined) {
    const hashes = tags.h.split(':').map((h) => h.trim().toLowerCase());
    if (!hashes.includes('sha256')) {
      problems.push({
        level: 'error',
        code: 'dkim.sha1',
        title: 'The key only allows SHA-1',
        detail: `h=${tags.h}: rsa-sha1 must not be used for signing and verifiers may ignore it. Allow sha256 (or drop h=).`,
        section: ['rfc8301', '3.1'],
      });
    }
  }
  if (tags.s !== undefined) {
    const svc = tags.s.split(':').map((s) => s.trim());
    if (!svc.includes('*') && !svc.includes('email')) {
      problems.push({
        level: 'error',
        code: 'dkim.service',
        title: 'The key is not for e-mail',
        detail: `s=${tags.s} excludes e-mail.`,
        section: ['rfc6376', '3.6.1'],
      });
    }
  }
  const flags = (tags.t ?? '').split(':').map((s) => s.trim().toLowerCase());
  const testing = flags.includes('y');
  if (testing) {
    problems.push({
      level: 'warning',
      code: 'dkim.testing',
      title: 'Testing mode (t=y)',
      detail: 'Verifiers must treat mail signed with this key like unsigned mail. Remove t=y once DKIM works.',
      section: ['rfc6376', '3.6.1'],
    });
  }
  return {
    record,
    tags,
    keyType: p === undefined ? null : keyType,
    keyBits: bits,
    testing,
    revoked,
    error: null,
    problems,
  };
}

export async function checkDkim(ctx: CheckContext): Promise<CheckResult<DkimData>> {
  const started = performance.now();
  const f = new Findings();
  const { dns, domain } = ctx;

  const sources = new Map<string, Set<DkimSource>>();
  const add = (sel: string, src: DkimSource) => {
    const s = sel.toLowerCase();
    if (!SELECTOR_RE.test(s)) return;
    if (!sources.has(s)) sources.set(s, new Set());
    sources.get(s)!.add(src);
  };
  for (const s of domain.dkimSelectors) add(s, 'configured');
  for (const s of ctx.known.reportSelectors) add(s, 'reports');
  for (const s of ctx.known.probeSelectors) add(s, 'delivery');
  for (const s of ctx.cfg.commonSelectors) add(s, 'common');

  const looked = await mapLimit(
    [...sources.entries()],
    8,
    async ([selector, src]): Promise<DkimSelector & { failed: boolean; multiple: number }> => {
      const name = `${selector}._domainkey.${domain.name}`;
      const r = await dns.txt(name);
      const base = {
        selector,
        sources: [...src].sort(),
        name,
        cname: r.cnames.at(-1) ?? null,
        failed: !answered(r),
        multiple: 0,
      };
      // A wildcard or unrelated TXT is not a key: require p= or v=DKIM1.
      const keys = r.records.filter((t) => /(^|;)\s*(v\s*=\s*DKIM1|p\s*=)/i.test(t));
      if (!keys.length) {
        return {
          ...base,
          found: false,
          record: null,
          tags: {},
          keyType: null,
          keyBits: null,
          testing: false,
          revoked: false,
          error: base.failed ? r.rcode : null,
        };
      }
      const { problems: _p, ...k } = analyseKey(keys[0]!);
      return { ...base, ...k, found: true, multiple: keys.length };
    },
  );

  // Key age: DNS has no publication date, so a key is dated from the first check that saw it.
  const before = new Map(
    ((ctx.previous.get('dkim')?.data as DkimData | null | undefined)?.selectors ?? []).map((s) => [s.selector, s]),
  );
  for (const s of looked) {
    const p = s.found && !s.revoked ? s.tags.p?.replace(/\s+/g, '') : undefined;
    if (!p) continue;
    s.keyHash = createHash('sha256').update(p).digest('hex').slice(0, 16);
    const prev = before.get(s.selector);
    s.keySince = (prev?.keyHash === s.keyHash && prev.keySince) || ctx.now.toISOString();
  }

  const found = looked.filter((s) => s.found);
  for (const s of looked) {
    const subject = s.selector;
    const why = s.sources.filter((x) => x !== 'common');
    if (!s.found) {
      if (s.failed) {
        f.warning('dkim.lookup-failed', `Could not look up selector "${s.selector}"`, `${s.name}: ${s.error}.`, {
          subject,
        });
      } else if (why.includes('configured') || why.includes('delivery')) {
        f.error(
          'dkim.selector-missing',
          `No DKIM key for selector "${s.selector}"`,
          `${s.name} has no key record, although the selector is ${why.includes('delivery') ? 'used to sign the delivery tests' : 'configured (DOMAIN_n_DKIM_SELECTORS)'}. Signatures with it fail.`,
          { subject, refs: [ref('rfc6376', '3.6.2.2')] },
        );
      } else if (why.includes('reports')) {
        f.info(
          'dkim.selector-gone',
          `Selector "${s.selector}" from the DMARC reports has no key`,
          `${s.name} has no key record. Fine if the selector was retired; otherwise mail signed with it fails DKIM.`,
          { subject, refs: [ref('rfc6376', '3.6.2.2')] },
        );
      }
      continue;
    }
    if (s.multiple > 1) {
      f.error(
        'dkim.multiple',
        `Selector "${s.selector}" has ${s.multiple} key records`,
        'Publish exactly one key record per selector; verifiers may pick any of them.',
        {
          subject,
          refs: [ref('rfc6376', '3.6.2.2')],
        },
      );
    }
    const { problems } = analyseKey(s.record!);
    for (const p of problems)
      f.add(p.level, p.code, `Selector "${s.selector}": ${p.title}`, p.detail, {
        subject,
        refs: [ref(p.section[0], p.section[1])],
      });
    if (s.revoked) {
      f.info(
        'dkim.revoked',
        `Selector "${s.selector}" is revoked`,
        'The key record has an empty p=, so signatures with this selector fail. That is the right way to retire a selector.',
        {
          subject,
          refs: [ref('rfc6376', '3.6.1')],
        },
      );
    }
    const ageDays = s.keySince ? Math.floor((ctx.now.getTime() - Date.parse(s.keySince)) / 86_400_000) : 0;
    const old = !s.revoked && ctx.cfg.dkimMaxAgeDays > 0 && ageDays > ctx.cfg.dkimMaxAgeDays;
    if (old) {
      f.warning(
        'dkim.old-key',
        `Selector "${s.selector}": key unchanged for ${ageDays} days`,
        `MailWatch first saw this key on ${s.keySince!.slice(0, 10)}. Rotate DKIM keys regularly (every 6–12 months): publish a new selector, sign with it, then revoke the old one (empty p=). Limit: DKIM_KEY_MAX_AGE_DAYS=${ctx.cfg.dkimMaxAgeDays}.`,
        { subject, refs: [ref('m3aawg-dkim'), ref('rfc6376', '3.6.1')] },
      );
    }
    if (!s.revoked && !old && !problems.some((p) => p.level !== 'info')) {
      f.ok(
        'dkim.ok',
        `Selector "${s.selector}": ${s.keyType === 'ed25519' ? 'Ed25519' : `${s.keyBits}-bit RSA`} key`,
        `${s.cname ? `CNAME to ${s.cname}. ` : ''}Found via: ${s.sources.join(', ')}.`,
        { subject, refs: [ref(s.keyType === 'ed25519' ? 'rfc8463' : 'rfc8301')] },
      );
    }
  }
  // "v=spf1 -all" declares that the domain sends no mail: then no key is expected.
  const spf = ctx.current.get('spf')?.data as SpfData | null | undefined;
  const sendsNoMail = spf?.records.length === 1 && /^v=spf1\s+-all\s*$/i.test(spf.records[0]!);
  if (!found.some((s) => !s.revoked) && sendsNoMail) {
    f.info(
      'dkim.not-sending',
      'No DKIM key (the domain sends no mail)',
      'The SPF record "v=spf1 -all" says that no server sends mail for this domain, so no DKIM key is needed.',
      {
        refs: [ref('rfc7208', '5.1')],
      },
    );
  } else if (!found.some((s) => !s.revoked)) {
    f.warning(
      'dkim.none-found',
      'No DKIM key found',
      `None of the ${looked.length} selectors tried has a key. DKIM selectors cannot be listed from DNS: add the ones your mail services use to DOMAIN_n_DKIM_SELECTORS, or wait until DMARC reports or delivery tests reveal them.`,
      { refs: [ref('rfc6376', '3.1')] },
    );
  }

  const selectors: DkimSelector[] = looked
    .filter((s) => s.found || s.sources.some((x) => x !== 'common'))
    .map(({ failed: _f, multiple: _m, ...s }) => s);
  return result(ctx, 'dkim', started, f, { selectors });
}
