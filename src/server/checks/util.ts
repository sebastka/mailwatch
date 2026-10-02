// Building blocks shared by the checks.
import { X509Certificate, createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { request as httpsRequest } from 'node:https';
import { checkServerIdentity, type TLSSocket } from 'node:tls';
import type { CertInfo, CheckKind, CheckResult, Finding, Level, RfcRef } from '../../shared/types.ts';
import type { Config } from '../config.ts';
import type { DnsClient, DnsResult } from '../dns.ts';
import { answered } from '../dns.ts';

export const LEVEL_ORDER: Record<Level, number> = { ok: 0, info: 1, warning: 2, error: 3 };

export const worst = (levels: Level[]): Level =>
  levels.reduce<Level>((w, l) => (LEVEL_ORDER[l] > LEVEL_ORDER[w] ? l : w), 'ok');

export const ref = (doc: string, section?: string): RfcRef => (section ? { doc, section } : { doc });

/** Collects the findings of one check. */
export class Findings {
  readonly list: Finding[] = [];

  add(
    level: Level,
    code: string,
    title: string,
    detail: string,
    opts: { subject?: string; refs?: RfcRef[] } = {},
  ): Finding {
    const f: Finding = { code, level, title, detail };
    if (opts.subject) f.subject = opts.subject;
    if (opts.refs?.length) f.refs = opts.refs;
    this.list.push(f);
    return f;
  }

  ok(code: string, title: string, detail = '', opts: { subject?: string; refs?: RfcRef[] } = {}) {
    return this.add('ok', code, title, detail, opts);
  }
  info(code: string, title: string, detail: string, opts: { subject?: string; refs?: RfcRef[] } = {}) {
    return this.add('info', code, title, detail, opts);
  }
  warning(code: string, title: string, detail: string, opts: { subject?: string; refs?: RfcRef[] } = {}) {
    return this.add('warning', code, title, detail, opts);
  }
  error(code: string, title: string, detail: string, opts: { subject?: string; refs?: RfcRef[] } = {}) {
    return this.add('error', code, title, detail, opts);
  }

  /** A DNS lookup that did not get an answer: the check cannot conclude. */
  lookupFailed(code: string, what: string, r: DnsResult<unknown>, subject?: string) {
    const why =
      r.rcode === 'SERVFAIL'
        ? 'the resolver answered SERVFAIL, which with DNSSEC usually means the answer failed validation (bogus signatures or a broken chain of trust)'
        : r.rcode === 'TIMEOUT'
          ? `no resolver answered (${r.error ?? 'timeout'})`
          : `the resolver answered ${r.rcode}`;
    return this.warning(code, `Could not look up ${what}`, `The lookup of ${r.name} (${r.type}) failed: ${why}.`, {
      ...(subject ? { subject } : {}),
    });
  }
}

export interface DomainCheckInput {
  name: string;
  dkimSelectors: string[];
  senderIps: string[];
}

/** What the checks of a domain know besides DNS: selectors and IPs seen in reports and delivery tests. */
export interface KnownFacts {
  /** DKIM selectors seen for this domain in DMARC reports. */
  reportSelectors: string[];
  /** DKIM selectors seen in delivered probes signed by this domain. */
  probeSelectors: string[];
  /** Sender IPs seen in delivered probes (the connecting client at the recipient). */
  probeIps: string[];
  /** Mailboxes MailWatch reads, so report destinations can be marked as monitored. */
  monitoredAddresses: string[];
}

export interface CheckContext {
  domain: DomainCheckInput;
  dns: DnsClient;
  /** For the blocklist lookups only (DNSBL_RESOLVERS); the same client when they are the same resolvers. */
  blocklistDns: DnsClient;
  /** SMTP probes of this run, shared by the domains that use the same MX hosts. */
  probes: import('./smtp.ts').ProbeCache;
  cfg: Config['checks'];
  known: KnownFacts;
  now: Date;
  /** The previous results of this domain, to detect changes (e.g. an MTA-STS policy without a new id). */
  previous: Map<CheckKind, CheckResult>;
  /** Results of this run so far (the checks run in order). */
  current: Map<CheckKind, CheckResult>;
  /** Filled by the MX check, used by MTA-STS, DANE and the blocklists. */
  mx?: import('../../shared/types.ts').MxData;
}

export function result<T>(
  ctx: CheckContext,
  check: CheckKind,
  started: number,
  findings: Findings,
  data: T,
): CheckResult<T> {
  return {
    domain: ctx.domain.name,
    check,
    level: worst(findings.list.map((f) => f.level)),
    checkedAt: ctx.now.toISOString(),
    durationMs: Math.round(performance.now() - started),
    findings: findings.list,
    data,
  };
}

/** The single TXT record starting with `prefix` (case-insensitive), as RFC 7208/7489/8461/8460 select them. */
export async function prefixedTxt(
  dns: DnsClient,
  name: string,
  prefix: RegExp,
): Promise<{ result: DnsResult<string>; matching: string[]; failed: boolean }> {
  const r = await dns.txt(name);
  return { result: r, matching: r.records.filter((t) => prefix.test(t)), failed: !answered(r) };
}

/** Parses "k=v; k=v" tag lists (DKIM, DMARC, MTA-STS, TLS-RPT, BIMI). Keys are lowercased. */
export function parseTags(s: string): { tags: Record<string, string>; order: string[]; errors: string[] } {
  const tags: Record<string, string> = {};
  const order: string[] = [];
  const errors: string[] = [];
  for (const part of s.split(';')) {
    const t = part.trim();
    if (!t) continue;
    const eq = t.indexOf('=');
    if (eq <= 0) {
      errors.push(`"${t}" is not a tag=value pair`);
      continue;
    }
    const k = t.slice(0, eq).trim().toLowerCase();
    const v = t.slice(eq + 1).trim();
    if (k in tags) errors.push(`tag "${k}" appears more than once`);
    else order.push(k);
    tags[k] = v;
  }
  return { tags, order, errors };
}

/** Certificate details and the digests DANE matches against. */
export function certInfo(der: Buffer, now = new Date()): CertInfo {
  const x = new X509Certificate(der);
  const spki = x.publicKey.export({ type: 'spki', format: 'der' });
  const hex = (alg: string, b: Buffer) => createHash(alg).update(b).digest('hex');
  const validTo = new Date(x.validTo);
  return {
    subject: x.subject.replace(/\n/g, ', '),
    issuer: x.issuer.replace(/\n/g, ', '),
    sans: (x.subjectAltName ?? '')
      .split(/,\s*/)
      .filter((s) => s.startsWith('DNS:'))
      .map((s) => s.slice(4).toLowerCase()),
    validFrom: new Date(x.validFrom).toISOString(),
    validTo: validTo.toISOString(),
    daysLeft: Math.floor((validTo.getTime() - now.getTime()) / 86_400_000),
    certSha256: hex('sha256', der),
    certSha512: hex('sha512', der),
    spkiSha256: hex('sha256', spki),
    spkiSha512: hex('sha512', spki),
    certDer: der.toString('hex'),
    spkiDer: spki.toString('hex'),
    selfSigned: x.subject === x.issuer && x.verify(x.publicKey),
  };
}

/** Findings for a certificate's remaining validity (shared by SMTP, MTA-STS and BIMI hosts). */
export function certExpiry(
  f: Findings,
  prefix: string,
  cert: CertInfo,
  warnDays: number,
  subject: string,
  what: string,
) {
  if (cert.daysLeft < 0) {
    f.error(
      `${prefix}.cert-expired`,
      `The ${what} certificate has expired`,
      `It expired on ${cert.validTo.slice(0, 10)}.`,
      {
        subject,
        refs: [ref('rfc9525')],
      },
    );
  } else if (cert.daysLeft < 7) {
    f.error(
      `${prefix}.cert-expiring`,
      `The ${what} certificate expires in ${cert.daysLeft} day${cert.daysLeft === 1 ? '' : 's'}`,
      `Valid until ${cert.validTo.slice(0, 10)}. Check that automatic renewal works.`,
      { subject },
    );
  } else if (cert.daysLeft < warnDays) {
    f.warning(
      `${prefix}.cert-expiring`,
      `The ${what} certificate expires in ${cert.daysLeft} days`,
      `Valid until ${cert.validTo.slice(0, 10)}. Check that automatic renewal works.`,
      { subject },
    );
  }
}

/** Private, loopback, link-local and other non-routable addresses (an MX there cannot receive Internet mail). */
export function isNonPublicIp(ip: string): boolean {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return isNonPublicIp(mapped[1]!);
  if (ip.includes(':')) {
    const s = ip.toLowerCase();
    return s === '::1' || s === '::' || /^f[cd]/.test(s) || /^fe[89ab]/.test(s) || s.startsWith('2001:db8');
  }
  const [a, b] = ip.split('.').map(Number) as [number, number];
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a >= 224
  );
}

/** Runs fn over items with at most `limit` in flight. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

export interface HttpsResult {
  status: number;
  contentType: string | null;
  location: string | null;
  body: string;
  bytes: number;
  /** WebPKI validation of the server certificate for the URL's host. */
  authorized: boolean;
  authorizationError: string | null;
  cert: CertInfo | null;
}

/**
 * GET over HTTPS without following redirects, with a timeout and a size limit. The certificate
 * is not enforced by the TLS layer, so that an invalid one can be reported with its details;
 * callers decide from `authorized`.
 */
export function httpsGet(url: string, dns: DnsClient, timeoutMs: number, maxBytes = 1024 * 1024): Promise<HttpsResult> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    if (u.protocol !== 'https:') return reject(new Error('not an https:// URL'));
    // IP literals bypass the lookup below.
    const literal = u.hostname.replace(/^\[|\]$/g, '');
    if (isIP(literal) && isNonPublicIp(literal)) {
      return reject(new Error(`${literal} is a non-public address; not fetched`));
    }
    const req = httpsRequest(
      u,
      {
        method: 'GET',
        rejectUnauthorized: false,
        headers: { 'user-agent': 'MailWatch', accept: '*/*' },
        // Resolved through DNS_RESOLVERS like every other check (not the OS resolver, which may
        // give an internal split-horizon view), so the fetch sees what senders see. URLs come
        // from DNS (BIMI l=/a=, MTA-STS): never connect to internal addresses. The URL host name
        // is still used for SNI and the certificate check.
        lookup: (host, opts, cb) => {
          const fail = (e: Error) => cb(e, opts.all ? [] : '', 0);
          dns.addresses(host).then((r) => {
            const list = r.ips.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
            const wanted = opts.family === 4 || opts.family === 6 ? list.filter((a) => a.family === opts.family) : list;
            if (!wanted.length)
              return fail(new Error(r.failed ? `cannot resolve ${host}: lookup failed` : `${host} has no address`));
            const bad = wanted.find((a) => isNonPublicIp(a.address));
            if (bad) return fail(new Error(`${host} resolves to a non-public address (${bad.address}); not fetched`));
            // Node asks for all addresses (happy eyeballs) or for one.
            if (opts.all) (cb as unknown as (e: null, a: typeof wanted) => void)(null, wanted);
            else cb(null, wanted[0]!.address, wanted[0]!.family);
          }, fail);
        },
      },
      (res) => {
        const sock = res.socket as TLSSocket;
        const peer = sock.getPeerCertificate?.();
        let cert: CertInfo | null = null;
        try {
          cert = peer?.raw ? certInfo(peer.raw) : null;
        } catch {
          cert = null;
        }
        let nameOk = true;
        if (peer?.raw) nameOk = checkServerIdentity(u.hostname, peer) === undefined;
        const authorized = sock.authorized && nameOk;
        const authorizationError = !sock.authorized
          ? String(sock.authorizationError ?? 'certificate not trusted')
          : nameOk
            ? null
            : `certificate is not valid for ${u.hostname}`;
        const chunks: Buffer[] = [];
        let bytes = 0;
        res.on('data', (c: Buffer) => {
          bytes += c.length;
          if (bytes > maxBytes) {
            req.destroy(new Error(`response larger than ${maxBytes} bytes`));
            return;
          }
          chunks.push(c);
        });
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            contentType: (res.headers['content-type'] as string | undefined) ?? null,
            location: (res.headers.location as string | undefined) ?? null,
            body: Buffer.concat(chunks).toString('utf8'),
            bytes,
            authorized,
            authorizationError,
            cert,
          }),
        );
        res.on('error', reject);
      },
    );
    // An overall deadline, not only an idle timeout: a server trickling bytes is cut off too.
    const deadline = setTimeout(() => req.destroy(new Error(`no response within ${timeoutMs / 1000} s`)), timeoutMs);
    req.on('close', () => clearTimeout(deadline));
    req.on('error', reject);
    req.end();
  });
}
