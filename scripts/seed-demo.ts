// Fills a separate demo database with synthetic data to preview the UI:
//   npm run demo   (seeds DB_NAME=mailwatch_demo and starts the server on it, MAILWATCH_DEMO=true)
// Three example domains: one healthy, one with warnings, one broken. Nothing touches the network.
import { createHash } from 'node:crypto';
import type {
  CertInfo,
  CheckKind,
  CheckResult,
  DmarcRecordRow,
  Finding,
  Level,
  MxData,
  ProbeStatus,
  SmtpProbe,
  SpfData,
} from '../src/shared/types.ts';
import { worst } from '../src/server/checks/util.ts';
import { config } from '../src/server/config.ts';
import { Store } from '../src/server/db.ts';
import type { NormalizedDmarcReport } from '../src/server/reports/dmarc.ts';
import { normalizeReport } from '../src/server/reports/tlsrpt.ts';

if (!config.db.database.endsWith('_demo')) {
  throw new Error(`refusing to seed "${config.db.database}": the demo database name must end with _demo`);
}
const store = await Store.connect(config.db);
for (const t of [
  'check_results',
  'record_changes',
  'finding_streaks',
  'tls_reports',
  'dmarc_reports',
  'failure_reports',
  'probes',
  'alerts',
  'snoozes',
  'messages',
]) {
  await store.pool.query(`DELETE FROM ${t}`);
}

let seed = 42;
const rand = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31;
const now = Date.now();
const DAY = 86_400_000;
const iso = (ms: number) => new Date(ms).toISOString();
const hex = (s: string) => createHash('sha256').update(s).digest('hex');

// --- Check results --------------------------------------------------------------------

const f = (
  level: Level,
  code: string,
  title: string,
  detail = '',
  refs: Finding['refs'] = [],
  subject?: string,
): Finding => ({
  code,
  level,
  title,
  detail,
  ...(refs.length ? { refs } : {}),
  ...(subject ? { subject } : {}),
});
const r = (doc: string, section?: string) => (section ? { doc, section } : { doc });

function result(domain: string, check: CheckKind, findings: Finding[], data: unknown): CheckResult {
  return {
    domain,
    check,
    level: worst(findings.map((x) => x.level)),
    checkedAt: iso(now - 4 * 60_000),
    durationMs: Math.round(20 + rand() * 300),
    findings,
    data,
  };
}

function cert(cn: string, issuer: string, days: number): CertInfo {
  return {
    subject: `CN=${cn}`,
    issuer: `C=US, O=Let's Encrypt, CN=${issuer}`,
    sans: [cn],
    validFrom: iso(now - (90 - days) * DAY),
    validTo: iso(now + days * DAY),
    daysLeft: days,
    certSha256: hex(`cert:${cn}`),
    certSha512: hex(`cert512:${cn}`),
    spkiSha256: hex(`spki:${cn}`),
    spkiSha512: hex(`spki512:${cn}`),
    certDer: '',
    spkiDer: '',
    selfSigned: false,
  };
}

function probe(host: string, ip: string, opts: { starttls?: boolean; days?: number } = {}): SmtpProbe {
  const starttls = opts.starttls ?? true;
  return {
    host,
    ip,
    port: 25,
    connected: true,
    banner: `220 ${host} ESMTP ready`,
    extensions: [
      'PIPELINING',
      'SIZE 52428800',
      ...(starttls ? ['STARTTLS'] : []),
      'ENHANCEDSTATUSCODES',
      '8BITMIME',
      'SMTPUTF8',
    ],
    starttls,
    tls: starttls
      ? {
          protocol: 'TLSv1.3',
          cipher: 'TLS_AES_256_GCM_SHA384',
          authorized: true,
          authorizationError: null,
          hostnameMatch: true,
          chain: [cert(host, 'R11', opts.days ?? 61)],
        }
      : null,
    error: null,
    durationMs: 180,
  };
}

const mx = (domain: string, hosts: [string, string][], probes: SmtpProbe[], dnssec: boolean): MxData => ({
  records: hosts.map(([h, ip], i) => ({
    preference: 10 * (i + 1),
    exchange: h,
    cname: null,
    addresses: [{ ip, ptr: h, fcrdns: true }],
  })),
  nullMx: false,
  implicit: false,
  dnssec,
  smtp: probes,
  probeEnabled: true,
});

const results: CheckResult[] = [];

// example.com: healthy, MTA-STS enforce, DANE, BIMI.
{
  const d = 'example.com';
  const hosts: [string, string][] = [
    ['mx1.example.com', '192.0.2.25'],
    ['mx2.example.com', '192.0.2.26'],
  ];
  const probes = hosts.map(([h, ip]) => probe(h, ip));
  results.push(
    result(
      d,
      'mx',
      [
        f('ok', 'smtp.ok', 'mx1.example.com: STARTTLS with TLSv1.3, valid certificate', '', [r('rfc3207')]),
        f('ok', 'smtp.ok', 'mx2.example.com: STARTTLS with TLSv1.3, valid certificate', '', [r('rfc3207')]),
        f('ok', 'mx.ok', '2 MX hosts', '10 mx1.example.com, 20 mx2.example.com', [r('rfc5321', '5.1')]),
      ],
      mx(d, hosts, probes, true),
    ),
    result(
      d,
      'spf',
      [
        f(
          'ok',
          'spf.ok',
          'Valid SPF record, 2 of 10 lookups, -all (fail)',
          'v=spf1 mx include:_spf.mailprovider.example -all',
          [r('rfc7208')],
        ),
      ],
      {
        record: 'v=spf1 mx include:_spf.mailprovider.example -all',
        records: ['v=spf1 mx include:_spf.mailprovider.example -all'],
        tree: {
          domain: d,
          record: 'v=spf1 mx include:_spf.mailprovider.example -all',
          terms: [
            { raw: 'mx', qualifier: null, kind: 'mx', value: null, lookups: 1 },
            {
              raw: 'include:_spf.mailprovider.example',
              qualifier: null,
              kind: 'include',
              value: '_spf.mailprovider.example',
              lookups: 1,
              child: {
                domain: '_spf.mailprovider.example',
                record: 'v=spf1 ip4:203.0.113.0/24 -all',
                terms: [
                  { raw: 'ip4:203.0.113.0/24', qualifier: null, kind: 'ip4', value: '203.0.113.0', lookups: 0 },
                  { raw: '-all', qualifier: '-', kind: 'all', value: null, lookups: 0 },
                ],
                error: null,
              },
            },
            { raw: '-all', qualifier: '-', kind: 'all', value: null, lookups: 0 },
          ],
          error: null,
        },
        lookups: 2,
        voidLookups: 0,
        ip4: ['192.0.2.25', '192.0.2.26', '203.0.113.0/24'],
        ip6: [],
        allQualifier: '-',
      },
    ),
    result(
      d,
      'dkim',
      [
        f(
          'ok',
          'dkim.ok',
          'Selector "s2026": 2048-bit RSA key',
          'Found via: configured, delivery, reports.',
          [r('rfc8301')],
          's2026',
        ),
      ],
      {
        selectors: [
          {
            selector: 's2026',
            sources: ['configured', 'delivery', 'reports'],
            name: `s2026._domainkey.${d}`,
            found: true,
            cname: null,
            record: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqh…',
            tags: { v: 'DKIM1', k: 'rsa' },
            keyType: 'rsa',
            keyBits: 2048,
            testing: false,
            revoked: false,
            error: null,
          },
        ],
      },
    ),
    result(
      d,
      'dmarc',
      [
        f('ok', 'dmarc.ok', 'DMARC policy "reject"', 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com', [
          r('rfc7489', '6.3'),
        ]),
      ],
      {
        name: d,
        record: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com; fo=1',
        records: ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com; fo=1'],
        inherited: false,
        tags: { v: 'DMARC1', p: 'reject', rua: 'mailto:dmarc@example.com', ruf: 'mailto:dmarc@example.com', fo: '1' },
        rua: [
          {
            uri: 'mailto:dmarc@example.com',
            scheme: 'mailto',
            address: 'dmarc@example.com',
            domain: d,
            authorized: null,
            monitored: true,
          },
        ],
        ruf: [
          {
            uri: 'mailto:dmarc@example.com',
            scheme: 'mailto',
            address: 'dmarc@example.com',
            domain: d,
            authorized: null,
            monitored: true,
          },
        ],
      },
    ),
    result(
      d,
      'mta-sts',
      [
        f('ok', 'mta-sts.ok', 'MTA-STS policy "enforce" covers every MX', 'id=20260901, max_age=1209600', [
          r('rfc8461'),
        ]),
      ],
      {
        record: 'v=STSv1; id=20260901',
        records: ['v=STSv1; id=20260901'],
        id: '20260901',
        policyUrl: `https://mta-sts.${d}/.well-known/mta-sts.txt`,
        fetch: {
          status: 200,
          contentType: 'text/plain',
          redirect: null,
          error: null,
          cert: cert(`mta-sts.${d}`, 'R10', 70),
        },
        raw: 'version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 1209600\n',
        policy: { version: 'STSv1', mode: 'enforce', maxAge: 1209600, mx: ['mx1.example.com', 'mx2.example.com'] },
        coverage: hosts.map(([h]) => ({ mx: h, matched: true, certValid: true })),
      },
    ),
    result(
      d,
      'tls-rpt',
      [f('ok', 'tls-rpt.ok', 'TLS-RPT record found', 'v=TLSRPTv1; rua=mailto:tlsrpt@example.com', [r('rfc8460', '3')])],
      {
        record: 'v=TLSRPTv1; rua=mailto:tlsrpt@example.com',
        records: ['v=TLSRPTv1; rua=mailto:tlsrpt@example.com'],
        rua: [
          {
            uri: 'mailto:tlsrpt@example.com',
            scheme: 'mailto',
            address: 'tlsrpt@example.com',
            domain: d,
            authorized: null,
            monitored: true,
          },
        ],
      },
    ),
    result(
      d,
      'dane',
      [
        f('ok', 'dane.dnssec', 'The domain is signed with DNSSEC', '', [r('rfc4033')]),
        ...hosts.map(([h]) =>
          f(
            'ok',
            'dane.match',
            `${h}: the certificate matches its TLSA record`,
            '2 usable TLSA records, 1 for another key (e.g. the next one).',
            [r('rfc7672', '3.1')],
            h,
          ),
        ),
      ],
      {
        mxSecure: true,
        zoneSigned: true,
        hosts: hosts.map(([h]) => ({
          mx: h,
          addressSecure: true,
          tlsaSecure: true,
          probed: true,
          tlsa: [
            { usage: 3, selector: 1, matchingType: 1, data: hex(`spki:${h}`), matched: true },
            { usage: 3, selector: 1, matchingType: 1, data: hex(`next:${h}`), matched: false },
          ],
        })),
      },
    ),
    result(
      d,
      'bimi',
      [
        f(
          'ok',
          'bimi.ok',
          'BIMI record and logo are valid',
          'v=BIMI1; l=https://example.com/bimi.svg; a=https://example.com/vmc.pem',
          [r('bimi')],
        ),
      ],
      {
        record: 'v=BIMI1; l=https://example.com/bimi.svg; a=https://example.com/vmc.pem',
        records: ['v=BIMI1; l=https://example.com/bimi.svg; a=https://example.com/vmc.pem'],
        tags: { v: 'BIMI1', l: 'https://example.com/bimi.svg', a: 'https://example.com/vmc.pem' },
        logo: {
          url: 'https://example.com/bimi.svg',
          status: 200,
          contentType: 'image/svg+xml',
          bytes: 4210,
          error: null,
        },
        authority: { url: 'https://example.com/vmc.pem', status: 200, error: null },
      },
    ),
    result(
      d,
      'dnsbl',
      [f('ok', 'dnsbl.ok', 'Not listed', '3 IP addresses and the domain checked against 6 lists.', [r('rfc5782')])],
      {
        zones: [
          'zen.spamhaus.org',
          'bl.spamcop.net',
          'psbl.surriel.com',
          'bl.mailspike.net',
          'dbl.spamhaus.org',
          'multi.surbl.org',
        ],
        ips: [
          ...hosts.map(([h, ip]) => ({ ip, sources: [`MX ${h}`] })),
          { ip: '192.0.2.10', sources: ['sender (delivery tests)'] },
          { ip: d, sources: ['domain'] },
        ].map((x) => ({
          ...x,
          listings: (x.ip === d
            ? ['dbl.spamhaus.org', 'multi.surbl.org']
            : ['zen.spamhaus.org', 'bl.spamcop.net', 'psbl.surriel.com', 'bl.mailspike.net']
          ).map((zone) => ({ zone, listed: false, refused: false, codes: [], reason: null })),
        })),
      },
    ),
  );
}

// example.net: works, with warnings: SPF near the limit, DMARC p=none, MTA-STS testing, short DKIM key.
{
  const d = 'example.net';
  const hosts: [string, string][] = [['mail.example.net', '198.51.100.25']];
  const probes = [probe('mail.example.net', '198.51.100.25', { days: 12 })];
  const spf =
    'v=spf1 include:_spf.google.com include:spf.protection.outlook.com include:sendgrid.net include:mailgun.org include:servers.mcsv.net a mx ~all';
  results.push(
    result(
      d,
      'mx',
      [
        f('info', 'mx.single', 'Only one MX host', 'That is fine: senders queue and retry when it is down.'),
        f(
          'warning',
          'smtp.cert-expiring',
          'The mail.example.net certificate expires in 12 days',
          `Valid until ${iso(now + 12 * DAY).slice(0, 10)}. Check that automatic renewal works.`,
          [],
          'mail.example.net 198.51.100.25',
        ),
      ],
      mx(d, hosts, probes, false),
    ),
    result(
      d,
      'spf',
      [
        f(
          'warning',
          'spf.near-lookup-limit',
          '9 of 10 DNS lookups used',
          'Close to the limit: a provider adding one include to its record would make yours fail.',
          [r('rfc7208', '4.6.4')],
        ),
      ],
      {
        record: spf,
        records: [spf],
        tree: {
          domain: d,
          record: spf,
          terms: spf
            .split(' ')
            .slice(1)
            .map((raw) => ({
              raw,
              qualifier: raw.startsWith('~') ? '~' : null,
              kind: raw.split(':')[0]!.replace('~', ''),
              value: raw.split(':')[1] ?? null,
              lookups: raw.includes('all') ? 0 : raw.startsWith('include') ? 1 : 1,
            })),
          error: null,
        },
        lookups: 9,
        voidLookups: 0,
        ip4: ['198.51.100.25'],
        ip6: [],
        allQualifier: '~',
      },
    ),
    result(
      d,
      'dkim',
      [
        f(
          'warning',
          'dkim.short-key',
          'Selector "selector1": 1024-bit RSA key',
          'Signers should use RSA keys of at least 2048 bits.',
          [r('rfc8301', '3.2')],
          'selector1',
        ),
        f('ok', 'dkim.ok', 'Selector "s1": 2048-bit RSA key', 'Found via: reports, common.', [r('rfc8301')], 's1'),
      ],
      {
        selectors: [
          {
            selector: 'selector1',
            sources: ['common', 'reports'],
            name: `selector1._domainkey.${d}`,
            found: true,
            cname: 'selector1-example-net._domainkey.example.onmicrosoft.com',
            record: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3…',
            tags: { v: 'DKIM1', k: 'rsa' },
            keyType: 'rsa',
            keyBits: 1024,
            testing: false,
            revoked: false,
            error: null,
          },
          {
            selector: 's1',
            sources: ['common', 'reports'],
            name: `s1._domainkey.${d}`,
            found: true,
            cname: null,
            record: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqh…',
            tags: { v: 'DKIM1', k: 'rsa' },
            keyType: 'rsa',
            keyBits: 2048,
            testing: false,
            revoked: false,
            error: null,
          },
        ],
      },
    ),
    result(
      d,
      'dmarc',
      [
        f(
          'warning',
          'dmarc.p-none',
          'Policy is "none": spoofed mail is still delivered',
          'p=none only collects reports. Once the reports show that all legitimate mail passes, move to p=quarantine and then p=reject.',
          [r('rfc7489', '6.3'), r('rfc7489', '6.7')],
        ),
        f(
          'error',
          'dmarc.external-unauthorized',
          'reports.example has not authorised reports for example.net',
          'Receivers only send reports to dmarc@reports.example if example.net._report._dmarc.reports.example has a TXT record "v=DMARC1".',
          [r('rfc7489', '7.1')],
          'dmarc@reports.example',
        ),
      ],
      {
        name: d,
        record: 'v=DMARC1; p=none; rua=mailto:dmarc@example.com,mailto:dmarc@reports.example',
        records: ['v=DMARC1; p=none; rua=mailto:dmarc@example.com,mailto:dmarc@reports.example'],
        inherited: false,
        tags: { v: 'DMARC1', p: 'none', rua: 'mailto:dmarc@example.com,mailto:dmarc@reports.example' },
        rua: [
          {
            uri: 'mailto:dmarc@example.com',
            scheme: 'mailto',
            address: 'dmarc@example.com',
            domain: 'example.com',
            authorized: true,
            monitored: true,
          },
          {
            uri: 'mailto:dmarc@reports.example',
            scheme: 'mailto',
            address: 'dmarc@reports.example',
            domain: 'reports.example',
            authorized: false,
            monitored: false,
          },
        ],
        ruf: [],
      },
    ),
    result(
      d,
      'mta-sts',
      [
        f(
          'info',
          'mta-sts.testing',
          'MTA-STS is in testing mode',
          'Senders report failures (TLS-RPT) but still deliver.',
          [r('rfc8461', '5')],
        ),
        f('ok', 'mta-sts.ok', 'MTA-STS policy "testing" covers every MX', 'id=2026a, max_age=604800', [r('rfc8461')]),
      ],
      {
        record: 'v=STSv1; id=2026a',
        records: ['v=STSv1; id=2026a'],
        id: '2026a',
        policyUrl: `https://mta-sts.${d}/.well-known/mta-sts.txt`,
        fetch: {
          status: 200,
          contentType: 'text/plain; charset=utf-8',
          redirect: null,
          error: null,
          cert: cert(`mta-sts.${d}`, 'R11', 40),
        },
        raw: 'version: STSv1\nmode: testing\nmx: mail.example.net\nmax_age: 604800\n',
        policy: { version: 'STSv1', mode: 'testing', maxAge: 604800, mx: ['mail.example.net'] },
        coverage: [{ mx: 'mail.example.net', matched: true, certValid: true }],
      },
    ),
    result(
      d,
      'tls-rpt',
      [f('ok', 'tls-rpt.ok', 'TLS-RPT record found', 'v=TLSRPTv1; rua=mailto:tlsrpt@example.com', [r('rfc8460', '3')])],
      {
        record: 'v=TLSRPTv1; rua=mailto:tlsrpt@example.com',
        records: ['v=TLSRPTv1; rua=mailto:tlsrpt@example.com'],
        rua: [
          {
            uri: 'mailto:tlsrpt@example.com',
            scheme: 'mailto',
            address: 'tlsrpt@example.com',
            domain: 'example.com',
            authorized: null,
            monitored: true,
          },
        ],
      },
    ),
    result(
      d,
      'dane',
      [
        f(
          'info',
          'dane.no-dnssec',
          'The domain is not signed with DNSSEC',
          'DANE needs DNSSEC on the domain and on the MX hosts’ zones.',
          [r('rfc4033'), r('rfc7672', '2.2')],
        ),
      ],
      {
        mxSecure: false,
        zoneSigned: false,
        hosts: [{ mx: 'mail.example.net', addressSecure: false, tlsa: [], tlsaSecure: false, probed: true }],
      },
    ),
    result(
      d,
      'bimi',
      [
        f(
          'info',
          'bimi.missing',
          'BIMI is not set up',
          'Optional: BIMI shows your logo next to authenticated mail in supporting mailboxes.',
          [r('bimi')],
        ),
      ],
      { record: null, records: [], tags: {}, logo: null, authority: null },
    ),
    result(
      d,
      'dnsbl',
      [
        f(
          'warning',
          'dnsbl.listed',
          '198.51.100.25 is listed on psbl.surriel.com',
          '127.0.0.2. Used as: MX mail.example.net.',
          [r('rfc5782', '2')],
          '198.51.100.25 psbl.surriel.com',
        ),
      ],
      {
        zones: [
          'zen.spamhaus.org',
          'bl.spamcop.net',
          'psbl.surriel.com',
          'bl.mailspike.net',
          'dbl.spamhaus.org',
          'multi.surbl.org',
        ],
        ips: [
          {
            ip: '198.51.100.25',
            sources: ['MX mail.example.net'],
            listings: ['zen.spamhaus.org', 'bl.spamcop.net', 'psbl.surriel.com', 'bl.mailspike.net'].map((zone) => ({
              zone,
              listed: zone === 'psbl.surriel.com',
              refused: false,
              codes: zone === 'psbl.surriel.com' ? ['127.0.0.2'] : [],
              reason: zone === 'psbl.surriel.com' ? 'Listed in PSBL' : null,
            })),
          },
          {
            ip: d,
            sources: ['domain'],
            listings: ['dbl.spamhaus.org', 'multi.surbl.org'].map((zone) => ({
              zone,
              listed: false,
              refused: false,
              codes: [],
              reason: null,
            })),
          },
        ],
      },
    ),
  );
}

// shop.example.org: broken: no DMARC, two SPF records, no STARTTLS on the MX, MTA-STS fetch fails.
{
  const d = 'shop.example.org';
  const hosts: [string, string][] = [['mx.shop.example.org', '203.0.113.40']];
  results.push(
    result(
      d,
      'mx',
      [
        f(
          'error',
          'smtp.no-starttls',
          'mx.shop.example.org does not offer STARTTLS',
          'Mail to this server is sent unencrypted. STARTTLS is also required for MTA-STS and DANE.',
          [r('rfc3207'), r('rfc8461', '4.2')],
          'mx.shop.example.org 203.0.113.40',
        ),
        f(
          'warning',
          'mx.no-ptr',
          'No reverse DNS for 203.0.113.40',
          '203.0.113.40 (MX mx.shop.example.org) has no PTR record.',
          [r('rfc1912', '2.1')],
          '203.0.113.40',
        ),
      ],
      {
        ...mx(d, hosts, [probe('mx.shop.example.org', '203.0.113.40', { starttls: false })], false),
        records: [
          {
            preference: 10,
            exchange: 'mx.shop.example.org',
            cname: null,
            addresses: [{ ip: '203.0.113.40', ptr: null, fcrdns: false }],
          },
        ],
      },
    ),
    result(
      d,
      'spf',
      [
        f(
          'error',
          'spf.multiple',
          '2 SPF records',
          'A domain must publish exactly one SPF record. With several, every receiver returns "permerror" and SPF fails. Merge them into one.',
          [r('rfc7208', '3.2'), r('rfc7208', '4.5')],
        ),
      ],
      {
        record: null,
        records: ['v=spf1 mx -all', 'v=spf1 include:shopplatform.example ~all'],
        tree: null,
        lookups: 0,
        voidLookups: 0,
        ip4: [],
        ip6: [],
        allQualifier: null,
      },
    ),
    result(
      d,
      'dkim',
      [
        f(
          'error',
          'dkim.selector-missing',
          'No DKIM key for selector "shop"',
          'shop._domainkey.shop.example.org has no key record, although the selector is used to sign the delivery tests.',
          [r('rfc6376', '3.6.2.2')],
          'shop',
        ),
      ],
      {
        selectors: [
          {
            selector: 'shop',
            sources: ['delivery'],
            name: `shop._domainkey.${d}`,
            found: false,
            cname: null,
            record: null,
            tags: {},
            keyType: null,
            keyBits: null,
            testing: false,
            revoked: false,
            error: null,
          },
        ],
      },
    ),
    result(
      d,
      'dmarc',
      [
        f(
          'error',
          'dmarc.missing',
          'No DMARC record',
          `Publish a record at _dmarc.${d}, e.g. "v=DMARC1; p=none; rua=mailto:dmarc@${d}" to start collecting reports.`,
          [r('rfc7489', '6.1'), r('rfc7489', '6.6.3')],
        ),
      ],
      { name: null, record: null, records: [], inherited: false, tags: {}, rua: [], ruf: [] },
    ),
    result(
      d,
      'mta-sts',
      [
        f(
          'error',
          'mta-sts.fetch-failed',
          'The policy cannot be fetched',
          `https://mta-sts.${d}/.well-known/mta-sts.txt: getaddrinfo ENOTFOUND mta-sts.${d}. Senders treat this as "no policy" (sts-policy-fetch-error).`,
          [r('rfc8461', '3.3')],
        ),
      ],
      {
        record: 'v=STSv1; id=1',
        records: ['v=STSv1; id=1'],
        id: '1',
        policyUrl: `https://mta-sts.${d}/.well-known/mta-sts.txt`,
        fetch: {
          status: null,
          contentType: null,
          redirect: null,
          error: `getaddrinfo ENOTFOUND mta-sts.${d}`,
          cert: null,
        },
        raw: null,
        policy: null,
        coverage: [],
      },
    ),
    result(
      d,
      'tls-rpt',
      [
        f(
          'warning',
          'tls-rpt.missing',
          'No TLS-RPT record',
          'MTA-STS is deployed, but without _smtp._tls you never hear about senders that fail to deliver over TLS.',
          [r('rfc8460', '3')],
        ),
      ],
      { record: null, records: [], rua: [] },
    ),
    result(
      d,
      'dane',
      [
        f(
          'info',
          'dane.no-dnssec',
          'The domain is not signed with DNSSEC',
          'DANE needs DNSSEC on the domain and on the MX hosts’ zones.',
          [r('rfc4033'), r('rfc7672', '2.2')],
        ),
      ],
      { mxSecure: false, zoneSigned: false, hosts: [] },
    ),
    result(d, 'bimi', [f('info', 'bimi.missing', 'BIMI is not set up', 'Optional.', [r('bimi')])], {
      record: null,
      records: [],
      tags: {},
      logo: null,
      authority: null,
    }),
    result(
      d,
      'dnsbl',
      [
        f(
          'error',
          'dnsbl.listed',
          '203.0.113.99 is listed on zen.spamhaus.org',
          'XBL (exploited host). Used as: sender (delivery tests).',
          [r('rfc5782', '2')],
          '203.0.113.99 zen.spamhaus.org',
        ),
      ],
      {
        zones: [
          'zen.spamhaus.org',
          'bl.spamcop.net',
          'psbl.surriel.com',
          'bl.mailspike.net',
          'dbl.spamhaus.org',
          'multi.surbl.org',
        ],
        ips: [
          {
            ip: '203.0.113.40',
            sources: ['MX mx.shop.example.org'],
            listings: ['zen.spamhaus.org', 'bl.spamcop.net', 'psbl.surriel.com', 'bl.mailspike.net'].map((zone) => ({
              zone,
              listed: false,
              refused: false,
              codes: [],
              reason: null,
            })),
          },
          {
            ip: '203.0.113.99',
            sources: ['sender (delivery tests)'],
            listings: ['zen.spamhaus.org', 'bl.spamcop.net', 'psbl.surriel.com', 'bl.mailspike.net'].map((zone) => ({
              zone,
              listed: zone === 'zen.spamhaus.org',
              refused: false,
              codes: zone === 'zen.spamhaus.org' ? ['127.0.0.4'] : [],
              reason: zone === 'zen.spamhaus.org' ? 'XBL (exploited host)' : null,
            })),
          },
          {
            ip: d,
            sources: ['domain'],
            listings: ['dbl.spamhaus.org', 'multi.surbl.org'].map((zone) => ({
              zone,
              listed: false,
              refused: false,
              codes: [],
              reason: null,
            })),
          },
        ],
      },
    ),
  );
}
// --- Domain and Sending (all three domains) ---------------------------------------------

const ns = (zone: string, hosts: [string, string][], serial: number) =>
  hosts.map(([host, ip]) => ({
    host,
    addresses: [ip],
    probes: [{ host, ip, rcode: 'NOERROR', authoritative: true, serial }],
  }));
const registration = (domain: string, expiresInDays: number, status: string[] = ['client transfer prohibited']) => ({
  domain,
  server: 'https://rdap.example/',
  fetchedAt: iso(now - 3 * 3_600_000),
  status,
  registrar: 'Example Registrar AS',
  registered: iso(now - 4000 * DAY),
  expires: iso(now + expiresInDays * DAY),
  lastChanged: iso(now - 200 * DAY),
  nameservers: ['ns1.dns.example', 'ns2.dns.example'],
  delegationSigned: true,
  error: null,
});
const nsHosts: [string, string][] = [
  ['ns1.dns.example', '198.18.1.53'],
  ['ns2.dns.example', '198.19.2.53'],
];
const reqs = (fail: string[] = [], unknown: string[] = []) =>
  (
    [
      ['auth', 'SPF or DKIM passes', 'all'],
      ['spf-and-dkim', 'SPF and DKIM both pass', 'bulk'],
      ['fcrdns', 'Sending IPs have forward-confirmed reverse DNS', 'all'],
      ['tls', 'Mail is transmitted over TLS', 'all'],
      ['dmarc', 'A DMARC policy is published (p=none or stricter)', 'bulk'],
      ['alignment', 'The From: domain is aligned (DMARC passes)', 'bulk'],
      ['unsubscribe', 'Marketing mail has one-click unsubscribe', 'bulk'],
      ['spam-rate', 'Spam complaint rate below 0.3 %', 'all'],
    ] as const
  ).map(([id, label, scope]) => ({
    id,
    label,
    scope,
    status: (id === 'unsubscribe'
      ? 'n/a'
      : id === 'spam-rate' || unknown.includes(id)
        ? 'unknown'
        : fail.includes(id)
          ? 'fail'
          : 'ok') as 'ok' | 'fail' | 'unknown' | 'n/a',
    detail: fail.includes(id) ? 'seen at Gmail, Microsoft: fail' : 'seen at Gmail, Microsoft: pass',
  }));
const service = (svc: 'submission' | 'imap', host: string, port: number, days: number) => ({
  service: svc,
  host,
  port,
  tlsMode: 'implicit' as const,
  connected: true,
  banner: svc === 'imap' ? '* OK [CAPABILITY IMAP4rev1] ready' : `220 ${host} ESMTP`,
  authBeforeTls: [],
  tls: { ...probe(host, '192.0.2.1', { days }).tls!, protocol: 'TLSv1.3' },
  error: null,
});
const srv = (domain: string, sub: string | null) => [
  { name: `_submissions._tcp.${domain}`, target: sub, port: sub ? 465 : null, found: Boolean(sub) },
  { name: `_submission._tcp.${domain}`, target: null, port: null, found: false },
  {
    name: `_imaps._tcp.${domain}`,
    target: sub && sub.replace(/^smtp/, 'imap'),
    port: sub ? 993 : null,
    found: Boolean(sub),
  },
  { name: `_imap._tcp.${domain}`, target: null, port: null, found: false },
];

results.push(
  result(
    'example.com',
    'domain',
    [
      f(
        'ok',
        'domain.registered',
        `Registered until ${iso(now + 290 * DAY).slice(0, 10)}`,
        'Example Registrar AS · client transfer prohibited',
        [r('rfc9083', '4.5')],
      ),
      f(
        'ok',
        'domain.ns-ok',
        '2 nameservers, all authoritative',
        'ns1.dns.example, ns2.dns.example · serial 2026100201',
        [r('rfc1034', '4.1')],
      ),
    ],
    {
      zone: 'example.com',
      registration: registration('example.com', 290),
      nameservers: ns('example.com', nsHosts, 2026100201),
      probed: true,
    },
  ),
  result(
    'example.net',
    'domain',
    [
      f(
        'warning',
        'domain.expiring',
        'example.net expires in 19 days',
        `Registered until ${iso(now + 19 * DAY).slice(0, 10)}. Make sure it renews (auto-renewal, payment method).`,
        [r('rfc9083', '4.5')],
      ),
      f(
        'warning',
        'domain.serial-mismatch',
        'The nameservers serve different versions of the zone',
        'SOA serials 2026100201, 2026092801: a secondary is not updated, so changes (e.g. to SPF or DKIM) reach only part of the resolvers.',
        [r('rfc1034', '4.3.5')],
      ),
    ],
    {
      zone: 'example.net',
      registration: registration('example.net', 19),
      nameservers: [
        ...ns('example.net', nsHosts.slice(0, 1), 2026100201),
        ...ns('example.net', nsHosts.slice(1), 2026092801),
      ],
      probed: true,
    },
  ),
  result(
    'shop.example.org',
    'domain',
    [
      f(
        'error',
        'domain.lame',
        'Nameserver ns2.dns.example is not authoritative for example.org',
        '198.19.2.53 answered REFUSED: a lame delegation. Resolvers that pick it fail or time out.',
        [r('rfc1912', '2.8')],
        'ns2.dns.example 198.19.2.53',
      ),
      f('ok', 'domain.registered', `Registered until ${iso(now + 120 * DAY).slice(0, 10)}`, 'Example Registrar AS', [
        r('rfc9083', '4.5'),
      ]),
    ],
    {
      zone: 'example.org',
      registration: registration('example.org', 120),
      nameservers: [
        ...ns('example.org', nsHosts.slice(0, 1), 2026090101),
        {
          host: 'ns2.dns.example',
          addresses: ['198.19.2.53'],
          probes: [
            { host: 'ns2.dns.example', ip: '198.19.2.53', rcode: 'REFUSED', authoritative: false, serial: null },
          ],
        },
      ],
      probed: true,
    },
  ),
  result(
    'example.com',
    'senders',
    [
      f('ok', 'senders.ips-ok', '1 sending IP: reverse DNS and SPF pass', '192.0.2.10 (out.example.com)', [
        r('rfc7208'),
        r('gmail-senders'),
      ]),
      f(
        'ok',
        'senders.submission-ok',
        'The submission server smtp.example.com:465: TLSv1.3, valid certificate',
        `Valid until ${iso(now + 60 * DAY).slice(0, 10)}.`,
        [r('rfc8314')],
        'smtp.example.com:465',
      ),
      f(
        'ok',
        'senders.imap-ok',
        'The IMAP server imap.example.com:993: TLSv1.3, valid certificate',
        `Valid until ${iso(now + 60 * DAY).slice(0, 10)}.`,
        [r('rfc8314')],
        'imap.example.com:993',
      ),
      f(
        'ok',
        'senders.requirements',
        'Gmail and Yahoo sender requirements met',
        'As far as MailWatch can see: authentication, reverse DNS, TLS and DMARC.',
        [r('gmail-senders'), r('yahoo-senders')],
      ),
    ],
    {
      envelopeDomain: 'example.com',
      ips: [
        {
          ip: '192.0.2.10',
          sources: ['delivery tests'],
          ptr: 'out.example.com',
          fcrdns: true,
          spf: 'pass',
          spfDetail: 'matched "ip4:192.0.2.0/24" in example.com',
        },
      ],
      services: [service('submission', 'smtp.example.com', 465, 60), service('imap', 'imap.example.com', 993, 60)],
      srv: srv('example.com', 'smtp.example.com'),
      autoconfig: { url: 'https://autoconfig.example.com/mail/config-v1.1.xml', status: 200, error: null },
      requirements: reqs(),
    },
  ),
  result(
    'example.net',
    'senders',
    [
      f(
        'warning',
        'senders.spf-not-pass',
        'SPF of example.net does not authorise 198.51.100.7 (softfail)',
        'matched "~all" in example.net. DMARC then depends on DKIM alone for this IP.',
        [r('rfc7208', '2.6')],
        '198.51.100.7',
      ),
      f(
        'info',
        'senders.no-autoconfig',
        'Mail clients cannot configure themselves',
        'No SRV records (_submissions._tcp, _imaps._tcp, …) and no autoconfig file.',
        [r('rfc6186', '3'), r('rfc8314', '5.1')],
      ),
      f(
        'info',
        'senders.requirements',
        '1 Gmail/Yahoo sender requirement not met',
        'SPF and DKIM both pass. The individual problems are reported (and alerted) by their own checks.',
        [r('gmail-senders'), r('yahoo-senders')],
      ),
    ],
    {
      envelopeDomain: 'example.net',
      ips: [
        {
          ip: '198.51.100.7',
          sources: ['configured', 'delivery tests'],
          ptr: 'mta7.mailer.example',
          fcrdns: true,
          spf: 'softfail',
          spfDetail: 'matched "~all" in example.net',
        },
      ],
      services: [service('submission', 'smtp.example.net', 465, 45)],
      srv: srv('example.net', null),
      autoconfig: {
        url: 'https://autoconfig.example.net/mail/config-v1.1.xml',
        status: null,
        error: 'getaddrinfo ENOTFOUND',
      },
      requirements: reqs(['spf-and-dkim']),
    },
  ),
  result(
    'shop.example.org',
    'senders',
    [
      f(
        'error',
        'senders.no-ptr',
        'Sending IP 203.0.113.80 has no reverse DNS',
        'Gmail, Yahoo and Microsoft require a PTR record for sending IPs and reject or spam-folder mail without one.',
        [r('gmail-senders'), r('rfc1912', '2.1')],
        '203.0.113.80',
      ),
      f(
        'error',
        'senders.auth-before-tls',
        'The submission server offers PLAIN, LOGIN before STARTTLS',
        'Clients may send the password unencrypted. Offer AUTH only after STARTTLS, or use implicit TLS on port 465.',
        [r('rfc8314', '3.3'), r('rfc4954', '4')],
        'mail.shop.example.org:587',
      ),
      f(
        'info',
        'senders.requirements',
        '2 Gmail/Yahoo sender requirements not met',
        'Sending IPs have forward-confirmed reverse DNS; The From: domain is aligned (DMARC passes).',
        [r('gmail-senders'), r('yahoo-senders')],
      ),
    ],
    {
      envelopeDomain: 'shop.example.org',
      ips: [
        {
          ip: '203.0.113.80',
          sources: ['delivery tests'],
          ptr: null,
          fcrdns: false,
          spf: 'pass',
          spfDetail: 'matched "a" in shop.example.org',
        },
      ],
      services: [
        {
          ...service('submission', 'mail.shop.example.org', 587, 12),
          tlsMode: 'starttls' as const,
          authBeforeTls: ['PLAIN', 'LOGIN'],
        },
      ],
      srv: srv('shop.example.org', null),
      autoconfig: { url: 'https://autoconfig.shop.example.org/mail/config-v1.1.xml', status: 404, error: null },
      requirements: reqs(['fcrdns', 'alignment']),
    },
  ),
);

await store.saveCheckResults(results);

// --- Record changes ------------------------------------------------------------------

await store.recordChange(
  'example.net',
  'spf',
  'v=spf1 include:_spf.google.com include:spf.protection.outlook.com a mx ~all',
  (results.find((x) => x.domain === 'example.net' && x.check === 'spf')!.data as SpfData).record,
  iso(now - 3 * DAY),
);
await store.recordChange(
  'example.com',
  'mta-sts',
  'v=STSv1; id=20260601\nversion: STSv1\nmode: testing\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 604800',
  'v=STSv1; id=20260901\nversion: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 1209600',
  iso(now - 31 * DAY),
);
await store.recordChange(
  'example.com',
  'dkim',
  's2025: v=DKIM1; k=rsa; p=MIIBIjANBgkqh…(2025)',
  's2025: v=DKIM1; k=rsa; p=\ns2026: v=DKIM1; k=rsa; p=MIIBIjANBgkqh…',
  iso(now - 12 * DAY),
);

// --- DMARC aggregate reports -----------------------------------------------------------

const xmlEscape = (s: string) => s.replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' })[c]!);
function toXml(rep: NormalizedDmarcReport): string {
  const t = (k: string, v: string | number | null | undefined) =>
    v === null || v === undefined ? '' : `<${k}>${xmlEscape(String(v))}</${k}>`;
  const recs = rep.records
    .map(
      (x) =>
        `  <record>\n    <row>${t('source_ip', x.sourceIp)}${t('count', x.count)}<policy_evaluated>${t('disposition', x.disposition)}${t('dkim', x.dkim)}${t('spf', x.spf)}${x.reasons.map((re) => `<reason>${t('type', re.type)}</reason>`).join('')}</policy_evaluated></row>\n    <identifiers>${t('header_from', x.headerFrom)}${t('envelope_from', x.envelopeFrom)}</identifiers>\n    <auth_results>${x.dkimResults.map((k) => `<dkim>${t('domain', k.domain)}${t('selector', k.selector)}${t('result', k.result)}</dkim>`).join('')}${x.spfResults.map((k) => `<spf>${t('domain', k.domain)}${t('scope', k.scope)}${t('result', k.result)}</spf>`).join('')}</auth_results>\n  </record>`,
    )
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<feedback>\n  <report_metadata>${t('org_name', rep.orgName)}${t('email', rep.email)}${t('report_id', rep.reportId)}<date_range>${t('begin', Date.parse(rep.begin) / 1000)}${t('end', Date.parse(rep.end) / 1000)}</date_range></report_metadata>\n  <policy_published>${t('domain', rep.policy.domain)}${t('adkim', rep.policy.adkim)}${t('aspf', rep.policy.aspf)}${t('p', rep.policy.p)}${t('pct', rep.policy.pct)}</policy_published>\n${recs}\n</feedback>\n`;
}

const reporters = [
  { org: 'google.com', email: 'noreply-dmarc-support@google.com', volume: 1.0 },
  { org: 'Outlook.com', email: 'dmarcreport@microsoft.com', volume: 0.6 },
  { org: 'Yahoo', email: 'dmarchelp@yahooinc.com', volume: 0.2 },
];
interface Src {
  ip: string;
  domain: string;
  volume: number;
  /** pass both, unaligned dkim, spoof, partial */
  kind: 'own' | 'service' | 'spoof' | 'partial' | 'forward';
}
const sources: Src[] = [
  { ip: '192.0.2.10', domain: 'example.com', volume: 120, kind: 'own' },
  { ip: '192.0.2.11', domain: 'example.com', volume: 40, kind: 'own' },
  { ip: '203.0.113.17', domain: 'example.com', volume: 30, kind: 'own' },
  { ip: '198.51.100.25', domain: 'example.net', volume: 50, kind: 'own' },
  { ip: '198.51.100.77', domain: 'example.net', volume: 25, kind: 'service' },
  { ip: '198.51.100.30', domain: 'example.net', volume: 12, kind: 'partial' },
  { ip: '209.85.220.41', domain: 'example.com', volume: 3, kind: 'forward' },
  ...Array.from({ length: 14 }, (_, i) => ({
    ip: `203.0.113.${100 + i * 7}`,
    domain: i % 3 ? 'example.com' : 'example.net',
    volume: 2,
    kind: 'spoof' as const,
  })),
];
let dmarcCount = 0;
for (let dd = 90; dd >= 1; dd--) {
  const begin = new Date(now - dd * DAY);
  begin.setUTCHours(0, 0, 0, 0);
  const day = begin.toISOString().slice(0, 10);
  for (const domain of ['example.com', 'example.net']) {
    for (const rep of reporters) {
      if (rand() < 0.15) continue;
      const policy = domain === 'example.com' ? { p: 'reject', pct: 100 } : { p: 'none', pct: null };
      const records: DmarcRecordRow[] = [];
      for (const s of sources.filter((x) => x.domain === domain)) {
        if (s.kind === 'spoof' && rand() < 0.7) continue;
        const count = Math.max(1, Math.round(s.volume * rep.volume * (0.4 + rand())));
        const own = { domain, selector: domain === 'example.com' ? 's2026' : 's1', result: 'pass' };
        const spfOwn = { domain: `bounce.${domain}`, scope: 'mfrom', result: 'pass' };
        let row: Omit<DmarcRecordRow, 'sourceIp' | 'count' | 'headerFrom'>;
        if (s.kind === 'own')
          row = {
            disposition: 'none',
            dkim: 'pass',
            spf: 'pass',
            reasons: [],
            envelopeFrom: `bounce.${domain}`,
            envelopeTo: null,
            dkimResults: [own],
            spfResults: [spfOwn],
          };
        else if (s.kind === 'service')
          row = {
            disposition: 'none',
            dkim: 'fail',
            spf: 'fail',
            reasons: [],
            envelopeFrom: 'em123.sendgrid.net',
            envelopeTo: null,
            dkimResults: [{ domain: 'sendgrid.net', selector: 's1', result: 'pass' }],
            spfResults: [{ domain: 'em123.sendgrid.net', scope: 'mfrom', result: 'pass' }],
          };
        else if (s.kind === 'forward')
          row = {
            disposition: 'none',
            dkim: 'pass',
            spf: 'fail',
            reasons: [{ type: 'forwarded', comment: null }],
            envelopeFrom: 'lists.example.org',
            envelopeTo: null,
            dkimResults: [own],
            spfResults: [{ domain: 'lists.example.org', scope: 'mfrom', result: 'pass' }],
          };
        else if (s.kind === 'partial') {
          const broken = dd < 20 && rand() < 0.6;
          row = broken
            ? {
                disposition: 'none',
                dkim: 'fail',
                spf: 'fail',
                reasons: [],
                envelopeFrom: `crm.${domain}`,
                envelopeTo: null,
                dkimResults: [{ domain, selector: 'crm', result: 'fail' }],
                spfResults: [{ domain: `crm.${domain}`, scope: 'mfrom', result: 'softfail' }],
              }
            : {
                disposition: 'none',
                dkim: 'pass',
                spf: 'pass',
                reasons: [],
                envelopeFrom: `crm.${domain}`,
                envelopeTo: null,
                dkimResults: [{ domain, selector: 'crm', result: 'pass' }],
                spfResults: [{ domain: `crm.${domain}`, scope: 'mfrom', result: 'pass' }],
              };
        } else
          row = {
            disposition: policy.p === 'reject' ? 'reject' : 'none',
            dkim: 'fail',
            spf: 'fail',
            reasons: [],
            envelopeFrom: domain,
            envelopeTo: null,
            dkimResults: [],
            spfResults: [{ domain, scope: 'mfrom', result: 'fail' }],
          };
        records.push({ sourceIp: s.ip, count, headerFrom: domain, ...row });
      }
      const report: NormalizedDmarcReport = {
        orgName: rep.org,
        reportId: `${rep.org}-${domain}-${day}`,
        email: rep.email,
        extraContact: null,
        begin: begin.toISOString(),
        end: new Date(begin.getTime() + DAY - 1000).toISOString(),
        errors: [],
        policy: { domain, adkim: 'r', aspf: 'r', p: policy.p, sp: null, np: null, pct: policy.pct, fo: null },
        records,
      };
      await store.insertDmarcReport(report, toXml(report), {
        from: rep.email,
        subject: `Report domain: ${domain} Submitter: ${rep.org} Report-ID: ${report.reportId}`,
        filename: `${rep.org}!${domain}!${Date.parse(report.begin) / 1000}!${Date.parse(report.end) / 1000}.xml.gz`,
        mailbox: 'dmarc@example.com@imap.example.com/INBOX',
        receivedAt: new Date(begin.getTime() + DAY + 6 * 3_600_000).toISOString(),
      });
      dmarcCount++;
    }
  }
}

// --- DMARC failure reports -------------------------------------------------------------

for (let i = 0; i < 6; i++) {
  const at = now - (i * 3 + 1) * DAY;
  const ip = `203.0.113.${100 + i * 7}`;
  await store.insertFailureReport(
    {
      key: `<demo-ruf-${i}@reporter.example>`,
      fields: [
        ['Feedback-Type', 'auth-failure'],
        ['Version', '1'],
        ['Auth-Failure', 'dmarc'],
        ['Reported-Domain', 'example.com'],
        ['Source-IP', ip],
        ['Delivery-Result', 'reject'],
        [
          'Authentication-Results',
          `mx.reporter.example; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=example.com; dkim=none`,
        ],
      ],
      feedbackType: 'auth-failure',
      authFailure: 'dmarc',
      reportedDomain: 'example.com',
      sourceIp: ip,
      arrivalDate: new Date(at).toUTCString(),
      originalMailFrom: 'billing@example.com',
      originalRcptTo: 'someone@reporter.example',
      dkimDomain: null,
      dkimSelector: null,
      deliveryResult: 'reject',
      identityAlignment: 'none',
      authenticationResults:
        'mx.reporter.example; dmarc=fail header.from=example.com; spf=fail smtp.mailfrom=example.com',
      headers: `From: "Example Billing" <billing@example.com>\nTo: someone@reporter.example\nSubject: Your invoice #${4711 + i} is overdue\nDate: ${new Date(at).toUTCString()}\nMessage-ID: <${hex(String(i)).slice(0, 16)}@spoof.invalid>`,
      headerFrom: '"Example Billing" <billing@example.com>',
      subject: `Your invoice #${4711 + i} is overdue`,
    },
    {
      from: 'dmarc-failures@reporter.example',
      subject: 'DMARC failure report for example.com',
      filename: null,
      mailbox: 'dmarc@example.com@imap.example.com/INBOX',
      receivedAt: iso(at + 3_600_000),
    },
  );
}

// --- TLS reports ---------------------------------------------------------------------

let tlsCount = 0;
for (let dd = 90; dd >= 1; dd--) {
  const start = new Date(now - dd * DAY);
  start.setUTCHours(0, 0, 0, 0);
  const day = start.toISOString().slice(0, 10);
  for (const rep of [
    { org: 'Google Inc.', volume: 60 },
    { org: 'Microsoft Corporation', volume: 35 },
  ]) {
    if (rand() < 0.2) continue;
    const policies: unknown[] = [];
    for (const [domain, mode, mxHost] of [
      ['example.com', 'enforce', 'mx1.example.com'],
      ['example.net', 'testing', 'mail.example.net'],
    ] as const) {
      const total = Math.round(rep.volume * (0.5 + rand()) * (domain === 'example.com' ? 1 : 0.5));
      const incident = domain === 'example.net' && dd > 10 && dd < 16;
      const failed = incident ? Math.round(total * 0.25) : 0;
      policies.push({
        policy: {
          'policy-type': 'sts',
          'policy-string': ['version: STSv1', `mode: ${mode}`, `mx: ${mxHost}`, 'max_age: 604800'],
          'policy-domain': domain,
          'mx-host': [mxHost],
        },
        summary: { 'total-successful-session-count': total - failed, 'total-failure-session-count': failed },
        'failure-details': failed
          ? [
              {
                'result-type': 'certificate-expired',
                'receiving-mx-hostname': mxHost,
                'receiving-ip': '198.51.100.25',
                'sending-mta-ip': '209.85.220.69',
                'failed-session-count': failed,
              },
            ]
          : [],
      });
    }
    const raw = {
      'organization-name': rep.org,
      'date-range': { 'start-datetime': `${day}T00:00:00Z`, 'end-datetime': `${day}T23:59:59Z` },
      'contact-info': 'smtp-tls-reporting@example.net',
      'report-id': `${day}_${rep.org}`,
      policies,
    };
    await store.insertTlsReport(normalizeReport(raw), raw, {
      from: 'noreply-smtp-tls-reporting@example.net',
      subject: `Report Domain: example.com Submitter: ${rep.org}`,
      filename: `${rep.org}!example.com!${day}.json.gz`,
      mailbox: 'tlsrpt@example.com@imap.example.com/INBOX',
      receivedAt: new Date(start.getTime() + DAY + 8 * 3_600_000).toISOString(),
    });
    tlsCount++;
  }
}

// --- Delivery tests ------------------------------------------------------------------

const senders = ['example.com', 'example.net', 'shop.example.org'];
const recipients = ['Gmail', 'Microsoft'];
let probes = 0;
for (let h = 7 * 24; h >= 1; h--) {
  for (const sender of senders) {
    for (const recipient of recipients) {
      const sentAt = now - h * 3_600_000 + Math.round(rand() * 120_000);
      const token = hex(`${sender}${recipient}${h}`).slice(0, 24);
      const id = await store.createProbe({ token, sender, recipient, sentAt: iso(sentAt) });
      let status: ProbeStatus = 'inbox';
      let dmarc = 'pass';
      if (sender === 'shop.example.org') {
        status = recipient === 'Microsoft' ? (rand() < 0.7 ? 'spam' : 'lost') : rand() < 0.5 ? 'spam' : 'inbox';
        dmarc = 'fail';
      } else if (sender === 'example.net' && recipient === 'Microsoft' && rand() < 0.15) status = 'spam';
      if (h === 1 && sender === 'shop.example.org' && recipient === 'Microsoft') status = 'lost';
      const latency = status === 'lost' ? null : Math.round(4 + rand() * (recipient === 'Microsoft' ? 90 : 20));
      const ip =
        sender === 'shop.example.org' ? '203.0.113.99' : sender === 'example.net' ? '198.51.100.25' : '192.0.2.10';
      const auth = {
        spf: sender === 'shop.example.org' ? 'permerror' : 'pass',
        dkim: sender === 'shop.example.org' ? 'fail' : 'pass',
        dmarc,
        arc: null,
        compauth: recipient === 'Microsoft' ? (dmarc === 'pass' ? 'pass reason=100' : 'fail reason=001') : null,
        scl: recipient === 'Microsoft' ? (status === 'spam' ? 5 : 1) : null,
      };
      const folder = status === 'spam' ? (recipient === 'Gmail' ? '[Gmail]/Spam' : 'Junk') : 'INBOX';
      const headers =
        status === 'lost'
          ? null
          : `Authentication-Results: ${recipient === 'Gmail' ? 'mx.google.com' : 'spf.protection.outlook.com'};\n       dkim=${auth.dkim} header.i=@${sender} header.s=${sender === 'example.com' ? 's2026' : sender === 'example.net' ? 's1' : 'shop'};\n       spf=${auth.spf} (sender IP is ${ip}) smtp.mailfrom=${sender};\n       dmarc=${dmarc} header.from=${sender}${auth.compauth ? `;\n       compauth=${auth.compauth}` : ''}\nReceived-SPF: ${auth.spf} client-ip=${ip};\nFrom: MailWatch <monitor@${sender}>\nTo: test@${recipient.toLowerCase()}.example\nSubject: MailWatch delivery test ${token}\nMessage-ID: <mailwatch.${token}@${sender}>\nX-MailWatch-Probe: ${token}`;
      await store.updateProbe(id, {
        status,
        smtpResponse: `250 2.0.0 Ok: queued as ${token.slice(0, 10).toUpperCase()}`,
        error: status === 'lost' ? 'not found within 30 minutes' : null,
        receivedAt: latency === null ? null : iso(sentAt + latency * 1000),
        folder: status === 'lost' ? null : folder,
        latencySeconds: latency,
        auth: status === 'lost' ? null : auth,
        clientIp: status === 'lost' ? null : ip,
        dkimSelectors:
          status === 'lost' ? [] : [sender === 'example.com' ? 's2026' : sender === 'example.net' ? 's1' : 'shop'],
        headers,
      });
      probes++;
    }
  }
}

// --- Alerts --------------------------------------------------------------------------

const open = async (a: Parameters<Store['openAlert']>[0], ago: number, resolvedAgo?: number) => {
  const id = await store.openAlert(a, iso(now - ago));
  await store.touchAlert(id, a, iso(now - 5 * 60_000));
  if (resolvedAgo !== undefined) await store.resolveAlert(id, iso(now - resolvedAgo));
  return id;
};
const fromFinding = (domain: string, check: CheckKind, code: string) => {
  const res = results.find((x) => x.domain === domain && x.check === check)!;
  const fd = res.findings.find((x) => x.code === code)!;
  return {
    key: `check|${check}|${code}|${domain}|${fd.subject ?? ''}`,
    kind: 'check' as const,
    code,
    domain,
    subject: fd.subject ?? '',
    title: fd.title,
    severity: (fd.level === 'error' ? 'error' : 'warning') as 'error' | 'warning',
    detail: fd.detail,
    refs: fd.refs ?? [],
  };
};
for (const x of results) {
  for (const fd of x.findings) {
    if (fd.level === 'warning' || fd.level === 'error')
      await open(fromFinding(x.domain, x.check, fd.code), (2 + rand() * 20) * 3_600_000);
  }
}
await open(
  {
    key: 'delivery|delivery.lost|shop.example.org|Microsoft',
    kind: 'delivery',
    code: 'delivery.lost',
    domain: 'shop.example.org',
    subject: 'Microsoft',
    title: 'shop.example.org → Microsoft: the test message did not arrive',
    severity: 'error',
    detail: 'Not found in the Inbox or Junk folder within 30 minutes.',
    refs: [],
  },
  50 * 60_000,
);
await open(
  {
    key: 'report|dmarc-reports.unaligned|example.net|',
    kind: 'report',
    code: 'dmarc-reports.unaligned',
    domain: 'example.net',
    subject: '',
    title: '1 source signs with another domain',
    severity: 'warning',
    detail: '198.51.100.77 (sendgrid.net). DKIM passes but is not aligned, so DMARC fails.',
    refs: [{ doc: 'rfc7489', section: '3.1.1' }],
  },
  6 * DAY,
);
await open(
  {
    key: 'report|tls-reports.failures|example.net|',
    kind: 'report',
    code: 'tls-reports.failures',
    domain: 'example.net',
    subject: '',
    title: '204 failed TLS sessions reported (12.4%)',
    severity: 'error',
    detail: 'certificate-expired',
    refs: [{ doc: 'rfc8460', section: '4.3' }],
  },
  15 * DAY,
  10 * DAY,
);
await open(
  {
    key: 'check|mx|smtp.cert-expired|example.net|mail.example.net 198.51.100.25',
    kind: 'check',
    code: 'smtp.cert-expired',
    domain: 'example.net',
    subject: 'mail.example.net 198.51.100.25',
    title: 'The mail.example.net certificate has expired',
    severity: 'error',
    detail: null,
    refs: [{ doc: 'rfc9525' }],
  },
  15 * DAY,
  10 * DAY,
);

await store.close();
console.log(
  `wrote ${results.length} check results, ${dmarcCount} DMARC, ${tlsCount} TLS and 6 failure reports, ${probes} delivery tests to ${config.db.database}`,
);
