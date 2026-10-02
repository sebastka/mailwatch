// The domain, DNSSEC, sending, DKIM key age and SMTP extension checks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { CheckResult, DkimData, SendersData, SmtpProbe } from '../src/shared/types.ts';
import { receivedOverTls } from '../src/server/auth-results.ts';
import { dsMatches, keyTag, signatureUrgency } from '../src/server/checks/dnssec.ts';
import { parseRdap } from '../src/server/checks/domain.ts';
import { runDomainChecks } from '../src/server/checks/index.ts';
import { extensionFindings } from '../src/server/checks/mx.ts';
import { checkHost, expandMacros, inCidr } from '../src/server/checks/spf-eval.ts';
import { Findings } from '../src/server/checks/util.ts';
import { checksConfig, checkWith, codes, FakeDns, type Zone } from './helpers.ts';

// RFC 4034 §5.4 and RFC 4509 §2.3: the DNSKEY of dskey.example.com and its DS records.
const RFC_KEY = {
  flags: 256,
  algorithm: 5,
  key: Buffer.from(
    'AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==',
    'base64',
  ),
};

test('DNSSEC: key tags and DS digests (RFC 4034 §5.4, RFC 4509 §2.3)', () => {
  assert.equal(keyTag(RFC_KEY), 60485);
  const ds = (digestType: number, hex: string) => ({
    keyTag: 60485,
    algorithm: 5,
    digestType,
    digest: Buffer.from(hex, 'hex'),
  });
  assert.equal(dsMatches('dskey.example.com.', ds(1, '2BB183AF5F22588179A53B0A98631FAD1A292118'), RFC_KEY), true);
  assert.equal(
    dsMatches('DSKEY.example.com', ds(2, 'D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A'), RFC_KEY),
    true,
  );
  // Another owner name, a wrong digest, an unknown digest type.
  assert.equal(dsMatches('other.example.com', ds(1, '2BB183AF5F22588179A53B0A98631FAD1A292118'), RFC_KEY), false);
  assert.equal(dsMatches('dskey.example.com', ds(1, '00'.repeat(20)), RFC_KEY), false);
  assert.equal(dsMatches('dskey.example.com', ds(9, '00'), RFC_KEY), null);
});

test('DNSSEC: signature urgency is relative to the validity period', () => {
  const now = 1_000_000_000;
  const day = 86_400;
  // Online signer: 2-day validity, 1 day left — normal.
  assert.equal(signatureUrgency(now - day, now + day, now, 3), null);
  // 30-day validity with 2 days left: the signer stopped re-signing.
  assert.equal(signatureUrgency(now - 28 * day, now + 2 * day, now, 3), 'warning');
  // Plenty of absolute time left although a quarter is used up: fine.
  assert.equal(signatureUrgency(now - 300 * day, now + 10 * day, now, 3), null);
  assert.equal(signatureUrgency(now - day, now + 3600, now, 3), 'error');
  assert.equal(signatureUrgency(now - day, now - 1, now, 3), 'expired');
});

test('RDAP domain objects are parsed (RFC 9083 §5.3)', () => {
  const r = parseRdap(
    'example.org',
    'https://rdap.example/',
    {
      objectClassName: 'domain',
      ldhName: 'EXAMPLE.ORG',
      status: ['client transfer prohibited', 'Client Hold'],
      events: [
        { eventAction: 'registration', eventDate: '2001-02-03T04:05:06Z' },
        { eventAction: 'expiration', eventDate: '2027-02-03T04:05:06.000+00:00' },
        { eventAction: 'last changed', eventDate: '2026-01-01T00:00:00Z' },
      ],
      entities: [
        { roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'Someone']]] },
        {
          roles: ['registrar'],
          vcardArray: [
            'vcard',
            [
              ['version', {}, 'text', '4.0'],
              ['fn', {}, 'text', 'Registrar AS'],
            ],
          ],
        },
      ],
      nameservers: [{ ldhName: 'NS2.EXAMPLE.NET.' }, { ldhName: 'ns1.example.net' }],
      secureDNS: { delegationSigned: true },
    },
    '2026-10-02T00:00:00.000Z',
  );
  assert.equal(r.registrar, 'Registrar AS');
  assert.equal(r.expires, '2027-02-03T04:05:06.000Z');
  assert.equal(r.registered, '2001-02-03T04:05:06.000Z');
  assert.deepEqual(r.status, ['client transfer prohibited', 'client hold']);
  assert.deepEqual(r.nameservers, ['ns1.example.net', 'ns2.example.net']);
  assert.equal(r.delegationSigned, true);
  // Garbage in: empty data, no exception.
  assert.deepEqual(parseRdap('x.org', 's', 'nonsense', 'now').nameservers, []);
});

test('Domain: nameserver count, addresses and network diversity', async () => {
  const one = await checkWith({ 'example.com NS': ['ns1.example.net'], 'ns1.example.net A': ['198.18.0.1'] });
  assert.ok(codes(one.get('domain')).includes('domain.single-ns'));

  const r = await checkWith({
    'example.com NS': ['ns1.example.net', 'ns2.example.net', 'ns3.example.net'],
    'ns1.example.net A': ['93.184.216.1'],
    'ns2.example.net A': ['93.184.216.2'],
  });
  const c = codes(r.get('domain'));
  assert.ok(c.includes('domain.ns-no-address'), c.join());
  assert.ok(c.includes('domain.ns-one-network'), c.join());
  assert.equal(r.get('domain')!.level, 'error');

  const ok = await checkWith({
    'example.com NS': ['ns1.example.net', 'ns2.example.org'],
    'ns1.example.net A': ['93.184.216.1'],
    'ns2.example.org A': ['151.101.1.1'],
  });
  assert.deepEqual(codes(ok.get('domain')), ['domain.ns-ok']);

  const failed = await checkWith({ 'example.com NS': { rcode: 'SERVFAIL' } });
  assert.deepEqual(codes(failed.get('domain')), ['domain.ns-lookup-failed']);
});

test('SPF check_host: CIDR, macros (RFC 7208 §7.4)', () => {
  assert.ok(inCidr('192.0.2.200', '192.0.2.0', 24));
  assert.ok(!inCidr('192.0.3.1', '192.0.2.0', 24));
  assert.ok(inCidr('10.1.2.3', '0.0.0.0', 0));
  assert.ok(inCidr('2001:db8::1', '2001:db8::', 32));
  assert.ok(!inCidr('2001:db9::1', '2001:db8::', 32));
  assert.ok(!inCidr('192.0.2.1', '2001:db8::', 0));

  const e = { ip: '192.0.2.3', sender: 'strong-bad@email.example.com', helo: 'mx.example.org' };
  const d = 'email.example.com';
  const x = (s: string) => expandMacros(s, e, d);
  assert.equal(x('%{s}'), 'strong-bad@email.example.com');
  assert.equal(x('%{o}'), 'email.example.com');
  assert.equal(x('%{d2}'), 'example.com');
  assert.equal(x('%{d1}'), 'com');
  assert.equal(x('%{dr}'), 'com.example.email');
  assert.equal(x('%{d2r}'), 'example.email');
  assert.equal(x('%{l}'), 'strong-bad');
  assert.equal(x('%{l-}'), 'strong.bad');
  assert.equal(x('%{lr-}'), 'bad.strong');
  assert.equal(x('%{l1r-}'), 'strong');
  assert.equal(x('%{ir}.%{v}._spf.%{d2}'), '3.2.0.192.in-addr._spf.example.com');
  assert.equal(x('%{lr-}.lp._spf.%{d2}'), 'bad.strong.lp._spf.example.com');
  assert.equal(
    expandMacros('%{ir}.%{v}._spf.%{d2}', { ...e, ip: '2001:db8::cb01' }, d),
    '1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com',
  );
  assert.equal(x('%%%_%-'), '% %20');
});

test('SPF check_host: mechanisms, include, redirect and limits', async () => {
  const zone: Zone = {
    'example.com TXT': ['v=spf1 ip4:203.0.113.0/24 a:web.example.com mx include:_spf.provider.example ~all'],
    'web.example.com A': ['93.184.216.34'],
    'example.com MX': [{ preference: 10, exchange: 'mx.example.com' }],
    'mx.example.com A': ['93.184.216.25'],
    '_spf.provider.example TXT': ['v=spf1 ip4:151.101.0.0/16 -all'],
    'redir.example TXT': ['v=spf1 redirect=example.com'],
    'macro.example TXT': ['v=spf1 exists:%{i}._ip.macro.example -all'],
    '151.101.9.9._ip.macro.example A': ['127.0.0.2'],
    'broken.example TXT': ['v=spf1 include:nothing.example -all'],
    'two.example TXT': ['v=spf1 -all', 'v=spf1 +all'],
    'loop.example TXT': ['v=spf1 include:loop.example -all'],
  };
  const dns = new FakeDns(zone);
  const r = (ip: string, domain = 'example.com') => checkHost(dns, ip, domain, `a@${domain}`).then((x) => x.result);
  assert.equal(await r('203.0.113.7'), 'pass');
  assert.equal(await r('93.184.216.34'), 'pass');
  assert.equal(await r('93.184.216.25'), 'pass');
  assert.equal(await r('151.101.9.9'), 'pass');
  assert.equal(await r('8.8.8.8'), 'softfail');
  assert.equal(await r('151.101.9.9', 'redir.example'), 'pass');
  assert.equal(await r('151.101.9.9', 'macro.example'), 'pass');
  assert.equal(await r('151.101.9.8', 'macro.example'), 'fail');
  assert.equal(await r('8.8.8.8', 'broken.example'), 'permerror');
  assert.equal(await r('8.8.8.8', 'two.example'), 'permerror');
  assert.equal(await r('8.8.8.8', 'loop.example'), 'permerror');
  assert.equal(await r('8.8.8.8', 'none.example'), 'none');
  const failed = new FakeDns({ 'example.com TXT': { rcode: 'SERVFAIL' } });
  assert.equal((await checkHost(failed, '8.8.8.8', 'example.com', 'a@example.com')).result, 'temperror');
});

test('the Received header of the hop from the sender tells whether it arrived over TLS', () => {
  const rx = (v: string) => receivedOverTls([['Received', v]]);
  assert.equal(rx('from mail.example by mx.google.com with ESMTPS id x; Fri, 2 Oct 2026'), true);
  assert.equal(rx('from x by y (Postfix) with ESMTPSA id 1'), true);
  assert.equal(rx('from x by y with Microsoft SMTP Server (version=TLS1_2, cipher=…)'), true);
  assert.equal(rx('from x by y with ESMTP id 1'), false);
  assert.equal(receivedOverTls([['Subject', 'x']]), null);
  // Internal hops above the one from the sender are skipped (Gmail).
  const gmail: [string, string][] = [
    ['Received', 'by 2002:a05:6a10:1234 with SMTP id x; Thu, 2 Oct 2026'],
    ['Received', 'from relay.example (relay.example [198.51.100.1]) by mx.google.com with ESMTP id z'],
    ['Received', 'from out.example.com (out.example.com. [93.184.216.34]) by relay.example with ESMTPS id y'],
  ];
  assert.equal(receivedOverTls(gmail, '93.184.216.34'), true);
  assert.equal(receivedOverTls(gmail), false, 'without the client IP: the first hop with a "from"');
});

const senderZone: Zone = {
  'example.com TXT': ['v=spf1 ip4:93.184.216.34 -all'],
  'example.com MX': [{ preference: 10, exchange: 'mx.example.com' }],
  'mx.example.com A': ['93.184.216.25'],
  '_dmarc.example.com TXT': ['v=DMARC1; p=reject'],
  '34.216.184.93.in-addr.arpa PTR': ['out.example.com'],
  'out.example.com A': ['93.184.216.34'],
  '35.216.184.93.in-addr.arpa PTR': ['elsewhere.example.net'],
  'elsewhere.example.net A': ['93.184.216.99'],
};

async function senders(
  ips: string[],
  probeResults: NonNullable<Parameters<typeof runDomainChecks>[2]>['known'] extends infer K
    ? K extends { probeResults?: infer P }
      ? P
      : never
    : never = [],
) {
  const results = await runDomainChecks({ name: 'example.com', dkimSelectors: [], senderIps: ips }, checksConfig(), {
    dns: new FakeDns(senderZone),
    known: { reportSelectors: [], probeSelectors: [], probeIps: [], monitoredAddresses: [], probeResults },
  });
  return results.find((r) => r.check === 'senders')!;
}

test('Sending: reverse DNS and SPF of the sending IPs', async () => {
  const good = await senders(['93.184.216.34', '10.0.0.1']);
  assert.deepEqual(
    (good.data as SendersData).ips.map((s) => s.ip),
    ['93.184.216.34'],
    'private addresses are skipped',
  );
  assert.ok(codes(good).includes('senders.ips-ok'), codes(good).join());

  const bad = await senders(['93.184.216.35', '93.184.216.36']);
  const c = codes(bad);
  assert.ok(c.includes('senders.no-fcrdns'), c.join());
  assert.ok(c.includes('senders.no-ptr'), c.join());
  assert.equal(c.filter((x) => x === 'senders.spf-fail').length, 2);
  assert.equal(bad.level, 'error');

  const none = await senders([]);
  assert.deepEqual(codes(none), ['senders.unknown']);
});

test('Sending: the Gmail/Yahoo summary uses what the delivery tests saw', async () => {
  const pass = { spf: 'pass', dkim: 'pass', dmarc: 'pass', tls: true } as never;
  const r = await senders(
    ['93.184.216.34'],
    [{ recipient: 'Gmail', status: 'received', at: '2026-10-02T00:00:00Z', auth: pass }],
  );
  const req = (r.data as SendersData).requirements;
  const status = Object.fromEntries(req.map((x) => [x.id, x.status]));
  assert.equal(status.auth, 'ok');
  assert.equal(status['spf-and-dkim'], 'ok');
  assert.equal(status.fcrdns, 'ok');
  assert.equal(status.tls, 'ok');
  assert.equal(status.dmarc, 'ok');
  assert.equal(status.unsubscribe, 'n/a');
  assert.equal(r.findings.find((f) => f.code === 'senders.requirements')!.level, 'ok');

  const failing = { spf: 'fail', dkim: 'pass', dmarc: 'pass', tls: false } as never;
  const r2 = await senders(
    ['93.184.216.34'],
    [{ recipient: 'Gmail', status: 'received', at: '2026-10-02T00:00:00Z', auth: failing }],
  );
  const f = r2.findings.find((x) => x.code === 'senders.requirements')!;
  assert.equal(f.level, 'info');
  assert.match(f.title, /2 Gmail\/Yahoo sender requirements not met/);

  // No delivery test: DKIM cannot be judged from DNS, so nothing is claimed.
  const r3 = await senders(['93.184.216.34']);
  const s3 = Object.fromEntries((r3.data as SendersData).requirements.map((x) => [x.id, x.status]));
  assert.equal(s3['spf-and-dkim'], 'unknown');
  assert.equal(s3.auth, 'ok', 'SPF passes for the configured sending IP');
});

test('DKIM: key age is counted from the first sighting of the same key', async () => {
  const zone: Zone = { 's1._domainkey.example.com TXT': ['v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL'] };
  const first = await checkWith(zone, 'example.com', { selectors: ['s1'] });
  const sel = (first.get('dkim')!.data as DkimData).selectors[0]!;
  assert.ok(sel.keyHash && sel.keySince);
  assert.ok(!codes(first.get('dkim')).includes('dkim.old-key'));

  const old = (hash: string): CheckResult[] => [
    {
      ...first.get('dkim')!,
      data: { selectors: [{ ...sel, keyHash: hash, keySince: new Date(Date.now() - 400 * 86_400_000).toISOString() }] },
    },
  ];
  const again = await checkWith(zone, 'example.com', { selectors: ['s1'], previous: old(sel.keyHash!) });
  assert.ok(codes(again.get('dkim')).includes('dkim.old-key'));
  // A new key under the same selector starts a new age.
  const rotated = await checkWith(zone, 'example.com', { selectors: ['s1'], previous: old('different') });
  assert.ok(!codes(rotated.get('dkim')).includes('dkim.old-key'));
});

test('MX: REQUIRETLS and SMTPUTF8 are reported from the EHLO extensions', () => {
  const probe = (host: string, extensions: string[]) =>
    ({ host, ip: '1', connected: true, extensions }) as unknown as SmtpProbe;
  const f = new Findings();
  extensionFindings(f, [probe('a', ['SIZE 1000', 'REQUIRETLS', 'SMTPUTF8']), probe('b', ['SMTPUTF8'])]);
  const by = Object.fromEntries(f.list.map((x) => [x.code, x]));
  assert.equal(by['smtp.requiretls']!.level, 'info');
  assert.match(by['smtp.requiretls']!.title, /some MX hosts only/);
  assert.equal(by['smtp.smtputf8']!.level, 'ok');
});
