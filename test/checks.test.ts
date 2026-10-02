import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import type { DmarcData, MxData, SpfData } from '../src/shared/types.ts';
import { analyseKey, keyBits } from '../src/server/checks/dkim.ts';
import { orgDomain, parseUris, related } from '../src/server/checks/dmarc.ts';
import { isRefusal } from '../src/server/checks/dnsbl.ts';
import { tlsaMatchesCert } from '../src/server/checks/dane.ts';
import { mxMatches, parsePolicy } from '../src/server/checks/mtasts.ts';
import { parseSpf } from '../src/server/checks/spf.ts';
import { isNonPublicIp, parseTags } from '../src/server/checks/util.ts';
import { expandIPv6, reverseName } from '../src/server/dns.ts';
import { checkWith, codes } from './helpers.ts';

const spfZone = (record: string, extra: Record<string, unknown[]> = {}) => ({
  'example.com TXT': [record],
  'example.com MX': [{ preference: 10, exchange: 'mx.example.com' }],
  'mx.example.com A': ['192.0.2.25'],
  ...extra,
});

test('SPF terms are parsed with qualifiers, prefixes and lookup costs', () => {
  const { terms, errors } = parseSpf(
    'v=spf1 +a/24 mx:mail.example.com//64 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.net ~all exp=x.example',
  );
  assert.deepEqual(errors, []);
  assert.deepEqual(
    terms.map((t) => [t.kind, t.qualifier, t.value, t.lookups]),
    [
      ['a', '+', null, 1],
      ['mx', null, 'mail.example.com', 1],
      ['ip4', null, '192.0.2.0', 0],
      ['ip6', null, '2001:db8::', 0],
      ['include', null, '_spf.example.net', 1],
      ['all', '~', null, 0],
      ['exp', null, 'x.example', 0],
    ],
  );
  assert.equal(terms[0]!.cidr4, 24);
  assert.equal(terms[1]!.cidr6, 64);
  assert.equal(terms[3]!.cidr6, 32);
});

test('SPF syntax errors are reported', () => {
  assert.match(parseSpf('v=spf1 ip4:999.1.1.1 -all').errors[0]!, /not a valid IPv4/);
  assert.match(parseSpf('v=spf1 foo:bar -all').errors[0]!, /unknown mechanism/);
  assert.match(parseSpf('v=spf1 redirect=a.example redirect=b.example').errors[0]!, /more than once/);
  assert.match(parseSpf('v=spf1 include -all').errors[0]!, /needs a domain/);
  assert.equal(parseSpf('v=spf1 exists:%{i}._spf.%{d} -all').errors.length, 0);
  assert.match(parseSpf('v=spf1 exists:%{z}.example -all').errors[0]!, /invalid macro/);
});

test('SPF counts DNS lookups across includes and flags the limit', async () => {
  const zone: Record<string, unknown[]> = {};
  const includes = Array.from({ length: 11 }, (_, i) => `i${i}.example.net`);
  for (const d of includes) zone[`${d} TXT`] = [`v=spf1 ip4:198.51.100.${includes.indexOf(d)} -all`];
  const r = await checkWith(spfZone(`v=spf1 ${includes.map((d) => `include:${d}`).join(' ')} -all`, zone));
  const spf = r.get('spf')!;
  assert.equal((spf.data as SpfData).lookups, 11);
  assert.ok(codes(spf).includes('spf.too-many-lookups'));
  assert.equal(spf.level, 'error');
  assert.equal((spf.data as SpfData).ip4.length, 11);
});

test('SPF: several records, missing include targets and void lookups', async () => {
  const two = await checkWith({ ...spfZone('v=spf1 -all'), 'example.com TXT': ['v=spf1 mx -all', 'v=spf1 a -all'] });
  assert.deepEqual(codes(two.get('spf')), ['spf.multiple']);
  const missing = await checkWith(
    spfZone('v=spf1 include:nothing.example a:gone1.example a:gone2.example a:gone3.example -all'),
  );
  const c = codes(missing.get('spf'));
  assert.ok(c.includes('spf.permerror'), c.join());
  assert.ok(c.includes('spf.too-many-void-lookups'), c.join());
  const near = await checkWith(spfZone('v=spf1 mx ?all'));
  assert.ok(codes(near.get('spf')).includes('spf.neutral-all'));
  const open = await checkWith(spfZone('v=spf1 +all'));
  assert.ok(codes(open.get('spf')).includes('spf.pass-all'));
  const ok = await checkWith(spfZone('v=spf1 mx -all'));
  assert.deepEqual(codes(ok.get('spf')), ['spf.ok']);
  assert.equal((ok.get('spf')!.data as SpfData).ip4[0], '192.0.2.25');
});

test('SPF include loops are a permerror, not an endless walk', async () => {
  const r = await checkWith(
    spfZone('v=spf1 include:a.example -all', { 'a.example TXT': ['v=spf1 include:example.com -all'] }),
  );
  assert.ok(codes(r.get('spf')).includes('spf.permerror'));
});

test('a SERVFAIL is reported as a failed lookup, not as a missing record', async () => {
  const r = await checkWith({ 'example.com TXT': { rcode: 'SERVFAIL' }, 'example.com MX': { rcode: 'SERVFAIL' } });
  assert.deepEqual(codes(r.get('spf')), ['spf.lookup-failed']);
  assert.deepEqual(codes(r.get('mx')), ['mx.lookup-failed']);
  assert.equal(r.get('spf')!.level, 'warning');
});

test('MX: Null MX, mixed Null MX, implicit MX, no MX', async () => {
  const parked = await checkWith({
    'example.com MX': [{ preference: 0, exchange: '' }],
    'example.com TXT': ['v=spf1 -all'],
  });
  assert.deepEqual(codes(parked.get('dkim')), ['dkim.not-sending']);
  const nullMx = await checkWith({ 'example.com MX': [{ preference: 0, exchange: '' }] });
  assert.deepEqual(codes(nullMx.get('mx')), ['mx.null']);
  assert.equal((nullMx.get('mx')!.data as MxData).nullMx, true);
  assert.ok(codes(nullMx.get('spf')).includes('spf.missing'));
  assert.match(nullMx.get('spf')!.findings[0]!.detail, /v=spf1 -all/);

  const mixed = await checkWith({
    'example.com MX': [
      { preference: 0, exchange: '' },
      { preference: 10, exchange: 'mx.example.com' },
    ],
  });
  assert.ok(codes(mixed.get('mx')).includes('mx.null-mixed'));

  const implicit = await checkWith({ 'example.com A': ['192.0.2.1'], 'example.com TXT': ['x'] });
  assert.ok(codes(implicit.get('mx')).includes('mx.implicit'));
  const none = await checkWith({ 'example.com TXT': ['x'] });
  assert.ok(codes(none.get('mx')).includes('mx.none'));
  const nx = await checkWith({});
  assert.deepEqual(codes(nx.get('mx')), ['mx.nxdomain']);
});

test('MX hosts without address or with private addresses are errors; missing PTR is a warning', async () => {
  const r = await checkWith({
    'example.com MX': [
      { preference: 10, exchange: 'mx1.example.com' },
      { preference: 20, exchange: 'mx2.example.com' },
      { preference: 30, exchange: 'mx3.example.com' },
    ],
    'mx1.example.com A': ['10.1.2.3'],
    'mx2.example.com TXT': ['exists but no address'],
    'mx3.example.com A': ['192.0.2.30'],
    '30.2.0.192.in-addr.arpa PTR': [],
  });
  const c = codes(r.get('mx'));
  assert.ok(c.includes('mx.private-ip'));
  assert.ok(c.includes('mx.no-address'));
  assert.ok(c.includes('mx.no-ptr'));
});

const dmarcZone = (record: string, extra: Record<string, unknown[]> = {}) => ({
  'example.com MX': [{ preference: 0, exchange: '' }],
  '_dmarc.example.com TXT': [record],
  ...extra,
});

test('DMARC: policy, pct, syntax, unknown tags', async () => {
  const none = await checkWith(dmarcZone('v=DMARC1; p=none; rua=mailto:d@example.com'));
  assert.ok(codes(none.get('dmarc')).includes('dmarc.p-none'));
  const pct = await checkWith(dmarcZone('v=DMARC1; p=reject; pct=20; rua=mailto:d@example.com'));
  assert.ok(codes(pct.get('dmarc')).includes('dmarc.pct'));
  const bad = await checkWith(dmarcZone('v=DMARC1; p=maybe; adkim=x; foo=bar'));
  const c = codes(bad.get('dmarc'));
  assert.ok(c.includes('dmarc.invalid-policy'));
  assert.ok(c.includes('dmarc.invalid-alignment'));
  assert.ok(c.includes('dmarc.unknown-tags'));
  assert.ok(c.includes('dmarc.no-rua'));
  const order = await checkWith(dmarcZone('p=reject; v=DMARC1'));
  // Not starting with v=DMARC1: not a DMARC record at all (RFC 7489 §6.6.3).
  assert.ok(codes(order.get('dmarc')).includes('dmarc.missing'));
  const two = await checkWith({
    ...dmarcZone('x'),
    '_dmarc.example.com TXT': ['v=DMARC1; p=none', 'v=DMARC1; p=reject'],
  });
  assert.deepEqual(codes(two.get('dmarc')), ['dmarc.multiple']);
});

test('DMARC: external report destinations need an authorisation record (RFC 7489 §7.1)', async () => {
  const record = 'v=DMARC1; p=reject; rua=mailto:a@reports.example,mailto:b@other.example';
  const r = await checkWith(
    dmarcZone(record, { 'example.com._report._dmarc.reports.example TXT': ['v=DMARC1'] }),
    'example.com',
    {
      known: { monitoredAddresses: ['a@reports.example'] },
    },
  );
  const d = r.get('dmarc')!;
  const data = d.data as DmarcData;
  assert.deepEqual(
    data.rua.map((u) => [u.address, u.authorized, u.monitored]),
    [
      ['a@reports.example', true, true],
      ['b@other.example', false, false],
    ],
  );
  const f = d.findings.find((x) => x.code === 'dmarc.external-unauthorized')!;
  assert.equal(f.subject, 'b@other.example');
  assert.deepEqual(f.refs, [{ doc: 'rfc7489', section: '7.1' }]);
});

test('DMARC: a subdomain inherits the parent policy (tree walk)', async () => {
  const r = await checkWith(
    {
      'shop.example.com MX': [{ preference: 0, exchange: '' }],
      '_dmarc.example.com TXT': ['v=DMARC1; p=reject; sp=quarantine'],
    },
    'shop.example.com',
  );
  const d = r.get('dmarc')!;
  assert.equal((d.data as DmarcData).name, 'example.com');
  assert.ok(codes(d).includes('dmarc.inherited'));
  assert.ok(codes(d).includes('dmarc.p-quarantine'), codes(d).join());
});

test('DMARC: a failed parent lookup is "unknown", not "no record"', async () => {
  const r = await checkWith(
    { 'shop.example.com MX': [{ preference: 0, exchange: '' }], '_dmarc.example.com TXT': { rcode: 'SERVFAIL' } },
    'shop.example.com',
  );
  assert.deepEqual(codes(r.get('dmarc')), ['dmarc.lookup-failed']);
});

test('DMARC report destinations in the same organisational domain need no authorisation', async () => {
  const r = await checkWith(dmarcZone('v=DMARC1; p=reject; rua=mailto:d@reports.example.com'), 'example.com');
  assert.equal((r.get('dmarc')!.data as DmarcData).rua[0]!.authorized, null);
  assert.equal(orgDomain('mail.shop.example.co.uk'), 'example.co.uk');
  assert.equal(orgDomain('a.b.example.com'), 'example.com');
  assert.equal(related('a.example.com', 'b.example.com'), true);
  const bad = parseUris('mailto:a%zz@example.com', []);
  assert.equal(bad.uris.length, 1);
});

test('DKIM: configured selectors must exist; common ones are silent when absent', async () => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
  const p = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const r = await checkWith(
    {
      'example.com MX': [{ preference: 0, exchange: '' }],
      'k1._domainkey.example.com TXT': [`v=DKIM1; k=rsa; p=${p}`],
    },
    'example.com',
    { selectors: ['k1', 'gone'] },
  );
  const d = r.get('dkim')!;
  assert.deepEqual(codes(d).sort(), ['dkim.selector-missing', 'dkim.short-key']);
  assert.equal(d.findings.find((f) => f.code === 'dkim.selector-missing')!.subject, 'gone');
});

test('DKIM key records are analysed', () => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const p = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  assert.equal(keyBits('rsa', p), 2048);
  const pkcs1 = publicKey.export({ type: 'pkcs1', format: 'der' }).toString('base64');
  assert.equal(keyBits('rsa', pkcs1), 2048);
  assert.equal(keyBits('ed25519', Buffer.alloc(32, 1).toString('base64')), 256);
  assert.deepEqual(analyseKey(`v=DKIM1; p=${p}`).problems, []);
  assert.ok(analyseKey(`v=DKIM1; t=y; p=${p}`).problems.some((x) => x.code === 'dkim.testing'));
  assert.ok(analyseKey(`v=DKIM1; h=sha1; p=${p}`).problems.some((x) => x.code === 'dkim.sha1'));
  assert.ok(analyseKey(`k=rsa; v=DKIM1; p=${p}`).problems.some((x) => x.code === 'dkim.version'));
  assert.equal(analyseKey('v=DKIM1; p=').revoked, true);
  assert.ok(analyseKey('v=DKIM1; p=bm90IGEga2V5').problems.some((x) => x.code === 'dkim.bad-key'));
});

test('MTA-STS policies are parsed and MX patterns match one label', () => {
  const p = parsePolicy(
    'version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n',
  );
  assert.deepEqual(
    [p.version, p.mode, p.maxAge, p.mx, p.errors],
    ['STSv1', 'enforce', 604800, ['mail.example.com', '*.example.net'], []],
  );
  assert.ok(parsePolicy('version: STSv1\nmode: sometimes\nmax_age: 99999999999').errors.length >= 2);
  assert.match(parsePolicy('version: STSv1\nmode: enforce\nmax_age: 1').errors.join(), /no mx patterns/);
  assert.equal(mxMatches('*.example.net', 'mx1.example.net'), true);
  assert.equal(mxMatches('*.example.net', 'a.b.example.net'), false);
  assert.equal(mxMatches('*.example.net', 'example.net'), false);
  assert.equal(mxMatches('Mail.Example.com', 'mail.example.com'), true);
});

test('TLSA matching by selector and matching type', () => {
  const c = {
    certDer: 'aa',
    certSha256: 'c256',
    certSha512: 'c512',
    spkiDer: 'bb',
    spkiSha256: 's256',
    spkiSha512: 's512',
  } as Parameters<typeof tlsaMatchesCert>[1];
  assert.equal(tlsaMatchesCert({ selector: 1, matchingType: 1, data: 'S256' }, c), true);
  assert.equal(tlsaMatchesCert({ selector: 0, matchingType: 2, data: 'c512' }, c), true);
  assert.equal(tlsaMatchesCert({ selector: 1, matchingType: 0, data: 'bb' }, c), true);
  assert.equal(tlsaMatchesCert({ selector: 0, matchingType: 1, data: 's256' }, c), false);
});

test('small helpers', () => {
  assert.deepEqual(parseTags(' v=DMARC1 ; p = reject;;rua=mailto:a@b ').tags, {
    v: 'DMARC1',
    p: 'reject',
    rua: 'mailto:a@b',
  });
  assert.deepEqual(parseTags('v=1; v=2; junk').errors.length, 2);
  assert.equal(related('mail.example.com', 'example.com'), true);
  assert.equal(related('example.com', 'example.net'), false);
  const u = parseUris('mailto:dmarc@Example.com!10m, https://r.example/x, nonsense', ['dmarc@example.com']);
  assert.deepEqual(
    u.uris.map((x) => [x.scheme, x.address, x.domain, x.monitored]),
    [
      ['mailto', 'dmarc@example.com', 'example.com', true],
      ['https', null, 'r.example', false],
    ],
  );
  assert.equal(u.errors.length, 1);
  assert.equal(isRefusal('127.255.255.254'), true);
  assert.equal(isRefusal('127.0.0.2'), false);
  assert.equal(reverseName('192.0.2.1', 'zen.spamhaus.org'), '1.2.0.192.zen.spamhaus.org');
  assert.equal(expandIPv6('2001:db8::1'), '2001:0db8:0000:0000:0000:0000:0000:0001');
  assert.equal(expandIPv6('::'), '0000:0000:0000:0000:0000:0000:0000:0000');
  assert.equal(isNonPublicIp('172.20.1.1'), true);
  assert.equal(isNonPublicIp('fd00::1'), true);
  assert.equal(isNonPublicIp('::ffff:10.0.0.5'), true);
  assert.equal(isNonPublicIp('192.0.2.1'), false);
});

test('blocklists: own resolver, Spamhaus DQS, and the key never shows', async () => {
  const key = 'abcdefghijklmnopqrstuvwxyz';
  const { runDomainChecks } = await import('../src/server/checks/index.ts');
  const { queryZone } = await import('../src/server/checks/dnsbl.ts');
  const { FakeDns, checksConfig } = await import('./helpers.ts');
  assert.equal(queryZone('zen.spamhaus.org', key), `${key}.zen.dq.spamhaus.net`);
  assert.equal(queryZone('dbl.spamhaus.org', key), `${key}.dbl.dq.spamhaus.net`);
  assert.equal(queryZone('zen.spamhaus.org', null), 'zen.spamhaus.org');
  assert.equal(queryZone('bl.spamcop.net', key), 'bl.spamcop.net');

  // The checks' resolver knows the domain; only the blocklist resolver knows the listings.
  const checks = new FakeDns({
    'example.com MX': [{ preference: 10, exchange: 'mx.example.com' }],
    'mx.example.com A': ['192.0.2.25'],
  });
  const lists = new FakeDns({
    [`25.2.0.192.${key}.zen.dq.spamhaus.net A`]: ['127.0.0.4'],
    [`example.com.${key}.dbl.dq.spamhaus.net A`]: ['127.255.255.252'],
    '25.2.0.192.bl.spamcop.net A': ['127.0.0.2'],
    '25.2.0.192.bl.spamcop.net TXT': ['Blocked - see spamcop'],
  });
  const cfg = {
    ...checksConfig(),
    ipZones: ['zen.spamhaus.org', 'bl.spamcop.net'],
    domainZones: ['dbl.spamhaus.org'],
    spamhausDqsKey: key,
  };
  const results = await runDomainChecks({ name: 'example.com', dkimSelectors: [], senderIps: [] }, cfg, {
    dns: checks,
    blocklistDns: lists,
  });
  const bl = results.find((r) => r.check === 'dnsbl')!;
  assert.deepEqual(
    bl.findings.map((f) => [f.code, f.subject]),
    [
      ['dnsbl.listed', '192.0.2.25 zen.spamhaus.org'],
      ['dnsbl.listed', '192.0.2.25 bl.spamcop.net'],
      ['dnsbl.refused', 'dbl.spamhaus.org'],
    ],
  );
  assert.match(bl.findings[0]!.detail, /XBL/);
  assert.match(bl.findings[2]!.detail, /DQS refused the queries/);
  assert.ok(!JSON.stringify(results).includes(key), 'the DQS key never appears in results');
  assert.ok(
    !checks.asked.some((q) => q.includes('spamhaus') || q.includes('spamcop')),
    'blocklists use their own resolver',
  );
  assert.ok(!lists.asked.some((q) => q.startsWith('example.com MX')), 'the other checks do not');
});
