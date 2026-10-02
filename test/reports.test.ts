import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { zipSync, strToU8 } from 'fflate';
import { parseProbeHeaders, parseAuthResults } from '../src/server/auth-results.ts';
import type { DmarcReportRow } from '../src/server/db.ts';
import { buildDmarcOverview, partialSources, unalignedSources } from '../src/server/reports/dmarc-analysis.ts';
import { decompress, DmarcFormatError, parseAggregate } from '../src/server/reports/dmarc.ts';
import { extractReports } from '../src/server/reports/mail.ts';
import { fixture, fixtureText } from './helpers.ts';

test('DMARC aggregate reports are parsed (Google format, DMARCbis np)', () => {
  const r = parseAggregate(fixtureText('google-dmarc.xml'));
  assert.equal(r.orgName, 'google.com');
  assert.equal(r.reportId, '4271982475937195221');
  assert.equal(r.begin, '2025-10-01T00:00:00.000Z');
  assert.deepEqual(r.policy, {
    domain: 'example.com',
    adkim: 'r',
    aspf: 'r',
    p: 'reject',
    sp: 'reject',
    np: 'reject',
    pct: 100,
    fo: null,
  });
  assert.equal(r.records.length, 2);
  const [a, b] = r.records as [(typeof r.records)[0], (typeof r.records)[0]];
  assert.deepEqual([a.sourceIp, a.count, a.dkim, a.spf, a.dkimResults.length], ['192.0.2.10', 12, 'pass', 'pass', 2]);
  assert.equal(a.dkimResults[0]!.selector, 's1');
  assert.deepEqual(b.reasons, [{ type: 'local_policy', comment: 'arc=fail' }]);
  assert.equal(b.headerFrom, 'example.com');
  assert.equal(b.envelopeFrom, 'spoof.example');
  assert.deepEqual(b.spfResults, [{ domain: 'spoof.example', scope: 'mfrom', result: 'softfail' }]);
});

test('unusable DMARC XML is refused with a reason', () => {
  assert.throws(() => parseAggregate('<feedback><report_metadata/></feedback>'), DmarcFormatError);
  assert.throws(() => parseAggregate('<html></html>'), /no <feedback>/);
});

test('gzip and zip payloads are decompressed', () => {
  const xml = fixtureText('google-dmarc.xml');
  assert.equal(decompress(gzipSync(xml)).toString(), xml);
  const zip = Buffer.from(zipSync({ 'google.com!example.com!1!2.xml': strToU8(xml) }));
  assert.equal(decompress(zip).toString(), xml);
  assert.equal(decompress(Buffer.from(xml)).toString(), xml);
});

const eml = (parts: { type: string; name: string; data: Buffer }[]) =>
  Buffer.from(
    [
      'From: noreply-dmarc-support@google.com',
      'To: dmarc@example.com',
      'Subject: Report domain: example.com',
      'Date: Thu, 02 Oct 2025 06:00:00 +0000',
      'Message-ID: <r1@google.com>',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="b"',
      '',
      '--b',
      'Content-Type: text/plain',
      '',
      'This is a report.',
      ...parts.flatMap((p) => [
        '--b',
        `Content-Type: ${p.type}; name="${p.name}"`,
        `Content-Disposition: attachment; filename="${p.name}"`,
        'Content-Transfer-Encoding: base64',
        '',
        p.data.toString('base64'),
      ]),
      '--b--',
      '',
    ].join('\r\n'),
  );

test('messages are classified: DMARC aggregate, TLS-RPT, both, and failure reports', async () => {
  const xml = fixtureText('google-dmarc.xml');
  const dmarc = await extractReports(
    eml([{ type: 'application/zip', name: 'r.zip', data: Buffer.from(zipSync({ 'r.xml': strToU8(xml) })) }]),
  );
  assert.equal(dmarc.dmarc.length, 1);
  assert.equal(dmarc.tls.length, 0);
  assert.equal(dmarc.from, 'noreply-dmarc-support@google.com');

  const tlsJson = JSON.stringify(fixture('google-sts.json'));
  const both = await extractReports(
    eml([
      { type: 'application/gzip', name: 'r.xml.gz', data: gzipSync(xml) },
      { type: 'application/tlsrpt+gzip', name: 't.json.gz', data: gzipSync(tlsJson) },
    ]),
  );
  assert.deepEqual([both.dmarc.length, both.tls.length, both.errors], [1, 1, []]);

  const broken = await extractReports(
    eml([{ type: 'application/gzip', name: 'x.xml.gz', data: gzipSync('<feedback/>') }]),
  );
  assert.equal(broken.dmarc.length, 0);
  assert.equal(broken.errors.length, 1);

  const arf = await extractReports(Buffer.from(fixtureText('arf-dmarc.eml')));
  assert.ok(arf.failure);
  assert.deepEqual(
    [
      arf.failure.authFailure,
      arf.failure.reportedDomain,
      arf.failure.sourceIp,
      arf.failure.dkimSelector,
      arf.failure.deliveryResult,
    ],
    ['dmarc', 'wemail.no', '192.0.2.1', 's1', 'reject'],
  );
  assert.equal(arf.failure.originalMailFrom, 'bounce@wemail.no');
  assert.equal(arf.failure.subject, 'Your invoice');
  assert.match(arf.failure.headers!, /^From: "Wemail" <news@wemail.no>/);
  assert.equal(arf.failure.key, '<arf-1@reporter.example>');
});

const rec = (sourceIp: string, count: number, dkim: string, spf: string, dkimDomain = 'example.com') => ({
  sourceIp,
  count,
  disposition: 'none',
  dkim,
  spf,
  reasons: [],
  headerFrom: 'example.com',
  envelopeFrom: null,
  envelopeTo: null,
  dkimResults: [
    { domain: dkimDomain, selector: 's1', result: dkim === 'pass' || dkimDomain !== 'example.com' ? 'pass' : 'fail' },
  ],
  spfResults: [],
});

test('DMARC analysis finds partly failing and unaligned sources', () => {
  const report = (id: number, day: string, records: ReturnType<typeof rec>[]): DmarcReportRow => ({
    id,
    org: 'google.com',
    reportId: String(id),
    domain: 'example.com',
    email: null,
    extraContact: null,
    begin: `${day}T00:00:00.000Z`,
    end: `${day}T23:59:59.000Z`,
    day,
    receivedAt: null,
    policy: { domain: 'example.com', adkim: 'r', aspf: 'r', p: 'none', sp: null, np: null, pct: null, fo: null },
    errors: [],
    records,
  });
  const reports = [
    report(1, '2026-09-01', [rec('192.0.2.10', 100, 'pass', 'pass'), rec('192.0.2.20', 10, 'pass', 'pass')]),
    report(2, '2026-09-02', [
      rec('192.0.2.20', 6, 'fail', 'fail'),
      rec('198.51.100.7', 40, 'fail', 'fail', 'esp.example'),
      rec('203.0.113.9', 2, 'fail', 'fail'),
    ]),
  ];
  const o = buildDmarcOverview(reports, {}, new Date('2026-09-03T00:00:00Z'));
  assert.equal(o.kpis.messages, 158);
  assert.equal(o.kpis.failed, 48);
  assert.deepEqual(
    partialSources(o).map((s) => s.ip),
    ['192.0.2.20'],
  );
  assert.deepEqual(
    unalignedSources(o).map((s) => s.ip),
    ['198.51.100.7'],
  );
  const titles = o.insights.map((i) => i.title).join(' | ');
  assert.match(titles, /DMARC only partly/);
  assert.match(titles, /sign.* with another domain/);
  assert.match(titles, /p=none/);
  assert.deepEqual(
    o.series.map((s) => [s.start, s.passed, s.failed]),
    [
      ['2026-09-01', 110, 0],
      ['2026-09-02', 0, 48],
    ],
  );
});

const GMAIL = `Delivered-To: me@gmail.com
Received: by 2002:a05:6a10:1234 with SMTP id x;
        Thu, 2 Oct 2026 03:04:05 -0700 (PDT)
ARC-Authentication-Results: i=1; mx.google.com;
       dkim=pass header.i=@example.com header.s=s1 header.b=abc;
       spf=pass (google.com: domain of bounce@example.com designates 192.0.2.10 as permitted sender) smtp.mailfrom=bounce@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=s1 header.b=abc;
       dkim=pass header.i=@esp.example header.s=x header.b=def;
       spf=pass (google.com: domain of bounce@example.com designates 192.0.2.10 as permitted sender) smtp.mailfrom=bounce@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
Received-SPF: pass (google.com: domain of bounce@example.com designates 192.0.2.10 as permitted sender) client-ip=192.0.2.10;
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s1;
        h=from:to:subject; bh=x; b=y
DKIM-Signature: v=1; a=rsa-sha256; d=esp.example; s=x; h=from; bh=x; b=y
Subject: MailWatch delivery test 0123456789abcdef01234567
`;

const OUTLOOK = `Authentication-Results: spf=pass (sender IP is 198.51.100.25)
 smtp.mailfrom=example.net; dkim=fail (signature did not verify)
 header.d=example.net;dmarc=fail action=quarantine
 header.from=example.net;compauth=fail reason=000
Received-SPF: Pass (protection.outlook.com: domain of example.net designates
 198.51.100.25 as permitted sender) receiver=protection.outlook.com;
 client-ip=198.51.100.25; helo=mail.example.net; pr=C
X-MS-Exchange-Organization-SCL: 6
Subject: MailWatch delivery test 0123456789abcdef01234567
`;

test('recipient authentication results are read from Gmail and Outlook headers', () => {
  const g = parseProbeHeaders(GMAIL, 'example.com');
  assert.deepEqual(g.auth, { spf: 'pass', dkim: 'pass', dmarc: 'pass', arc: null, compauth: null, scl: null });
  assert.equal(g.clientIp, '192.0.2.10');
  assert.deepEqual(g.dkimSelectors, ['s1']);

  const o = parseProbeHeaders(OUTLOOK, 'example.net');
  assert.deepEqual(o.auth, {
    spf: 'pass',
    dkim: 'fail',
    dmarc: 'fail',
    arc: null,
    compauth: 'fail reason=000',
    scl: 6,
  });
  assert.equal(o.clientIp, '198.51.100.25');

  const ar = parseAuthResults('example.org; none');
  assert.deepEqual(ar, { authservId: 'example.org', results: [] });
  const quoted = parseAuthResults('mx.example (comment; with semicolon); spf=pass smtp.mailfrom="a;b@example.com"');
  assert.equal(quoted.authservId, 'mx.example');
  assert.equal(quoted.results[0]!.props['smtp.mailfrom'], 'a;b@example.com');
});
