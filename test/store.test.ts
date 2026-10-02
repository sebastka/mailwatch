// Integration tests against a real MariaDB. Skipped unless TEST_DB_HOST is set.
// The database named TEST_DB_NAME (default mailwatch_test) is dropped and recreated.
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import type { CheckResult, DeliveryProbe, Finding } from '../src/shared/types.ts';
import { Alerts } from '../src/server/alerts.ts';
import { recordSignature } from '../src/server/checks/signature.ts';
import { Store } from '../src/server/db.ts';
import { parseAggregate } from '../src/server/reports/dmarc.ts';
import { extractReports } from '../src/server/reports/mail.ts';
import { reportFindings } from '../src/server/reports/findings.ts';
import { normalizeReport } from '../src/server/reports/tlsrpt.ts';
import { saveSettings, DEFAULT_SETTINGS } from '../src/server/settings.ts';
import { fixture, fixtureText, freshDatabase, testDb } from './helpers.ts';

const env = process.env;
const src = {
  from: 'r@example.net',
  subject: 's',
  filename: 'f.xml.gz',
  mailbox: 'm@x/INBOX',
  receivedAt: '2026-09-28T16:02:31.000Z',
};

class FakeTelegram {
  configured = true;
  sent: string[] = [];
  fail = false;
  async send(html: string) {
    if (this.fail) throw new Error('Telegram down');
    this.sent.push(html);
  }
}

const finding = (code: string, level: Finding['level'], subject?: string): Finding => ({
  code,
  level,
  title: `${code} title`,
  detail: `${code} detail`,
  refs: [{ doc: 'rfc7208', section: '4.6.4' }],
  ...(subject ? { subject } : {}),
});
const result = (domain: string, check: CheckResult['check'], findings: Finding[], data: unknown = {}): CheckResult => ({
  domain,
  check,
  level: 'ok',
  checkedAt: new Date().toISOString(),
  durationMs: 1,
  findings,
  data,
});

describe('Store and alerts (MariaDB)', { skip: env.TEST_DB_HOST ? false : 'TEST_DB_HOST not set' }, () => {
  let store: Store;
  before(async () => {
    store = await freshDatabase(testDb());
  });
  after(async () => {
    await store?.close();
  });

  test('migrations are idempotent', async () => {
    const again = await Store.connect(testDb());
    await again.close();
  });

  test('reports are stored once and loaded back with their records', async () => {
    const xml = fixtureText('google-dmarc.xml');
    assert.equal(await store.insertDmarcReport(parseAggregate(xml), xml, src), true);
    assert.equal(await store.insertDmarcReport(parseAggregate(xml), xml, src), false);
    const [r] = await store.loadDmarcReports({ domain: 'example.com' });
    assert.ok(r);
    assert.equal(r.records.length, 2);
    assert.equal(r.records[0]!.dkimResults[0]!.selector, 's1');
    assert.equal(r.policy.p, 'reject');
    assert.equal((await store.dmarcReportSource(r.id))!.raw, xml);
    assert.deepEqual(await store.loadDmarcReports({ domain: 'other.example' }), []);

    const raw = fixture('google-sts.json');
    assert.equal(await store.insertTlsReport(normalizeReport(raw), raw, src), true);
    assert.equal(await store.insertTlsReport(normalizeReport(raw), raw, src), false);
    assert.equal((await store.loadTlsReports({})).length, 1);

    const arf = await extractReports(Buffer.from(fixtureText('arf-dmarc.eml')));
    assert.equal(await store.insertFailureReport(arf.failure!, src), true);
    assert.equal(await store.insertFailureReport(arf.failure!, src), false);
    const [fr] = await store.failureReports({ domain: 'wemail.no' });
    assert.equal(fr!.sourceIp, '192.0.2.1');
    assert.match((await store.failureReport(fr!.id))!.headers!, /Your invoice/);
  });

  test('dates are stored as UTC whatever the process time zone', async () => {
    const [row] = await store.pool.query<{ t: string }[]>('SELECT begin_ts AS t FROM dmarc_reports LIMIT 1');
    assert.equal(row!.t, '2025-10-01 00:00:00');
  });

  test('check results replace the previous ones; removed domains are pruned', async () => {
    await store.saveCheckResults([
      result('a.example', 'spf', [finding('spf.ok', 'ok')]),
      result('b.example', 'spf', []),
    ]);
    await store.saveCheckResults([result('a.example', 'spf', [finding('spf.multiple', 'error')])]);
    const rows = await store.checkResults({ check: 'spf' });
    assert.deepEqual(
      rows.map((r) => [r.domain, r.findings.map((f) => f.code)]),
      [
        ['a.example', ['spf.multiple']],
        ['b.example', []],
      ],
    );
    await store.pruneCheckResults(['a.example']);
    assert.deepEqual(
      (await store.checkResults({})).map((r) => r.domain),
      ['a.example'],
    );
  });

  test('finding streaks count consecutive sightings', async () => {
    assert.deepEqual(
      [...(await store.updateStreaks('s', ['x', 'y']))],
      [
        ['x', 1],
        ['y', 1],
      ],
    );
    assert.deepEqual([...(await store.updateStreaks('s', ['x']))], [['x', 2]]);
    assert.deepEqual(
      [...(await store.updateStreaks('s', ['x', 'y']))],
      [
        ['x', 3],
        ['y', 1],
      ],
    );
    assert.deepEqual([...(await store.updateStreaks('other', ['x']))], [['x', 1]]);
  });

  describe('alert lifecycle', () => {
    let tg: FakeTelegram;
    let alerts: Alerts;
    let clock = Date.parse('2026-10-02T12:00:00Z');
    beforeEach(async () => {
      await store.pool.query('DELETE FROM alerts');
      await store.pool.query('DELETE FROM finding_streaks');
      await store.pool.query('DELETE FROM snoozes');
      await saveSettings(store, DEFAULT_SETTINGS);
      tg = new FakeTelegram();
      clock = Date.now();
      alerts = new Alerts(store, tg, {
        now: () => clock,
        confirmations: 2,
        timezone: 'UTC',
        publicUrl: 'https://mw.example',
        log: () => {},
      });
    });

    test('a finding alerts after two checks, is announced once per domain, and resolves', async () => {
      const bad = [
        result('a.example', 'spf', [finding('spf.too-many-lookups', 'error')]),
        result('a.example', 'dmarc', [finding('dmarc.p-none', 'warning')]),
      ];
      await alerts.checks('a.example', bad);
      assert.equal((await store.openAlerts()).length, 0, 'not confirmed yet');
      await alerts.checks('a.example', bad);
      const open = await store.openAlerts();
      assert.deepEqual(open.map((a) => [a.code, a.severity]).sort(), [
        ['dmarc.p-none', 'warning'],
        ['spf.too-many-lookups', 'error'],
      ]);
      await alerts.notify();
      assert.equal(tg.sent.length, 1);
      assert.match(tg.sent[0]!, /2 problems<\/b> · a\.example/);
      assert.match(tg.sent[0]!, /RFC 7208 §4\.6\.4/);
      assert.match(tg.sent[0]!, /https:\/\/mw\.example\/spf\?domain=a\.example/);
      await alerts.notify();
      assert.equal(tg.sent.length, 1, 'announced once');

      // The SPF problem is fixed; the DMARC one stays.
      await alerts.checks('a.example', [result('a.example', 'spf', []), bad[1]!]);
      assert.deepEqual(
        (await store.openAlerts()).map((a) => a.code),
        ['dmarc.p-none'],
      );
      await alerts.notify();
      assert.equal(tg.sent.length, 2);
      assert.match(tg.sent[1]!, /Resolved/);
      assert.match(tg.sent[1]!, /spf\.too-many-lookups title/);
    });

    test('an escalation is announced again, also after a silenced warning', async () => {
      await saveSettings(store, { ...DEFAULT_SETTINGS, notifyMinSeverity: 'error' });
      const warn = [result('a.example', 'mx', [finding('smtp.cert-expiring', 'warning', 'mx 1.2.3.4')])];
      await alerts.checks('a.example', warn);
      await alerts.checks('a.example', warn);
      await alerts.notify();
      assert.equal(tg.sent.length, 0, 'below the threshold');
      const err = [result('a.example', 'mx', [finding('smtp.cert-expiring', 'error', 'mx 1.2.3.4')])];
      await alerts.checks('a.example', err);
      await alerts.notify();
      assert.equal(tg.sent.length, 1);
      const open = await store.openAlerts();
      assert.deepEqual(
        open.map((a) => [a.code, a.severity]),
        [['smtp.cert-expiring', 'error']],
      );
    });

    test('alerts of domains that are no longer configured are closed silently', async () => {
      const bad = [result('gone.example', 'spf', [finding('spf.multiple', 'error')])];
      await alerts.checks('gone.example', bad);
      await alerts.checks('gone.example', bad);
      await alerts.notify();
      await alerts.pruneDomains(['a.example']);
      assert.deepEqual(await store.openAlerts(), []);
      await alerts.notify();
      assert.equal(tg.sent.length, 1, 'no "resolved" message');
    });

    test('if the MX lookup fails, the alerts of the checks built on it stay open', async () => {
      const bad = [result('a.example', 'dane', [finding('dane.mismatch', 'error', 'mx')])];
      await alerts.checks('a.example', bad);
      await alerts.checks('a.example', bad);
      await alerts.checks('a.example', [
        result('a.example', 'mx', [finding('mx.lookup-failed', 'warning')]),
        result('a.example', 'dane', []),
      ]);
      assert.deepEqual(
        (await store.openAlerts()).map((a) => a.code),
        ['dane.mismatch'],
      );
    });

    test('a failed lookup keeps the alerts of that check open', async () => {
      const bad = [result('a.example', 'spf', [finding('spf.multiple', 'error')])];
      await alerts.checks('a.example', bad);
      await alerts.checks('a.example', bad);
      await alerts.checks('a.example', [result('a.example', 'spf', [finding('spf.lookup-failed', 'warning')])]);
      const open = await store.openAlerts();
      assert.ok(open.some((a) => a.code === 'spf.multiple'));
    });

    test('snoozed and low-severity alerts are not sent, nor their end', async () => {
      await saveSettings(store, { ...DEFAULT_SETTINGS, notifyMinSeverity: 'error' });
      const bad = [
        result('a.example', 'dmarc', [finding('dmarc.p-none', 'warning')]),
        result('a.example', 'mx', [finding('smtp.no-starttls', 'error', 'mx 1.2.3.4')]),
      ];
      await store.snooze('check|mx|smtp.no-starttls|a.example|mx 1.2.3.4', 't', 60, 'me');
      await alerts.checks('a.example', bad);
      await alerts.checks('a.example', bad);
      await alerts.notify();
      assert.equal(tg.sent.length, 0);
      const all = await store.listAlerts({ active: true });
      assert.ok(all.every((a) => a.silenced));
      await alerts.checks('a.example', []);
      await alerts.notify();
      assert.equal(tg.sent.length, 0);
    });

    test('quiet hours hold warnings but not errors', async () => {
      const h = new Date(clock).getUTCHours();
      const pad = (n: number) => String((n + 24) % 24).padStart(2, '0');
      await saveSettings(store, {
        ...DEFAULT_SETTINGS,
        quietHours: { enabled: true, start: `${pad(h - 1)}:00`, end: `${pad(h + 2)}:00`, exemptErrors: true },
      });
      const bad = [result('a.example', 'dmarc', [finding('dmarc.p-none', 'warning')])];
      await alerts.checks('a.example', bad);
      await alerts.checks('a.example', bad);
      await alerts.notify();
      assert.equal(tg.sent.length, 0, 'warning held');
      const err = [result('b.example', 'spf', [finding('spf.multiple', 'error')])];
      await alerts.checks('b.example', err);
      await alerts.checks('b.example', err);
      await alerts.notify();
      assert.equal(tg.sent.length, 1, 'error sent anyway');
      assert.match(tg.sent[0]!, /b\.example/);
    });

    test('a failed send is retried on the next cycle', async () => {
      const bad = [result('a.example', 'spf', [finding('spf.multiple', 'error')])];
      await alerts.checks('a.example', bad);
      await alerts.checks('a.example', bad);
      tg.fail = true;
      await alerts.notify();
      assert.equal(alerts.lastNotifyError, 'Telegram down');
      tg.fail = false;
      await alerts.notify();
      assert.equal(tg.sent.length, 1);
      assert.equal(alerts.lastNotifyError, null);
    });

    test('delivery results open and resolve delivery alerts', async () => {
      const probe = (status: DeliveryProbe['status'], dmarc: string | null = null): DeliveryProbe => ({
        id: 1,
        sender: 'a.example',
        recipient: 'Gmail',
        token: 't',
        sentAt: new Date(clock).toISOString(),
        status,
        smtpResponse: null,
        error: null,
        receivedAt: null,
        folder: 'INBOX',
        latencySeconds: 5,
        auth: dmarc ? { spf: 'pass', dkim: 'fail', dmarc, arc: null, compauth: null, scl: null } : null,
        clientIp: null,
        dkimSelectors: [],
        headers: null,
      });
      await alerts.delivery([probe('lost')], ['a.example'], ['Gmail'], 30);
      assert.deepEqual(
        (await store.openAlerts()).map((a) => a.code),
        ['delivery.lost'],
      );
      await alerts.delivery([probe('spam', 'fail')], ['a.example'], ['Gmail'], 30);
      assert.deepEqual((await store.openAlerts()).map((a) => a.code).sort(), ['delivery.dmarc', 'delivery.spam']);
      await alerts.delivery([probe('inbox', 'pass')], ['a.example'], ['Gmail'], 30);
      assert.deepEqual(await store.openAlerts(), []);
      // Pairs that are no longer configured do not alert.
      await alerts.delivery([probe('lost')], ['b.example'], ['Gmail'], 30);
      assert.deepEqual(await store.openAlerts(), []);
    });
  });

  test('report findings flag sources that partly fail DMARC', async () => {
    await store.pool.query('DELETE FROM dmarc_reports');
    const today = new Date().toISOString().slice(0, 10);
    const xml = fixtureText('google-dmarc.xml').replace('1759276800', String(Date.parse(`${today}T00:00:00Z`) / 1000));
    const rep = parseAggregate(xml);
    // The same source passes in one record and fails in another (≥ 5 messages).
    rep.records.push({ ...rep.records[0]!, count: 7, dkim: 'fail', spf: 'fail' });
    await store.insertDmarcReport(rep, xml, src);
    const f = await reportFindings(store, ['example.com'], 7);
    assert.deepEqual(
      f.get('example.com')!.map((x) => x.code),
      ['dmarc-reports.partial'],
    );
    assert.deepEqual(await store.dmarcSelectors('example.com', 7), ['s1']);
  });

  test('record changes are logged with their signature', async () => {
    const a = result('a.example', 'spf', [], { records: ['v=spf1 -all'] });
    const b = result('a.example', 'spf', [], { records: ['v=spf1 mx -all'] });
    const failed = result('a.example', 'spf', [finding('spf.lookup-failed', 'warning')], { records: [] });
    assert.equal(recordSignature(a), 'v=spf1 -all');
    assert.equal(recordSignature(failed), undefined, 'a failed lookup is not a change');
    await store.recordChange('a.example', 'spf', recordSignature(a)!, recordSignature(b)!, new Date().toISOString());
    const [c] = await store.changes({ domain: 'a.example' });
    assert.deepEqual([c!.before, c!.after], ['v=spf1 -all', 'v=spf1 mx -all']);
  });
});
