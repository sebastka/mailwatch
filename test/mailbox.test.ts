// End-to-end against a disposable IMAP server (the dovecot/dovecot image from compose.yaml) and
// MariaDB. Skipped unless TEST_IMAP_HOST and TEST_DB_HOST are set. Never point this at a real
// mailbox: it logs in as fresh random users, which the test server creates on the fly.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { strToU8, zipSync } from 'fflate';
import { ImapFlow } from 'imapflow';
import type { ImapConfig, MailboxConfig, RecipientConfig } from '../src/server/config.ts';
import type { Store } from '../src/server/db.ts';
import { Delivery, PROBE_SUBJECT } from '../src/server/delivery.ts';
import { cleanupCutoff, ReportSyncer, selectForDeletion } from '../src/server/sync.ts';
import { fixture, fixtureText, freshDatabase, testDb } from './helpers.ts';

test('cleanup cutoff is N calendar months back, clamped to the end of shorter months', () => {
  const day = (d: Date) => d.toISOString().slice(0, 10);
  assert.equal(day(cleanupCutoff(new Date('2026-09-29T15:00:00Z'), 6)), '2026-03-29');
  assert.equal(day(cleanupCutoff(new Date('2026-03-31T00:00:00Z'), 1)), '2026-02-28');
  assert.equal(day(cleanupCutoff(new Date('2028-03-31T00:00:00Z'), 1)), '2028-02-29');
  assert.equal(day(cleanupCutoff(new Date('2026-01-15T00:00:00Z'), 2)), '2025-11-15');
});

test('only processed and imported messages are selected for deletion', () => {
  const { remove, kept } = selectForDeletion([7, 3, 5, 9, 1], 7, new Set([1, 3, 7, 9]));
  assert.deepEqual(remove, [1, 3, 7]); // 5 not imported, 9 above the last processed UID
  assert.equal(kept, 2);
});

const env = process.env;
describe(
  'mailboxes (IMAP + MariaDB)',
  { skip: env.TEST_IMAP_HOST && env.TEST_DB_HOST ? false : 'TEST_IMAP_HOST/TEST_DB_HOST not set' },
  () => {
    const imapCfg = (user: string): ImapConfig => ({
      host: env.TEST_IMAP_HOST!,
      port: Number(env.TEST_IMAP_PORT ?? 31993),
      secure: true,
      rejectUnauthorized: false,
      auth: { kind: 'password', user, pass: env.TEST_IMAP_PASSWORD ?? 'secret' },
    });
    const client = (user: string) =>
      new ImapFlow({
        host: env.TEST_IMAP_HOST!,
        port: Number(env.TEST_IMAP_PORT ?? 31993),
        secure: true,
        auth: { user, pass: env.TEST_IMAP_PASSWORD ?? 'secret' },
        tls: { rejectUnauthorized: false },
        logger: false,
      });
    let store: Store;
    before(async () => {
      store = await freshDatabase(testDb('_imap'));
    });
    after(async () => {
      await store?.close();
    });

    const mime = (date: string, subject: string, parts: { type: string; name: string; data: Buffer }[]) =>
      [
        'From: reporter@example.net',
        `Date: ${date}`,
        `Subject: ${subject}`,
        `Message-ID: <${randomBytes(6).toString('hex')}@example.net>`,
        'MIME-Version: 1.0',
        ...(parts.length
          ? [
              'Content-Type: multipart/mixed; boundary="b"',
              '',
              ...parts.flatMap((p) => [
                '--b',
                `Content-Type: ${p.type}`,
                `Content-Disposition: attachment; filename="${p.name}"`,
                'Content-Transfer-Encoding: base64',
                '',
                p.data.toString('base64'),
              ]),
              '--b--',
            ]
          : ['Content-Type: text/plain', '', 'Not a report.']),
        '',
      ].join('\r\n');

    test('report mailboxes: every kind is imported once; the cleanup deletes only old imported messages', async () => {
      const user = `reports-${randomBytes(4).toString('hex')}`;
      const c = client(user);
      await c.connect();
      const xml = fixtureText('google-dmarc.xml');
      const old = 'Mon, 01 Jan 2024 10:00:00 +0000';
      const recent = new Date().toUTCString();
      await c.append(
        'INBOX',
        mime(old, 'old dmarc', [
          { type: 'application/zip', name: 'r.zip', data: Buffer.from(zipSync({ 'r.xml': strToU8(xml) })) },
        ]),
      );
      await c.append(
        'INBOX',
        mime(recent, 'tls', [
          {
            type: 'application/tlsrpt+gzip',
            name: 't.json.gz',
            data: gzipSync(JSON.stringify(fixture('google-sts.json'))),
          },
        ]),
      );
      await c.append('INBOX', fixtureText('arf-dmarc.eml').replace(/\n/g, '\r\n'));
      await c.append('INBOX', mime(old, 'old note', []));
      await c.append(
        'INBOX',
        mime(recent, 'broken', [{ type: 'application/gzip', name: 'x.xml.gz', data: gzipSync('<feedback/>') }]),
      );
      await c.logout();

      const mailbox: MailboxConfig = {
        n: 1,
        key: `${user}@test/INBOX`,
        name: 'Reports',
        address: null,
        imap: imapCfg(user),
        folder: 'INBOX',
        maxMessageSize: 1_000_000,
        deleteAfterMonths: 6,
        deleteDryRun: false,
      };
      const syncer = new ReportSyncer(store, [mailbox], () => {});
      const r = await syncer.run();
      assert.deepEqual(
        [r.messagesSeen, r.dmarcReports, r.tlsReports, r.failureReports, r.messagesWithoutReport, r.errors, r.deleted],
        [5, 1, 1, 1, 1, 1, 1],
      );
      const [status] = await syncer.status();
      assert.equal(status!.lastError, null);
      assert.equal(status!.issues.length, 2);
      // A second run sees nothing new and deletes nothing more.
      const again = await syncer.run();
      assert.deepEqual([again.messagesSeen, again.deleted], [0, 0]);
      const v = client(user);
      await v.connect();
      const box = (await v.status('INBOX', { messages: true })) as { messages: number };
      await v.logout();
      assert.equal(box.messages, 4, 'the old imported report is gone, the old note is kept');
      assert.equal((await store.loadDmarcReports({})).length, 1, 'the report stays stored');
    });

    test('delivery probes are found in the Inbox and Junk, recorded and removed', async () => {
      const user = `probe-${randomBytes(4).toString('hex')}`;
      const c = client(user);
      await c.connect();
      await c.mailboxCreate('Junk');
      const recipient: RecipientConfig = {
        n: 1,
        name: 'Test',
        address: `${user}@test.example`,
        imap: imapCfg(user),
        folders: ['INBOX', 'Junk'],
        keepMessages: false,
      };
      const delivery = new Delivery(
        store,
        [],
        [recipient],
        { intervalMinutes: 60, timeoutMinutes: 30, pollSeconds: 60, retentionDays: 90 },
        () => {},
      );
      const sentAt = new Date(Date.now() - 60_000).toISOString();
      const tokens = [
        randomBytes(12).toString('hex'),
        randomBytes(12).toString('hex'),
        randomBytes(12).toString('hex'),
      ];
      const ids: number[] = [];
      for (const [i, token] of tokens.entries()) {
        const id = await store.createProbe({
          token,
          sender: 'example.com',
          recipient: 'Test',
          sentAt: i === 2 ? new Date(Date.now() - 3_600_000).toISOString() : sentAt,
        });
        await store.updateProbe(id, { status: 'sent' });
        ids.push(id);
      }
      const probe = (token: string) =>
        [
          'Authentication-Results: mx.test.example; dkim=pass header.i=@example.com header.s=s1; spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com',
          'Received-SPF: pass client-ip=192.0.2.10;',
          'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s1; h=from; bh=x; b=y',
          'From: MailWatch <monitor@example.com>',
          `To: ${user}@test.example`,
          `Subject: ${PROBE_SUBJECT} ${token}`,
          `Date: ${new Date().toUTCString()}`,
          '',
          'Probe',
          '',
        ].join('\r\n');
      await c.append('INBOX', probe(tokens[0]!));
      await c.append('Junk', probe(tokens[1]!));
      await c.append('INBOX', mime(new Date().toUTCString(), 'unrelated', []));
      await c.logout();

      await delivery.poll(new Date());
      const [inbox, junk, lost] = await Promise.all(ids.map((id) => store.probe(id)));
      assert.deepEqual(
        [inbox!.status, inbox!.folder, inbox!.auth?.dmarc, inbox!.clientIp, inbox!.dkimSelectors],
        ['inbox', 'INBOX', 'pass', '192.0.2.10', ['s1']],
      );
      assert.ok(inbox!.latencySeconds !== null && inbox!.latencySeconds >= 0);
      assert.equal(junk!.status, 'spam');
      assert.equal(lost!.status, 'lost', 'sent an hour ago, past the 30-minute timeout');
      const [rs] = await delivery.recipientStatus();
      assert.equal(rs!.lastError, null);

      const v = client(user);
      await v.connect();
      const [i, j] = (await Promise.all([
        v.status('INBOX', { messages: true }),
        v.status('Junk', { messages: true }),
      ])) as {
        messages: number;
      }[];
      await v.logout();
      assert.deepEqual([i!.messages, j!.messages], [1, 0], 'found probes are removed; other mail is untouched');
    });

    test('a recipient that cannot log in is reported and its probes are not marked lost', async () => {
      const recipient: RecipientConfig = {
        n: 1,
        name: 'Broken',
        address: 'x@test.example',
        imap: {
          ...imapCfg(`broken-${randomBytes(4).toString('hex')}`),
          auth: { kind: 'password', user: 'nobody', pass: 'wrong' },
        },
        folders: null,
        keepMessages: false,
      };
      const delivery = new Delivery(
        store,
        [],
        [recipient],
        { intervalMinutes: 60, timeoutMinutes: 1, pollSeconds: 60, retentionDays: 90 },
        () => {},
      );
      const id = await store.createProbe({
        token: randomBytes(12).toString('hex'),
        sender: 'example.com',
        recipient: 'Broken',
        sentAt: new Date(Date.now() - 3_600_000).toISOString(),
      });
      await store.updateProbe(id, { status: 'sent' });
      await delivery.poll(new Date());
      assert.match((await delivery.recipientErrors()).get('Broken') ?? '', /login as nobody failed/);
      assert.equal((await store.probe(id))!.status, 'sent');
    });
  },
);
