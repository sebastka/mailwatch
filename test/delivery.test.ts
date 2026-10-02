// Sending delivery probes, against a minimal fake submission server (implicit TLS, like port 465).
// The database part needs MariaDB (TEST_DB_HOST); the message format is tested without.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer, type Server, type TLSSocket } from 'node:tls';
import type { DomainConfig, RecipientConfig } from '../src/server/config.ts';
import type { Store } from '../src/server/db.ts';
import { Delivery, probeMessage, PROBE_SUBJECT } from '../src/server/delivery.ts';
import { freshDatabase, testDb } from './helpers.ts';

const domain = (port: number, pass = 'right'): DomainConfig => ({
  n: 1,
  name: 'example.com',
  dkimSelectors: [],
  senderIps: [],
  smtp: { host: '127.0.0.1', port, secure: true, user: 'tester@example.com', pass, rejectUnauthorized: false },
  from: 'tester@example.com',
  sendIntervalMinutes: 60,
});
const recipient = (name: string, address: string): RecipientConfig => ({
  n: 1,
  name,
  address,
  imap: {
    host: '127.0.0.1',
    port: 1,
    secure: true,
    rejectUnauthorized: false,
    auth: { kind: 'password', user: 'u', pass: 'p' },
  },
  folders: null,
  keepMessages: false,
});

test('probe messages carry the token in the subject, Message-ID and a header', () => {
  const m = probeMessage(
    domain(465),
    recipient('Gmail', 'me@gmail.com'),
    '0123456789abcdef01234567',
    new Date('2026-10-02T10:00:00Z'),
  );
  assert.equal(m.subject, `${PROBE_SUBJECT} 0123456789abcdef01234567`);
  assert.equal(m.messageId, '<mailwatch.0123456789abcdef01234567@example.com>');
  assert.equal(m.headers['X-MailWatch-Probe'], '0123456789abcdef01234567');
  assert.deepEqual(m.from, { name: 'MailWatch', address: 'tester@example.com' });
});

/** Accepts AUTH PLAIN with the password "right" and recipients not starting with "reject". */
function fakeSubmission(received: string[]): Server {
  const dir = new URL('fixtures/', import.meta.url);
  return createServer(
    { key: readFileSync(new URL('test-smtp.key', dir)), cert: readFileSync(new URL('test-smtp.crt', dir)) },
    (s: TLSSocket) => {
      let data = false;
      let body = '';
      let buf = '';
      s.write('220 fake ESMTP\r\n');
      s.on('data', (d) => {
        buf += d.toString();
        let i: number;
        while ((i = buf.indexOf('\r\n')) >= 0) {
          const line = buf.slice(0, i);
          buf = buf.slice(i + 2);
          if (data) {
            if (line === '.') {
              data = false;
              received.push(body);
              body = '';
              s.write('250 2.0.0 Ok: queued as FAKE1\r\n');
            } else body += `${line}\n`;
            continue;
          }
          const cmd = line.toUpperCase();
          if (cmd.startsWith('EHLO')) s.write('250-fake\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n');
          else if (cmd.startsWith('AUTH PLAIN')) {
            const creds = Buffer.from(line.split(' ')[2] ?? '', 'base64')
              .toString()
              .split('\0');
            s.write(
              creds[2] === 'right' ? '235 2.7.0 Authentication successful\r\n' : '535 5.7.8 Authentication failed\r\n',
            );
          } else if (cmd.startsWith('MAIL FROM')) s.write('250 2.1.0 Ok\r\n');
          else if (cmd.startsWith('RCPT TO'))
            s.write(cmd.includes('REJECT') ? '550 5.1.1 No such user\r\n' : '250 2.1.5 Ok\r\n');
          else if (cmd === 'DATA') {
            data = true;
            s.write('354 End data with <CR><LF>.<CR><LF>\r\n');
          } else if (cmd === 'QUIT') s.end('221 2.0.0 Bye\r\n');
          else s.write('250 Ok\r\n');
        }
      });
    },
  );
}

const env = process.env;
describe(
  'sending probes (fake submission server + MariaDB)',
  { skip: env.TEST_DB_HOST ? false : 'TEST_DB_HOST not set' },
  () => {
    let store: Store;
    let server: Server;
    let port = 0;
    const received: string[] = [];
    const cfg = { intervalMinutes: 60, timeoutMinutes: 30, pollSeconds: 60, retentionDays: 90 };
    before(async () => {
      store = await freshDatabase(testDb('_send'));
      server = fakeSubmission(received);
      await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
      port = (server.address() as { port: number }).port;
    });
    after(async () => {
      server?.close();
      await store?.close();
    });

    test('every sender sends to every recipient when due, and not again before its interval', async () => {
      const d = new Delivery(
        store,
        [domain(port)],
        [recipient('A', 'a@test.example'), recipient('B', 'reject@test.example')],
        cfg,
        () => {},
      );
      const now = new Date();
      await d.sendDue(now);
      const probes = await store.probes({ sinceDays: 1 });
      assert.deepEqual(probes.map((p) => [p.recipient, p.status]).sort(), [
        ['A', 'sent'],
        ['B', 'send-failed'],
      ]);
      const a = probes.find((p) => p.recipient === 'A')!;
      assert.match(a.smtpResponse!, /queued as FAKE1/);
      assert.match(probes.find((p) => p.recipient === 'B')!.error!, /550|reject/i);
      assert.equal(received.length, 1);
      assert.match(received[0]!, new RegExp(`Subject: ${PROBE_SUBJECT} ${a.token}`));
      assert.match(received[0]!, new RegExp(`X-MailWatch-Probe: ${a.token}`, 'i'));

      // Ten minutes later nothing is due; after the interval it is.
      await d.sendDue(new Date(now.getTime() + 10 * 60_000));
      assert.equal((await store.probes({ sinceDays: 1 })).length, 2);
      await d.sendDue(new Date(now.getTime() + 60 * 60_000));
      assert.equal((await store.probes({ sinceDays: 1 })).length, 4);
    });

    test('a rejected login is a send failure with the server answer', async () => {
      await store.pool.query('DELETE FROM probes');
      const d = new Delivery(store, [domain(port, 'wrong')], [recipient('A', 'a@test.example')], cfg, () => {});
      await d.sendDue(new Date());
      const [p] = await store.probes({ sinceDays: 1 });
      assert.equal(p!.status, 'send-failed');
      assert.match(p!.error!, /EAUTH|Authentication failed/);
    });
  },
);
