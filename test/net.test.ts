// Network edge cases of the DNS client and the SMTP probe, against local fake servers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSocket } from 'node:dgram';
import { createServer, type AddressInfo } from 'node:net';
import * as packet from 'dns-packet';
import { probeSmtp } from '../src/server/checks/smtp.ts';
import { DnsClient } from '../src/server/dns.ts';

test('a truncated UDP answer followed by a TCP server that hangs up does not hang the lookup', async () => {
  const tcp = createServer((s) => s.destroy());
  await new Promise<void>((r) => tcp.listen(0, '127.0.0.1', r));
  const port = (tcp.address() as AddressInfo).port;
  const udp = createSocket('udp4');
  udp.on('message', (msg, rinfo) => {
    const q = packet.decode(msg);
    udp.send(
      packet.encode({ type: 'response', id: q.id, flags: packet.TRUNCATED_RESPONSE, questions: q.questions }),
      rinfo.port,
      rinfo.address,
    );
  });
  await new Promise<void>((r) => udp.bind(port, '127.0.0.1', r));
  try {
    const started = Date.now();
    const r = await new DnsClient([`127.0.0.1:${port}`], 500).txt('example.com');
    assert.equal(r.rcode, 'TIMEOUT');
    assert.match(r.error!, /closed before a complete answer/);
    assert.ok(Date.now() - started < 3000);
  } finally {
    udp.close();
    tcp.close();
  }
});

test('the SMTP probe gives up on a server that never sends its banner', async () => {
  const silent = createServer(() => {});
  await new Promise<void>((r) => silent.listen(0, '127.0.0.1', r));
  try {
    const started = Date.now();
    const p = await probeSmtp('mx.test', '127.0.0.1', {
      heloName: 'test',
      timeoutMs: 400,
      port: (silent.address() as AddressInfo).port,
    });
    assert.equal(p.connected, true);
    assert.match(p.error!, /no complete answer within/);
    assert.ok(Date.now() - started < 2000);
  } finally {
    silent.close();
  }
});

test('the SMTP probe timeout also covers connecting', async () => {
  // A TEST-NET address that nothing answers: either unreachable at once, or cut off by the deadline.
  const started = Date.now();
  const p = await probeSmtp('mx.test', '192.0.2.1', { heloName: 'test', timeoutMs: 500, port: 25 });
  assert.equal(p.connected, false);
  assert.ok(p.error);
  assert.ok(Date.now() - started < 2500, `took ${Date.now() - started} ms`);
});

test('pipelined replies that arrive before they are awaited are not lost', async () => {
  // The server sends the banner and the EHLO answer in one go, before EHLO was even sent.
  const eager = createServer((s) => {
    s.write('220 hi\r\n250-mx.test\r\n250 8BITMIME\r\n');
    s.on('data', (d) => d.toString().startsWith('QUIT') && s.end('221 bye\r\n'));
  });
  await new Promise<void>((r) => eager.listen(0, '127.0.0.1', r));
  try {
    const p = await probeSmtp('mx.test', '127.0.0.1', {
      heloName: 'test',
      timeoutMs: 2000,
      port: (eager.address() as AddressInfo).port,
    });
    assert.equal(p.error, null);
    assert.equal(p.banner, '220 hi');
    assert.deepEqual(p.extensions, ['8BITMIME']);
    assert.equal(p.starttls, false);
  } finally {
    eager.close();
  }
});

test('HTTPS fetches of URLs from DNS refuse internal addresses', async () => {
  const { httpsGet } = await import('../src/server/checks/util.ts');
  await assert.rejects(httpsGet('https://localhost:1/', 2000), /non-public address \((127\.0\.0\.1|::1)\)/);
  await assert.rejects(httpsGet('https://127.0.0.1:1/', 2000), /non-public address/);
  await assert.rejects(httpsGet('http://example.com/', 2000), /not an https/);
});
