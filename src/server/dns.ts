// A small DNS stub resolver over UDP (TCP on truncation) that exposes what node:dns hides:
// the response code (NXDOMAIN vs. no data vs. SERVFAIL) and the DNSSEC AD flag. It asks a
// validating recursive resolver (DNS_RESOLVERS) with the DO and AD bits set (RFC 6840 §5.7).
import { createSocket } from 'node:dgram';
import { isIP, isIPv6, connect as tcpConnect } from 'node:net';
import { randomInt } from 'node:crypto';
import * as packet from 'dns-packet';

export type RecordType = 'A' | 'AAAA' | 'MX' | 'TXT' | 'CNAME' | 'PTR' | 'TLSA' | 'SOA' | 'DNSKEY' | 'NS' | 'CAA';

export interface DnsResult<T> {
  name: string;
  type: RecordType;
  /** NOERROR, NXDOMAIN, SERVFAIL, REFUSED, …; "TIMEOUT" when no server answered. */
  rcode: string;
  /** The answer was DNSSEC-validated by the resolver (AD flag). */
  secure: boolean;
  records: T[];
  /** CNAMEs followed from the queried name, in order. */
  cnames: string[];
  /** Why no server answered (rcode TIMEOUT). */
  error?: string;
}

export interface MxRecord {
  preference: number;
  exchange: string;
}

export interface TlsaRaw {
  usage: number;
  selector: number;
  matchingType: number;
  data: Buffer;
}

/** The lookup worked (records, or authoritatively none). */
export const answered = (r: DnsResult<unknown>) => r.rcode === 'NOERROR' || r.rcode === 'NXDOMAIN';
/** The name or type has no records ("void lookup" in SPF terms, RFC 7208 §4.6.4). */
export const empty = (r: DnsResult<unknown>) => answered(r) && r.records.length === 0;

export const normalizeName = (s: string) => s.trim().toLowerCase().replace(/\.$/, '');

function splitServer(s: string): { host: string; port: number } {
  const v6 = /^\[(.+)\](?::(\d+))?$/.exec(s);
  if (v6) return { host: v6[1]!, port: Number(v6[2] ?? 53) };
  if (isIP(s)) return { host: s, port: 53 };
  const m = /^(.+):(\d+)$/.exec(s);
  return m ? { host: m[1]!, port: Number(m[2]) } : { host: s, port: 53 };
}

function buildQuery(name: string, type: RecordType): { id: number; buf: Buffer } {
  const id = randomInt(0, 65536);
  const buf = packet.encode({
    type: 'query',
    id,
    flags: packet.RECURSION_DESIRED | packet.AUTHENTIC_DATA,
    questions: [{ type, name, class: 'IN' }],
    additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 1232, flags: packet.DNSSEC_OK } as packet.Answer],
  });
  return { id, buf };
}

function udpQuery(server: { host: string; port: number }, name: string, type: RecordType, timeoutMs: number) {
  return new Promise<packet.DecodedPacket>((resolve, reject) => {
    const { id, buf } = buildQuery(name, type);
    const sock = createSocket(isIPv6(server.host) ? 'udp6' : 'udp4');
    const timer = setTimeout(() => {
      sock.close();
      reject(new Error('timeout'));
    }, timeoutMs);
    sock.on('error', (e) => {
      clearTimeout(timer);
      sock.close();
      reject(e);
    });
    sock.on('message', (msg) => {
      let res: packet.DecodedPacket;
      try {
        res = packet.decode(msg);
      } catch {
        return; // garbage: keep waiting for the real answer
      }
      if (res.id !== id) return;
      clearTimeout(timer);
      sock.close();
      resolve(res);
    });
    sock.send(buf, server.port, server.host);
  });
}

function tcpQuery(server: { host: string; port: number }, name: string, type: RecordType, timeoutMs: number) {
  return new Promise<packet.DecodedPacket>((resolve, reject) => {
    const { id, buf } = buildQuery(name, type);
    const sock = tcpConnect(server.port, server.host);
    const chunks: Buffer[] = [];
    let settled = false;
    const finish = (err: Error | null, res?: packet.DecodedPacket) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      if (err) reject(err);
      else resolve(res!);
    };
    const timer = setTimeout(() => finish(new Error('timeout')), timeoutMs);
    sock.on('connect', () => {
      const len = Buffer.alloc(2);
      len.writeUInt16BE(buf.length);
      sock.write(Buffer.concat([len, buf]));
    });
    sock.on('data', (d: Buffer) => {
      chunks.push(d);
      const all = Buffer.concat(chunks);
      if (all.length < 2 || all.length < 2 + all.readUInt16BE(0)) return;
      try {
        const res = packet.decode(all.subarray(2, 2 + all.readUInt16BE(0)));
        finish(res.id === id ? null : new Error('mismatched response id'), res);
      } catch (e) {
        finish(e as Error);
      }
    });
    sock.on('error', (e) => finish(e));
    // A server that closes the connection before a complete answer must not leave us waiting.
    sock.on('close', () => finish(new Error('connection closed before a complete answer')));
  });
}

/**
 * One resolver per check run: answers are cached for the lifetime of the instance, so the
 * checks of one domain (and SPF include trees) never ask the same question twice.
 */
export class DnsClient {
  private readonly servers: { host: string; port: number }[];
  private readonly timeoutMs: number;
  private readonly cache = new Map<string, Promise<DnsResult<unknown>>>();
  /** Number of queries actually sent (for tests and logs). */
  queries = 0;

  constructor(servers: string[], timeoutMs = 4000) {
    if (!servers.length) throw new Error('no DNS resolvers configured');
    this.servers = servers.map(splitServer);
    this.timeoutMs = timeoutMs;
  }

  query<T = unknown>(rawName: string, type: RecordType): Promise<DnsResult<T>> {
    const name = normalizeName(rawName);
    const key = `${name}|${type}`;
    let p = this.cache.get(key);
    if (!p) {
      p = this.lookup(name, type);
      this.cache.set(key, p);
    }
    return p as Promise<DnsResult<T>>;
  }

  private async lookup(name: string, type: RecordType): Promise<DnsResult<unknown>> {
    let lastError = 'no answer';
    // Each server is tried once; a second round helps against a single lost UDP packet.
    for (const server of [...this.servers, ...this.servers]) {
      try {
        this.queries++;
        let res = await udpQuery(server, name, type, this.timeoutMs);
        if (res.flag_tc) res = await tcpQuery(server, name, type, this.timeoutMs);
        return this.toResult(name, type, res);
      } catch (e) {
        lastError = (e as Error).message;
      }
    }
    return { name, type, rcode: 'TIMEOUT', secure: false, records: [], cnames: [], error: lastError };
  }

  private toResult(name: string, type: RecordType, res: packet.DecodedPacket): DnsResult<unknown> {
    const rcode = (res as unknown as { rcode?: string }).rcode ?? 'NOERROR';
    // OPT pseudo-records carry no data; every other answer does.
    const answers = (res.answers ?? []) as (packet.Answer & { data: unknown })[];
    // Follow the CNAME chain from the queried name; records of the type may hang off any link.
    const cnames: string[] = [];
    const names = new Set([name]);
    let cur = name;
    for (let i = 0; i < 16; i++) {
      const c = answers.find((a) => a.type === 'CNAME' && normalizeName(a.name) === cur);
      if (!c || type === 'CNAME') break;
      cur = normalizeName(c.data as string);
      cnames.push(cur);
      names.add(cur);
    }
    const records = answers
      .filter((a) => a.type === type && names.has(normalizeName(a.name)))
      .map((a) => convert(type, a.data));
    return { name, type, rcode, secure: res.flag_ad, records, cnames };
  }

  // --- Typed helpers ---

  /** TXT records, each with its character-strings concatenated (RFC 7208 §3.3). */
  txt(name: string) {
    return this.query<string>(name, 'TXT');
  }
  mx(name: string) {
    return this.query<MxRecord>(name, 'MX');
  }
  a(name: string) {
    return this.query<string>(name, 'A');
  }
  aaaa(name: string) {
    return this.query<string>(name, 'AAAA');
  }
  ptr(ip: string) {
    return this.query<string>(reverseName(ip), 'PTR');
  }
  tlsa(name: string) {
    return this.query<TlsaRaw>(name, 'TLSA');
  }

  /** IPv4 and IPv6 addresses of a host; secure only when both answers validated. */
  async addresses(name: string): Promise<{ ips: string[]; secure: boolean; failed: boolean; cnames: string[] }> {
    const [a, aaaa] = await Promise.all([this.a(name), this.aaaa(name)]);
    return {
      ips: [...a.records, ...aaaa.records],
      secure: a.secure && aaaa.secure,
      failed: !answered(a) || !answered(aaaa),
      cnames: a.cnames,
    };
  }

  /**
   * The PTR name of an IP, and whether it resolves back to the IP (FCrDNS). With several PTR
   * records, the first one that resolves back wins.
   */
  async reverse(ip: string): Promise<{ ptr: string | null; fcrdns: boolean | null }> {
    const r = await this.ptr(ip);
    if (!answered(r)) return { ptr: null, fcrdns: null };
    if (!r.records.length) return { ptr: null, fcrdns: false };
    let unknown = false;
    for (const ptr of r.records.slice(0, 4)) {
      const fwd = await (isIPv6(ip) ? this.aaaa(ptr) : this.a(ptr));
      if (!answered(fwd)) unknown = true;
      else if (fwd.records.some((x) => sameIp(x, ip))) return { ptr, fcrdns: true };
    }
    return { ptr: r.records[0]!, fcrdns: unknown ? null : false };
  }
}

function convert(type: RecordType, data: unknown): unknown {
  switch (type) {
    case 'TXT': {
      const parts = Array.isArray(data) ? data : [data];
      return parts.map((p) => (Buffer.isBuffer(p) ? p.toString('utf8') : String(p))).join('');
    }
    case 'MX': {
      const d = data as { preference: number; exchange: string };
      return { preference: d.preference, exchange: normalizeName(d.exchange) };
    }
    case 'CNAME':
    case 'PTR':
    case 'NS':
      return normalizeName(String(data));
    case 'TLSA': {
      const d = data as { usage: number; selector: number; matchingType: number; certificate: Buffer };
      return { usage: d.usage, selector: d.selector, matchingType: d.matchingType, data: d.certificate };
    }
    default:
      return data;
  }
}

/** Full 8-group form of an IPv6 address, lowercase. */
export function expandIPv6(ip: string): string {
  let s = ip.toLowerCase();
  // An embedded IPv4 tail (::ffff:1.2.3.4) becomes two groups.
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (v4) {
    const o = v4[1]!.split('.').map(Number);
    s = s.slice(0, -v4[1]!.length) + `${((o[0]! << 8) | o[1]!).toString(16)}:${((o[2]! << 8) | o[3]!).toString(16)}`;
  }
  const [head, tail] = s.split('::') as [string, string | undefined];
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const fill = tail === undefined ? [] : Array(8 - h.length - t.length).fill('0');
  return [...h, ...fill, ...t].map((g) => g.padStart(4, '0')).join(':');
}

export const sameIp = (a: string, b: string) =>
  isIPv6(a) && isIPv6(b) ? expandIPv6(a) === expandIPv6(b) : a.toLowerCase() === b.toLowerCase();

/** The reverse-lookup name: 4.3.2.1.in-addr.arpa, or nibbles under ip6.arpa. */
export function reverseName(ip: string, zone?: string): string {
  if (isIPv6(ip)) {
    const nibbles = expandIPv6(ip).replace(/:/g, '').split('').reverse().join('.');
    return `${nibbles}.${zone ?? 'ip6.arpa'}`;
  }
  return `${ip.split('.').reverse().join('.')}.${zone ?? 'in-addr.arpa'}`;
}
