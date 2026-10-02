// A minimal SMTP client for probing an MX: banner, EHLO, STARTTLS (RFC 3207), the certificate
// chain and the negotiated TLS version. It never sends MAIL FROM; the session ends with QUIT.
import { connect as netConnect, type Socket } from 'node:net';
import { checkServerIdentity, connect as tlsConnect, type DetailedPeerCertificate, type TLSSocket } from 'node:tls';
import type { CertInfo, SmtpProbe } from '../../shared/types.ts';
import { certInfo } from './util.ts';

/** Reads SMTP replies (possibly multi-line, "250-…" then "250 …") from a socket. */
class ReplyReader {
  private buf = '';
  private lines: string[] = [];
  /** Complete replies not yet asked for (a server may answer before we wait). */
  private readonly ready: { code: number; lines: string[] }[] = [];
  private waiting: { resolve: (r: { code: number; lines: string[] }) => void; reject: (e: Error) => void } | null =
    null;
  private error: Error | null = null;

  attach(sock: Socket | TLSSocket): void {
    sock.on('data', (d: Buffer) => this.push(d.toString('latin1')));
  }

  /** Fails the pending and every later next() (the first error wins). */
  fail(e: Error): void {
    this.error ??= e;
    const w = this.waiting;
    this.waiting = null;
    w?.reject(this.error);
  }

  private push(s: string): void {
    this.buf += s;
    let i: number;
    while ((i = this.buf.indexOf('\n')) >= 0) {
      const line = this.buf.slice(0, i).replace(/\r$/, '');
      this.buf = this.buf.slice(i + 1);
      this.lines.push(line);
      if (/^\d{3}(?: |$)/.test(line)) {
        this.ready.push({ code: Number(line.slice(0, 3)), lines: this.lines.map((l) => l.slice(4)) });
        this.lines = [];
      }
    }
    this.deliver();
  }

  private deliver(): void {
    if (!this.waiting || !this.ready.length) return;
    const w = this.waiting;
    this.waiting = null;
    w.resolve(this.ready.shift()!);
  }

  next(): Promise<{ code: number; lines: string[] }> {
    return new Promise((resolve, reject) => {
      if (this.ready.length) return resolve(this.ready.shift()!);
      if (this.error) return reject(this.error);
      this.waiting = { resolve, reject };
    });
  }
}

function chainOf(peer: DetailedPeerCertificate, now: Date): CertInfo[] {
  const out: CertInfo[] = [];
  const seen = new Set<string>();
  let c: DetailedPeerCertificate | undefined = peer;
  while (c?.raw && !seen.has(c.fingerprint256)) {
    seen.add(c.fingerprint256);
    out.push(certInfo(c.raw, now));
    c = c.issuerCertificate;
  }
  return out;
}

export interface ProbeOptions {
  heloName: string;
  timeoutMs: number;
  port?: number;
  now?: Date;
}

export async function probeSmtp(host: string, ip: string, opts: ProbeOptions): Promise<SmtpProbe> {
  const started = performance.now();
  const port = opts.port ?? 25;
  const out: SmtpProbe = {
    host,
    ip,
    port,
    connected: false,
    banner: null,
    extensions: [],
    starttls: false,
    tls: null,
    error: null,
    durationMs: 0,
  };
  let sock: Socket | TLSSocket | null = null;
  const reader = new ReplyReader();
  const deadline = setTimeout(() => {
    const e = new Error(`no complete answer within ${Math.round(opts.timeoutMs / 1000)} s`);
    reader.fail(e);
    sock?.destroy(e);
  }, opts.timeoutMs);

  const send = (line: string) => sock!.write(`${line}\r\n`);
  try {
    // Assigned before connecting, so that the deadline also cuts a connection attempt short.
    const conn = netConnect({ host: ip, port });
    sock = conn;
    await new Promise<void>((resolve, reject) => {
      conn.once('connect', () => resolve());
      conn.once('error', reject);
      conn.once('close', () => reject(new Error(`no connection within ${Math.round(opts.timeoutMs / 1000)} s`)));
    });
    out.connected = true;
    sock.on('error', (e) => reader.fail(e));
    sock.on('close', () => reader.fail(new Error('connection closed by the server')));
    reader.attach(sock);

    const banner = await reader.next();
    out.banner = `${banner.code} ${banner.lines.join(' ')}`.trim();
    if (banner.code !== 220) throw new Error(`the server refused the session: ${out.banner}`);

    send(`EHLO ${opts.heloName}`);
    const ehlo = await reader.next();
    if (ehlo.code !== 250) throw new Error(`EHLO was refused: ${ehlo.code} ${ehlo.lines.join(' ')}`);
    out.extensions = ehlo.lines.slice(1).map((l) => l.trim().toUpperCase());
    out.starttls = out.extensions.some((e) => e === 'STARTTLS' || e.startsWith('STARTTLS '));
    if (!out.starttls) {
      send('QUIT');
      return out;
    }

    send('STARTTLS');
    const go = await reader.next();
    if (go.code !== 220) throw new Error(`STARTTLS was refused: ${go.code} ${go.lines.join(' ')}`);

    const plain = sock;
    plain.removeAllListeners('data');
    plain.removeAllListeners('close');
    const tls = await new Promise<TLSSocket>((resolve, reject) => {
      const t = tlsConnect({
        socket: plain,
        servername: host,
        rejectUnauthorized: false,
        // Accept old protocols so that we can report them (RFC 8996) instead of failing.
        minVersion: 'TLSv1',
        ciphers: 'DEFAULT:@SECLEVEL=0',
      });
      t.once('secureConnect', () => resolve(t));
      t.once('error', reject);
    });
    sock = tls;
    const peer = tls.getPeerCertificate(true);
    const now = opts.now ?? new Date();
    out.tls = {
      protocol: tls.getProtocol(),
      cipher: tls.getCipher()?.name ?? null,
      authorized: tls.authorized,
      authorizationError: tls.authorized ? null : String(tls.authorizationError ?? 'not trusted'),
      hostnameMatch: peer?.raw ? checkServerIdentity(host, peer) === undefined : false,
      chain: peer?.raw ? chainOf(peer, now) : [],
    };

    const r2 = new ReplyReader();
    r2.attach(tls);
    tls.on('error', (e) => r2.fail(e));
    tls.write(`EHLO ${opts.heloName}\r\n`);
    const ehlo2 = await r2.next().catch(() => null);
    if (ehlo2?.code === 250) out.extensions = ehlo2.lines.slice(1).map((l) => l.trim().toUpperCase());
    tls.write('QUIT\r\n');
    return out;
  } catch (e) {
    out.error = (e as Error).message;
    return out;
  } finally {
    clearTimeout(deadline);
    out.durationMs = Math.round(performance.now() - started);
    // Give QUIT a moment to be sent, then close.
    const s = sock;
    if (s) setTimeout(() => s.destroy(), 200).unref();
  }
}

/**
 * Probes of one check run, by MX host: domains that share an MX (common with a mail provider)
 * probe it once, and all of them get the same result. Holds promises, so domains checked in
 * parallel share a probe that is still running.
 */
export class ProbeCache {
  private readonly byHost = new Map<string, Promise<SmtpProbe[]>>();

  forHost(host: string, probe: () => Promise<SmtpProbe[]>): Promise<SmtpProbe[]> {
    const key = host.toLowerCase();
    let p = this.byHost.get(key);
    if (!p) {
      p = probe();
      this.byHost.set(key, p);
    }
    return p;
  }
}
