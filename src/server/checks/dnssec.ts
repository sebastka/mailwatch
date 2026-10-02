// DNSSEC helpers: key tags and DS digests (RFC 4034), and how much validity a signature has left.
import { createHash } from 'node:crypto';

export interface DnskeyRecord {
  flags: number;
  algorithm: number;
  key: Buffer;
}

export interface DsRecord {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: Buffer;
}

/** DNSKEY RDATA in wire format: flags, protocol (always 3), algorithm, public key. */
function dnskeyRdata(k: DnskeyRecord): Buffer {
  const head = Buffer.alloc(4);
  head.writeUInt16BE(k.flags, 0);
  head.writeUInt8(3, 2);
  head.writeUInt8(k.algorithm, 3);
  return Buffer.concat([head, k.key]);
}

/** The key tag of a DNSKEY (RFC 4034 Appendix B). */
export function keyTag(k: DnskeyRecord): number {
  const rdata = dnskeyRdata(k);
  let ac = 0;
  for (let i = 0; i < rdata.length; i++) ac += i & 1 ? rdata[i]! : rdata[i]! << 8;
  ac += (ac >> 16) & 0xffff;
  return ac & 0xffff;
}

/** A domain name in canonical wire format (lowercase labels, RFC 4034 §6.2). */
function wireName(name: string): Buffer {
  const labels = name.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  return Buffer.concat([
    ...labels.map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'ascii')])),
    Buffer.from([0]),
  ]);
}

const DIGESTS: Record<number, string> = { 1: 'sha1', 2: 'sha256', 4: 'sha384' };

/**
 * Does a DS record match a DNSKEY of the zone (RFC 4034 §5.1.4)? null when the digest type is
 * not one we can compute.
 */
export function dsMatches(owner: string, ds: DsRecord, key: DnskeyRecord): boolean | null {
  const alg = DIGESTS[ds.digestType];
  if (!alg) return null;
  if (ds.algorithm !== key.algorithm || ds.keyTag !== keyTag(key)) return false;
  const digest = createHash(alg).update(wireName(owner)).update(dnskeyRdata(key)).digest();
  return digest.equals(Buffer.from(ds.digest));
}

/**
 * How urgent a signature's expiry is. Online signers (Cloudflare and others) use validity
 * periods of a day or two and re-sign all the time, so a short remaining time alone means
 * nothing. A signer that stopped re-signing shows as little time left in a large part of the
 * validity: warning when less than a quarter and less than `warnDays` remain, error when it
 * expires within 6 hours or has expired.
 */
export function signatureUrgency(
  inception: number,
  expiration: number,
  nowSeconds: number,
  warnDays: number,
): 'expired' | 'error' | 'warning' | null {
  const left = expiration - nowSeconds;
  if (left <= 0) return 'expired';
  if (left < 6 * 3600) return 'error';
  const total = Math.max(1, expiration - inception);
  if (left < total / 4 && left < warnDays * 86_400) return 'warning';
  return null;
}
