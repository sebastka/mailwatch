// DNSSEC algorithm numbers (IANA), shared by the DANE check and its details in the UI.

/** DNSSEC algorithms: number → name, and those RFC 8624 §3.1 says must not or should not be used. */
export const ALGORITHMS: Record<number, string> = {
  1: 'RSAMD5',
  3: 'DSA',
  5: 'RSASHA1',
  6: 'DSA-NSEC3-SHA1',
  7: 'RSASHA1-NSEC3-SHA1',
  8: 'RSASHA256',
  10: 'RSASHA512',
  12: 'ECC-GOST',
  13: 'ECDSAP256SHA256',
  14: 'ECDSAP384SHA384',
  15: 'ED25519',
  16: 'ED448',
};
export const DEPRECATED_ALGORITHMS = new Set([1, 3, 5, 6, 7, 12]);
