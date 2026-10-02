// The specifications MailWatch checks against. Shared by the server (finding references) and
// the UI (the "Relevant RFCs" panel of every tab, which marks the ones with problems).
import type { CheckKind, RfcRef } from './types.ts';

export interface SpecDoc {
  /** Display name, e.g. "RFC 7208". */
  label: string;
  title: string;
  url: string;
  /** Short note on the document's status, when it is not a Proposed/Internet Standard. */
  status?: string;
}

const rfc = (n: number, title: string, status?: string): SpecDoc => ({
  label: `RFC ${n}`,
  title,
  url: `https://www.rfc-editor.org/rfc/rfc${n}`,
  ...(status ? { status } : {}),
});

const draft = (name: string, label: string, title: string): SpecDoc => ({
  label,
  title,
  url: `https://datatracker.ietf.org/doc/${name}/`,
  status: 'Internet-Draft',
});

export const SPECS: Record<string, SpecDoc> = {
  rfc1034: rfc(1034, 'Domain Names: Concepts and Facilities', 'Internet Standard'),
  rfc1912: rfc(1912, 'Common DNS Operational and Configuration Errors', 'Informational'),
  rfc2181: rfc(2181, 'Clarifications to the DNS Specification'),
  rfc2182: rfc(2182, 'Selection and Operation of Secondary DNS Servers', 'Best Current Practice'),
  rfc3207: rfc(3207, 'SMTP Service Extension for Secure SMTP over TLS (STARTTLS)'),
  rfc4033: rfc(4033, 'DNS Security Introduction and Requirements (DNSSEC)'),
  rfc4034: rfc(4034, 'Resource Records for the DNS Security Extensions'),
  rfc4035: rfc(4035, 'Protocol Modifications for the DNS Security Extensions'),
  rfc4954: rfc(4954, 'SMTP Service Extension for Authentication'),
  rfc5321: rfc(5321, 'Simple Mail Transfer Protocol'),
  rfc5322: rfc(5322, 'Internet Message Format'),
  rfc5782: rfc(5782, 'DNS Blacklists and Whitelists', 'Informational'),
  rfc5965: rfc(5965, 'An Extensible Format for Email Feedback Reports (ARF)'),
  rfc6186: rfc(6186, 'Use of SRV Records for Locating Email Submission/Access Services'),
  rfc6376: rfc(6376, 'DomainKeys Identified Mail (DKIM) Signatures', 'Internet Standard'),
  rfc6531: rfc(6531, 'SMTP Extension for Internationalized Email (SMTPUTF8)'),
  rfc6591: rfc(6591, 'Authentication Failure Reporting Using the Abuse Reporting Format'),
  rfc6651: rfc(6651, 'Extensions to DKIM for Failure Reporting'),
  rfc6652: rfc(6652, 'SPF Authentication Failure Reporting Using the Abuse Reporting Format'),
  rfc6698: rfc(6698, 'The DNS-Based Authentication of Named Entities (DANE) TLSA Protocol'),
  rfc7208: rfc(7208, 'Sender Policy Framework (SPF)'),
  rfc7489: rfc(7489, 'Domain-based Message Authentication, Reporting, and Conformance (DMARC)', 'Informational'),
  rfc7505: rfc(7505, 'A "Null MX" No Service Resource Record'),
  rfc7671: rfc(7671, 'The DANE Protocol: Updates and Operational Guidance'),
  rfc7672: rfc(7672, 'SMTP Security via Opportunistic DANE TLS'),
  rfc8056: rfc(8056, 'EPP and RDAP Status Mapping'),
  rfc8058: rfc(8058, 'Signaling One-Click Functionality for List Email Headers'),
  rfc8301: rfc(8301, 'Cryptographic Algorithm and Key Usage Update to DKIM'),
  rfc8314: rfc(8314, 'Cleartext Considered Obsolete: Use of TLS for Email Submission and Access'),
  rfc8460: rfc(8460, 'SMTP TLS Reporting'),
  rfc8461: rfc(8461, 'SMTP MTA Strict Transport Security (MTA-STS)'),
  rfc8463: rfc(8463, 'A New Cryptographic Signature Method for DKIM (Ed25519)'),
  rfc8601: rfc(8601, 'Message Header Field for Indicating Message Authentication Status'),
  rfc8617: rfc(8617, 'The Authenticated Received Chain (ARC) Protocol', 'Experimental'),
  rfc8624: rfc(8624, 'Algorithm Implementation Requirements and Usage Guidance for DNSSEC'),
  rfc8689: rfc(8689, 'SMTP Require TLS Option (REQUIRETLS)'),
  rfc8996: rfc(8996, 'Deprecating TLS 1.0 and TLS 1.1', 'Best Current Practice'),
  rfc9083: rfc(9083, 'JSON Responses for the Registration Data Access Protocol (RDAP)', 'Internet Standard'),
  rfc9224: rfc(9224, 'Finding the Authoritative RDAP Service', 'Internet Standard'),
  rfc9525: rfc(9525, 'Service Identity in TLS'),
  dmarcbis: draft('draft-ietf-dmarc-dmarcbis', 'DMARCbis', 'DMARC (revision of RFC 7489)'),
  'dmarc-aggregate': draft(
    'draft-ietf-dmarc-aggregate-reporting',
    'DMARCbis aggregate',
    'DMARC Aggregate Reporting (revision of RFC 7489 §7.2)',
  ),
  'dmarc-failure': draft(
    'draft-ietf-dmarc-failure-reporting',
    'DMARCbis failure',
    'DMARC Failure Reporting (revision of RFC 7489 §7.3)',
  ),
  'gmail-senders': {
    label: 'Gmail sender guidelines',
    title: 'Email sender guidelines (Google)',
    url: 'https://support.google.com/a/answer/81126',
    status: 'Provider policy',
  },
  'yahoo-senders': {
    label: 'Yahoo sender requirements',
    title: 'Sender Best Practices (Yahoo)',
    url: 'https://senders.yahooinc.com/best-practices/',
    status: 'Provider policy',
  },
  'm3aawg-dkim': {
    label: 'M3AAWG DKIM keys',
    title: 'M3AAWG DKIM Key Rotation Best Common Practices',
    url: 'https://www.m3aawg.org/DKIMKeyRotation',
    status: 'Industry best practice',
  },
  bimi: draft(
    'draft-brand-indicators-for-message-identification',
    'BIMI',
    'Brand Indicators for Message Identification',
  ),
};

/** The documents shown on each tab, most important first. */
export const TAB_SPECS: Record<CheckKind | 'dmarc-reports' | 'delivery', string[]> = {
  domain: ['rfc9083', 'rfc8056', 'rfc9224', 'rfc1034', 'rfc2182', 'rfc1912'],
  mx: ['rfc5321', 'rfc7505', 'rfc2181', 'rfc3207', 'rfc8996', 'rfc9525', 'rfc1912', 'rfc8314', 'rfc8689', 'rfc6531'],
  spf: ['rfc7208'],
  dkim: ['rfc6376', 'rfc8301', 'rfc8463', 'm3aawg-dkim'],
  dmarc: ['rfc7489', 'dmarcbis'],
  'dmarc-reports': ['rfc7489', 'dmarc-aggregate', 'rfc6591', 'rfc5965', 'rfc6651', 'rfc6652', 'dmarc-failure'],
  'mta-sts': ['rfc8461', 'rfc9525'],
  'tls-rpt': ['rfc8460', 'rfc8461', 'rfc7672'],
  dane: ['rfc7672', 'rfc6698', 'rfc7671', 'rfc4033', 'rfc4034', 'rfc4035', 'rfc8624'],
  bimi: ['bimi', 'rfc7489'],
  dnsbl: ['rfc5782'],
  senders: [
    'gmail-senders',
    'yahoo-senders',
    'rfc7208',
    'rfc1912',
    'rfc8314',
    'rfc4954',
    'rfc6186',
    'rfc8996',
    'rfc8058',
  ],
  delivery: ['rfc8601', 'rfc5321', 'rfc7208', 'rfc6376', 'rfc7489', 'rfc8617'],
};

/** "RFC 7208 §4.6.4" */
export function refLabel(r: RfcRef): string {
  const d = SPECS[r.doc];
  return `${d?.label ?? r.doc}${r.section ? ` §${r.section}` : ''}`;
}

/** Link to the document, at the section when one is given. */
export function refUrl(r: RfcRef): string {
  const d = SPECS[r.doc];
  if (!d) return '#';
  return r.section ? `${d.url.replace(/\/$/, '')}#section-${r.section}` : d.url;
}
