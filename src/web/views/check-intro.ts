import type { CheckKind } from '../../shared/types.ts';

export const CHECK_INTRO: Record<CheckKind, string> = {
  mx: 'The MX records, their addresses and reverse DNS, and the SMTP service on port 25 of every MX: STARTTLS, the TLS version and the certificate.',
  spf: 'The SPF record that lists the servers allowed to send for the domain, with its include tree and the DNS lookup limits receivers enforce.',
  dkim: 'DKIM public keys under the configured selectors, the selectors seen in DMARC reports and delivery tests, and common selectors. Selectors cannot be listed from DNS.',
  dmarc:
    'The DMARC policy: what receivers do with mail that fails SPF and DKIM alignment, and where they send reports.',
  'mta-sts':
    'MTA-STS makes senders require TLS with a valid certificate when delivering to your MX hosts. Checked: the _mta-sts record, the HTTPS policy and its coverage of the MX hosts.',
  'tls-rpt':
    'The TLS-RPT record tells senders where to send daily reports about TLS failures when delivering to you. The reports received are analysed below.',
  dane: 'DANE pins the MX certificates in DNSSEC-signed TLSA records. Checked: DNSSEC on the domain and MX records, the TLSA records, and whether they match the certificates the MX hosts present.',
  bimi: 'BIMI shows a brand logo next to authenticated mail in supporting mailboxes. It requires DMARC enforcement.',
  dnsbl: 'The MX hosts, the known sending IPs and the domain itself, looked up in DNS blocklists.',
};
