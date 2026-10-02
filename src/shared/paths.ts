// Names of the checks and where things are shown in the UI. Shared by the server (links in
// Telegram messages) and the UI.
import type { Alert, CheckKind } from './types.ts';

export const CHECK_LABEL: Record<CheckKind, string> = {
  mx: 'MX & SMTP',
  spf: 'SPF',
  dkim: 'DKIM',
  dmarc: 'DMARC',
  'mta-sts': 'MTA-STS',
  'tls-rpt': 'TLS-RPT',
  dane: 'DANE',
  bimi: 'BIMI',
  dnsbl: 'Blocklists',
};

/** The check an alert belongs to: check|<check>|<code>|<domain>|<subject>. */
export const checkOfKey = (key: string): CheckKind | null =>
  key.startsWith('check|') ? (key.split('|')[1] as CheckKind) : null;

/** Where an alert is shown in the UI. */
export function alertPath(a: Pick<Alert, 'kind' | 'key' | 'code'>): string {
  if (a.kind === 'check') return `/${checkOfKey(a.key) ?? ''}`;
  if (a.kind === 'delivery') return '/delivery';
  if (a.kind === 'report') return a.code.startsWith('tls-reports.') ? '/tls-rpt' : '/dmarc-reports';
  return '/status';
}

/** The area an alert belongs to, e.g. "SPF" or "Delivery". */
export function areaOf(a: Pick<Alert, 'kind' | 'key'>): string {
  if (a.kind === 'check') return CHECK_LABEL[checkOfKey(a.key) ?? 'mx'] ?? 'Check';
  if (a.kind === 'delivery') return 'Delivery';
  if (a.kind === 'report') return 'Reports';
  return 'Mailbox';
}
