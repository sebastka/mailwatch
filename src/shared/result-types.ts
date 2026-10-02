// Shared by server (insights) and UI (tooltips).
/** Human readable explanations of the RFC 8460 result types. */
export const RESULT_TYPES: Record<string, string> = {
  'starttls-not-supported': 'The receiving MX did not offer STARTTLS.',
  'certificate-host-mismatch': 'The certificate presented did not match the MX hostname.',
  'certificate-expired': 'The certificate presented had expired.',
  'certificate-not-trusted': 'The certificate chain did not lead to a trusted root.',
  'validation-failure': 'General certificate or policy validation failure.',
  'tlsa-invalid': 'DANE: the TLSA record was invalid or did not match the certificate.',
  'dnssec-invalid': 'DANE: DNSSEC validation of the TLSA records failed.',
  'dane-required': 'DANE: the sender requires DANE but no valid TLSA records were found.',
  'sts-policy-fetch-error': 'MTA-STS: the policy could not be fetched over HTTPS.',
  'sts-policy-invalid': 'MTA-STS: the fetched policy failed to validate.',
  'sts-webpki-invalid': 'MTA-STS: the policy host certificate failed WebPKI validation.',
};
