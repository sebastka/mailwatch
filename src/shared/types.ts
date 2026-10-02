// Types shared between the API server and the web UI.
// Keep this file free of runtime code so both sides can import it as types only.

/** Status of a check or finding. "ok" findings document what is right. */
export type Level = 'ok' | 'info' | 'warning' | 'error';
/** Alert severities: an "ok" finding never alerts. */
export type Severity = 'info' | 'warning' | 'error';

export type CheckKind = 'mx' | 'spf' | 'dkim' | 'dmarc' | 'mta-sts' | 'tls-rpt' | 'dane' | 'bimi' | 'dnsbl';

/** A document a finding is based on, e.g. { doc: 'rfc7208', section: '4.6.4' }. Keys of RFCS. */
export interface RfcRef {
  doc: string;
  section?: string;
}

export interface Finding {
  /** Stable identifier, e.g. "spf.too-many-lookups"; part of the alert identity. */
  code: string;
  level: Level;
  title: string;
  detail: string;
  /** What the finding is about within the domain (an MX host, a DKIM selector, an IP). */
  subject?: string;
  /** The specifications this finding is based on (for warnings and errors: the ones broken). */
  refs?: RfcRef[];
}

export interface CheckResult<T = unknown> {
  domain: string;
  check: CheckKind;
  /** The worst level among the findings. */
  level: Level;
  checkedAt: string;
  durationMs: number;
  findings: Finding[];
  data: T;
}

// --- Check data ------------------------------------------------------------------

export interface CertInfo {
  subject: string;
  issuer: string;
  sans: string[];
  validFrom: string;
  validTo: string;
  daysLeft: number;
  /** Hex digests used for DANE matching (RFC 6698 §2.1.3). */
  certSha256: string;
  certSha512: string;
  spkiSha256: string;
  spkiSha512: string;
  /** Hex of the DER certificate and of its SubjectPublicKeyInfo (matching type 0). */
  certDer: string;
  spkiDer: string;
  selfSigned: boolean;
}

export interface TlsInfo {
  protocol: string | null;
  cipher: string | null;
  /** WebPKI validation against Node's CA store. */
  authorized: boolean;
  authorizationError: string | null;
  hostnameMatch: boolean;
  /** Leaf first, then the rest of the chain as presented. */
  chain: CertInfo[];
}

export interface SmtpProbe {
  host: string;
  ip: string;
  port: number;
  connected: boolean;
  banner: string | null;
  extensions: string[];
  starttls: boolean;
  tls: TlsInfo | null;
  error: string | null;
  durationMs: number;
}

export interface AddressInfo {
  ip: string;
  ptr: string | null;
  /** The PTR name resolves back to this address (forward-confirmed reverse DNS). */
  fcrdns: boolean | null;
}

export interface MxHost {
  preference: number;
  exchange: string;
  /** Set when the MX target is an alias (RFC 2181 §10.3 forbids this). */
  cname: string | null;
  addresses: AddressInfo[];
}

export interface MxData {
  records: MxHost[];
  nullMx: boolean;
  /** No MX records: delivery falls back to the domain's own address records (RFC 5321 §5.1). */
  implicit: boolean;
  /** The MX answer was DNSSEC-validated (AD flag). */
  dnssec: boolean;
  smtp: SmtpProbe[];
  /** Whether port 25 probing is enabled (SMTP_PROBE). */
  probeEnabled: boolean;
}

export interface SpfTerm {
  raw: string;
  qualifier: '+' | '-' | '~' | '?' | null;
  kind: string;
  value: string | null;
  /** DNS lookups this term costs (RFC 7208 §4.6.4). */
  lookups: number;
  child?: SpfNode;
}

export interface SpfNode {
  domain: string;
  record: string | null;
  terms: SpfTerm[];
  error: string | null;
}

export interface SpfData {
  record: string | null;
  /** All TXT records starting with v=spf1 (more than one is a permerror). */
  records: string[];
  tree: SpfNode | null;
  lookups: number;
  voidLookups: number;
  ip4: string[];
  ip6: string[];
  allQualifier: '+' | '-' | '~' | '?' | null;
}

export type DkimSource = 'configured' | 'common' | 'reports' | 'delivery';

export interface DkimSelector {
  selector: string;
  sources: DkimSource[];
  name: string;
  found: boolean;
  cname: string | null;
  record: string | null;
  tags: Record<string, string>;
  keyType: string | null;
  keyBits: number | null;
  testing: boolean;
  revoked: boolean;
  error: string | null;
}

export interface DkimData {
  selectors: DkimSelector[];
}

export interface DmarcUri {
  uri: string;
  scheme: string;
  address: string | null;
  domain: string | null;
  /** External destination authorised by <domain>._report._dmarc.<dest> (RFC 7489 §7.1); null when internal. */
  authorized: boolean | null;
  /** The address is a mailbox MailWatch reads. */
  monitored: boolean;
  /** Why the destination is unusable (e.g. "mailto:" twice); null when it is valid. */
  problem?: string | null;
}

export interface DmarcData {
  /** Where the record was found (the domain itself, or a parent via the tree walk). */
  name: string | null;
  record: string | null;
  records: string[];
  inherited: boolean;
  tags: Record<string, string>;
  rua: DmarcUri[];
  ruf: DmarcUri[];
}

export interface MtaStsMxCoverage {
  mx: string;
  matched: boolean;
  /** The MX certificate is WebPKI-valid for the host name (RFC 8461 §4.2); null when not probed. */
  certValid: boolean | null;
}

export interface MtaStsData {
  record: string | null;
  records: string[];
  id: string | null;
  policyUrl: string;
  fetch: {
    status: number | null;
    contentType: string | null;
    redirect: string | null;
    error: string | null;
    cert: CertInfo | null;
  } | null;
  raw: string | null;
  policy: { version: string | null; mode: string | null; maxAge: number | null; mx: string[] } | null;
  coverage: MtaStsMxCoverage[];
  /** The policy (digest) first seen under the current id, to notice edits without a new id. */
  idPolicy?: { id: string; hash: string } | null;
}

export interface TlsRptData {
  record: string | null;
  records: string[];
  rua: DmarcUri[];
}

export interface TlsaRecord {
  usage: number;
  selector: number;
  matchingType: number;
  data: string;
  /** Matched the certificate chain of at least one probed address; null when not probed. */
  matched: boolean | null;
}

export interface DaneHost {
  mx: string;
  /** The MX host's address records were DNSSEC-validated. */
  addressSecure: boolean;
  tlsa: TlsaRecord[];
  tlsaSecure: boolean;
  /** The TLSA lookup failed (e.g. SERVFAIL): DANE senders defer delivery to this MX. */
  tlsaFailed?: string | null;
  probed: boolean;
  /** Addresses whose certificate matches none of the usable TLSA records. */
  unmatchedIps?: string[];
}

export interface DaneData {
  /** The MX answer was DNSSEC-validated. */
  mxSecure: boolean;
  /** The zone has DNSKEY records and validates (AD on the SOA). */
  zoneSigned: boolean;
  hosts: DaneHost[];
}

export interface BimiData {
  record: string | null;
  records: string[];
  tags: Record<string, string>;
  logo: {
    url: string;
    status: number | null;
    contentType: string | null;
    bytes: number | null;
    error: string | null;
  } | null;
  authority: { url: string; status: number | null; error: string | null } | null;
}

export interface DnsblListing {
  zone: string;
  listed: boolean;
  /** The list refused the query (e.g. Spamhaus via a public resolver): unknown. */
  refused: boolean;
  codes: string[];
  reason: string | null;
}

export interface DnsblData {
  ips: { ip: string; sources: string[]; listings: DnsblListing[] }[];
  zones: string[];
}

// --- Domains & overview ---------------------------------------------------------------

export interface DomainInfo {
  /** The n in DOMAIN_<n>_… */
  n: number;
  name: string;
  /** Delivery tests are sent from this domain (SMTP credentials configured). */
  sender: boolean;
  from: string | null;
  sendIntervalMinutes: number | null;
  dkimSelectors: string[];
}

export interface CheckSummary {
  check: CheckKind;
  level: Level;
  checkedAt: string;
  counts: Record<Level, number>;
}

export interface DomainOverview extends DomainInfo {
  level: Level | null;
  checks: CheckSummary[];
}

export interface RecordChange {
  id: number;
  domain: string;
  check: CheckKind;
  at: string;
  before: string | null;
  after: string | null;
}

// --- Insights (report analysis) -------------------------------------------------

/** A domain, reporter or source a finding applies to; the UI shows these as chips that filter the view. */
export interface InsightSubject {
  kind: 'domain' | 'org' | 'ip';
  value: string;
  note?: string;
  level?: Level;
}

export interface Insight {
  level: Level;
  title: string;
  detail: string;
  subjects?: InsightSubject[];
  refs?: RfcRef[];
}

// --- TLS reports (RFC 8460) -----------------------------------------------------------

export type PolicyType = 'sts' | 'tlsa' | 'no-policy-found' | (string & {});

export interface Filters {
  /** Inclusive start day, YYYY-MM-DD (UTC). */
  from?: string;
  /** Inclusive end day, YYYY-MM-DD (UTC). */
  to?: string;
  domain?: string;
  org?: string;
}

export interface TlsKpis {
  reports: number;
  reporters: number;
  domains: number;
  /** Deduplicated session count (see DECISIONS.md, "Counting sessions"). */
  sessions: number;
  successful: number;
  failed: number;
  successRate: number | null;
  lastReportEnd: string | null;
}

export interface TimeBucket {
  start: string;
  successful: number;
  failed: number;
  reports: number;
}

export interface OrgStat {
  org: string;
  reports: number;
  sessions: number;
  failed: number;
  lastReportEnd: string;
}

export interface PolicyStat {
  domain: string;
  type: PolicyType;
  reports: number;
  successful: number;
  failed: number;
  latestMode: string | null;
  latestMxHosts: string[];
  latestPolicyString: string[];
  lastSeen: string;
}

export interface FailureTypeStat {
  resultType: string;
  sessions: number;
  reports: number;
}

export interface FailureDetailStat {
  domain: string;
  policyType: PolicyType;
  resultType: string;
  sendingMtaIp: string | null;
  receivingMxHostname: string | null;
  receivingMxHelo: string | null;
  receivingIp: string | null;
  failureReasonCode: string | null;
  additionalInformation: string | null;
  sessions: number;
  reporters: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface TlsOverview {
  range: { from: string | null; to: string | null };
  bucket: 'day' | 'week';
  kpis: TlsKpis;
  series: TimeBucket[];
  byOrg: OrgStat[];
  byPolicy: PolicyStat[];
  failureTypes: FailureTypeStat[];
  failureDetails: FailureDetailStat[];
  insights: Insight[];
}

export interface TlsReportSummary {
  id: number;
  org: string;
  reportId: string;
  start: string;
  end: string;
  domains: string[];
  policyTypes: string[];
  sessions: number;
  failed: number;
  receivedAt: string | null;
}

export interface TlsFailureDetail {
  resultType: string;
  sendingMtaIp: string | null;
  receivingMxHostname: string | null;
  receivingMxHelo: string | null;
  receivingIp: string | null;
  failedSessionCount: number;
  additionalInformation: string | null;
  failureReasonCode: string | null;
}

export interface TlsPolicyDetail {
  type: PolicyType;
  domain: string;
  policyString: string[];
  mxHosts: string[];
  mode: string | null;
  successful: number;
  failed: number;
  failures: TlsFailureDetail[];
}

export interface ReportSource {
  from: string | null;
  subject: string | null;
  filename: string | null;
  mailbox: string | null;
}

export interface TlsReportDetail extends TlsReportSummary {
  contactInfo: string | null;
  policies: TlsPolicyDetail[];
  source: ReportSource;
  raw: unknown;
}

export interface ReportFilterOptions {
  domains: string[];
  orgs: string[];
  firstDay: string | null;
  lastDay: string | null;
}

// --- DMARC aggregate reports (RFC 7489 §7.2, Appendix C) ------------------------------

export interface DmarcPolicyPublished {
  domain: string;
  adkim: string | null;
  aspf: string | null;
  p: string | null;
  sp: string | null;
  np: string | null;
  pct: number | null;
  fo: string | null;
}

export interface DmarcAuthResult {
  domain: string;
  selector?: string | null;
  scope?: string | null;
  result: string;
}

export interface DmarcRecordRow {
  sourceIp: string;
  count: number;
  disposition: string;
  /** policy_evaluated: aligned results. */
  dkim: string;
  spf: string;
  reasons: { type: string; comment: string | null }[];
  headerFrom: string;
  envelopeFrom: string | null;
  envelopeTo: string | null;
  dkimResults: DmarcAuthResult[];
  spfResults: DmarcAuthResult[];
}

export interface DmarcKpis {
  reports: number;
  reporters: number;
  domains: number;
  sources: number;
  messages: number;
  /** Messages that passed DMARC (aligned SPF or aligned DKIM pass). */
  passed: number;
  failed: number;
  passRate: number | null;
  quarantined: number;
  rejected: number;
  lastReportEnd: string | null;
}

export interface DmarcBucket {
  start: string;
  passed: number;
  failed: number;
  reports: number;
}

export interface DmarcSourceStat {
  ip: string;
  ptr: string | null;
  messages: number;
  passed: number;
  failed: number;
  spfAligned: number;
  dkimAligned: number;
  quarantined: number;
  rejected: number;
  headerFrom: string[];
  envelopeFrom: string[];
  dkimDomains: string[];
  reporters: string[];
  lastSeen: string;
}

export interface DmarcOrgStat {
  org: string;
  reports: number;
  messages: number;
  failed: number;
  lastReportEnd: string;
}

export interface DmarcDomainStat {
  domain: string;
  reports: number;
  messages: number;
  passed: number;
  failed: number;
  policy: DmarcPolicyPublished | null;
  lastSeen: string;
}

export interface DmarcSelectorStat {
  domain: string;
  selector: string;
  pass: number;
  fail: number;
}

export interface DmarcOverview {
  range: { from: string | null; to: string | null };
  bucket: 'day' | 'week';
  kpis: DmarcKpis;
  series: DmarcBucket[];
  bySource: DmarcSourceStat[];
  byOrg: DmarcOrgStat[];
  byDomain: DmarcDomainStat[];
  selectors: DmarcSelectorStat[];
  insights: Insight[];
}

export interface DmarcReportSummary {
  id: number;
  org: string;
  reportId: string;
  domain: string;
  start: string;
  end: string;
  messages: number;
  failed: number;
  receivedAt: string | null;
}

export interface DmarcReportDetail extends DmarcReportSummary {
  email: string | null;
  extraContact: string | null;
  errors: string[];
  policy: DmarcPolicyPublished;
  records: DmarcRecordRow[];
  source: ReportSource;
  raw: string;
}

// --- DMARC failure reports (RFC 6591 / RFC 5965) --------------------------------------

export interface FailureReport {
  id: number;
  reporter: string | null;
  receivedAt: string | null;
  feedbackType: string | null;
  authFailure: string | null;
  reportedDomain: string | null;
  sourceIp: string | null;
  arrivalDate: string | null;
  originalMailFrom: string | null;
  originalRcptTo: string | null;
  dkimDomain: string | null;
  dkimSelector: string | null;
  deliveryResult: string | null;
  identityAlignment: string | null;
  authenticationResults: string | null;
  headerFrom: string | null;
  subject: string | null;
}

export interface FailureReportDetail extends FailureReport {
  fields: [string, string][];
  headers: string | null;
  source: ReportSource;
}

// --- Mailboxes --------------------------------------------------------------------

export interface SyncResult {
  messagesSeen: number;
  tlsReports: number;
  dmarcReports: number;
  failureReports: number;
  duplicates: number;
  messagesWithoutReport: number;
  errors: number;
  deleted: number;
}

export interface MessageIssue {
  uid: number;
  from: string | null;
  subject: string | null;
  date: string | null;
  status: 'no-report' | 'error';
  error: string | null;
}

export interface MailboxStatus {
  key: string;
  n: number;
  name: string;
  address: string | null;
  folder: string;
  running: boolean;
  lastRunAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  lastResult: SyncResult | null;
  messages: number;
  issues: MessageIssue[];
  cleanup: { afterMonths: number; dryRun: boolean } | null;
}

// --- Delivery tests ----------------------------------------------------------------

export type ProbeStatus = 'sending' | 'sent' | 'inbox' | 'spam' | 'lost' | 'send-failed';

export interface ProbeAuth {
  spf: string | null;
  dkim: string | null;
  dmarc: string | null;
  arc: string | null;
  /** Microsoft's composite authentication, e.g. "pass reason=100". */
  compauth: string | null;
  /** Microsoft's spam confidence level, when exposed. */
  scl: number | null;
}

export interface DeliveryProbe {
  id: number;
  sender: string;
  recipient: string;
  token: string;
  sentAt: string;
  status: ProbeStatus;
  smtpResponse: string | null;
  error: string | null;
  receivedAt: string | null;
  folder: string | null;
  latencySeconds: number | null;
  auth: ProbeAuth | null;
  clientIp: string | null;
  dkimSelectors: string[];
  headers: string | null;
}

export interface RecipientInfo {
  n: number;
  name: string;
  address: string;
  auth: 'password' | 'oauth2';
}

export interface RecipientStatus extends RecipientInfo {
  lastPollAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
}

export interface DeliveryPair {
  sender: string;
  recipient: string;
  latest: DeliveryProbe | null;
  /** Over the selected period. */
  sent: number;
  inbox: number;
  spam: number;
  lost: number;
  failed: number;
  medianLatencySeconds: number | null;
}

export interface DeliveryOverview {
  days: number;
  pairs: DeliveryPair[];
  recent: DeliveryProbe[];
}

// --- Alerts -------------------------------------------------------------------------

export type AlertKind = 'check' | 'delivery' | 'report' | 'sync';

export interface Alert {
  id: number;
  /** Stable identity: kind|code|domain|subject. Snoozes use it. */
  key: string;
  kind: AlertKind;
  code: string;
  domain: string | null;
  subject: string;
  title: string;
  severity: Severity;
  detail: string | null;
  refs: RfcRef[];
  startedAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  notified: boolean;
  ackedAt: string | null;
  ackedBy: string | null;
  silenced: boolean;
  snoozedUntil: string | null;
}

export interface Snooze {
  key: string;
  title: string;
  until: string;
  createdBy: string | null;
  createdAt: string;
}

export interface QuietHours {
  enabled: boolean;
  start: string;
  end: string;
  /** Error alerts are sent during quiet hours anyway. */
  exemptErrors: boolean;
}

export interface Settings {
  quietHours: QuietHours;
  /** Alerts below this severity are shown in the dashboard but not sent to Telegram. */
  notifyMinSeverity: Severity;
  /** Send a Telegram message when a monitored DNS record changes. */
  notifyChanges: boolean;
}

// --- Status -------------------------------------------------------------------------

export interface JobStatus {
  running: boolean;
  lastRunAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  nextRunAt: string | null;
  intervalMinutes: number;
}

export interface Status {
  demo: boolean;
  timezone: string;
  domains: DomainInfo[];
  checks: JobStatus;
  reports: JobStatus;
  delivery: JobStatus & { timeoutMinutes: number };
  mailboxes: MailboxStatus[];
  recipients: RecipientStatus[];
  telegram: { configured: boolean; lastError: string | null; quiet: boolean };
  dns: { resolvers: string[]; blocklistResolvers: string[]; spamhausDqs: boolean };
  smtpProbe: boolean;
}

// --- Auth ---------------------------------------------------------------------------

export interface AuthUser {
  sub: string;
  email: string | null;
  name: string | null;
  /** May change settings and send test notifications (OIDC_EDITOR_GROUPS). */
  canEdit: boolean;
}

export interface Me {
  user: AuthUser;
}
