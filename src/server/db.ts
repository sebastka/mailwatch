// MariaDB persistence.
import mariadb, { type Pool, type PoolConnection } from 'mariadb';
import type {
  Alert,
  AlertKind,
  CheckKind,
  CheckResult,
  DeliveryProbe,
  DmarcPolicyPublished,
  DmarcRecordRow,
  FailureReport,
  FailureReportDetail,
  Filters,
  MessageIssue,
  ProbeAuth,
  ProbeStatus,
  RecordChange,
  ReportFilterOptions,
  RfcRef,
  Severity,
  Snooze,
} from '../shared/types.ts';
import type { NormalizedFailureReport } from './reports/arf.ts';
import type { NormalizedDmarcReport } from './reports/dmarc.ts';
import type { NormalizedFailure, NormalizedReport } from './reports/tlsrpt.ts';

/**
 * Ordered schema migrations. Never edit an applied migration; append a new one.
 * Each entry is a list of statements (the driver runs one statement per query).
 */
const MIGRATIONS: string[][] = [
  [
    `CREATE TABLE meta (
       k VARCHAR(191) NOT NULL PRIMARY KEY,
       v TEXT NOT NULL
     )`,
    // Latest result of every check of every domain.
    `CREATE TABLE check_results (
       domain      VARCHAR(253) NOT NULL,
       check_kind  VARCHAR(16)  NOT NULL,
       checked_at  DATETIME     NOT NULL,
       level       ENUM('ok', 'info', 'warning', 'error') NOT NULL,
       duration_ms INT UNSIGNED NOT NULL,
       findings    LONGTEXT NOT NULL CHECK (JSON_VALID(findings)),
       data        LONGTEXT NOT NULL CHECK (JSON_VALID(data)),
       PRIMARY KEY (domain, check_kind)
     )`,
    // Changes of the published records (SPF, DMARC, MTA-STS policy, …).
    `CREATE TABLE record_changes (
       id           INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       domain       VARCHAR(253) NOT NULL,
       check_kind   VARCHAR(16)  NOT NULL,
       at           DATETIME     NOT NULL,
       before_value MEDIUMTEXT,
       after_value  MEDIUMTEXT,
       KEY changes_at (at)
     )`,
    // How many consecutive checks have seen a finding (ALERT_CONFIRMATIONS).
    `CREATE TABLE finding_streaks (
       k          VARCHAR(191) NOT NULL PRIMARY KEY,
       scope      VARCHAR(253) NOT NULL,
       n          INT UNSIGNED NOT NULL,
       updated_at DATETIME     NOT NULL,
       KEY streaks_scope (scope)
     )`,
    `CREATE TABLE messages (
       mailbox      VARCHAR(191) NOT NULL,
       uidvalidity  VARCHAR(32)  NOT NULL,
       uid          INT UNSIGNED NOT NULL,
       message_id   TEXT,
       from_addr    VARCHAR(320),
       subject      TEXT,
       date         DATETIME,
       kind         VARCHAR(32),
       status       ENUM('ok', 'duplicate', 'no-report', 'error') NOT NULL,
       error        TEXT,
       processed_at DATETIME NOT NULL,
       deleted_at   DATETIME NULL,
       PRIMARY KEY (mailbox, uidvalidity, uid)
     )`,
    // SMTP TLS reports (RFC 8460), as in tlsrpt.
    `CREATE TABLE tls_reports (
       id           INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       org_name     VARCHAR(255) NOT NULL,
       report_id    VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
       contact_info VARCHAR(1024),
       start_ts     DATETIME NOT NULL,
       end_ts       DATETIME NOT NULL,
       day          DATE NOT NULL,
       raw_json     LONGTEXT NOT NULL CHECK (JSON_VALID(raw_json)),
       src_from     VARCHAR(320),
       src_subject  TEXT,
       src_filename VARCHAR(1024),
       src_mailbox  VARCHAR(191),
       received_at  DATETIME,
       created_at   DATETIME NOT NULL,
       UNIQUE KEY tls_reports_unique (org_name, report_id),
       KEY tls_reports_day (day)
     )`,
    `CREATE TABLE tls_policies (
       id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       report_ref    INT UNSIGNED NOT NULL,
       policy_type   VARCHAR(32)  NOT NULL,
       policy_domain VARCHAR(255) NOT NULL,
       policy_string LONGTEXT NOT NULL CHECK (JSON_VALID(policy_string)),
       mx_hosts      LONGTEXT NOT NULL CHECK (JSON_VALID(mx_hosts)),
       sts_mode      VARCHAR(32),
       success_count INT UNSIGNED NOT NULL,
       failure_count INT UNSIGNED NOT NULL,
       KEY tls_policies_domain (policy_domain),
       CONSTRAINT tls_policies_report FOREIGN KEY (report_ref) REFERENCES tls_reports (id) ON DELETE CASCADE
     )`,
    `CREATE TABLE tls_failures (
       id                     INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       policy_ref             INT UNSIGNED NOT NULL,
       result_type            VARCHAR(64) NOT NULL,
       sending_mta_ip         VARCHAR(64),
       receiving_mx_hostname  VARCHAR(255),
       receiving_mx_helo      VARCHAR(255),
       receiving_ip           VARCHAR(64),
       failed_session_count   INT UNSIGNED NOT NULL,
       additional_information TEXT,
       failure_reason_code    VARCHAR(255),
       CONSTRAINT tls_failures_policy FOREIGN KEY (policy_ref) REFERENCES tls_policies (id) ON DELETE CASCADE
     )`,
    // DMARC aggregate reports (rua).
    `CREATE TABLE dmarc_reports (
       id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       org_name      VARCHAR(255) NOT NULL,
       report_id     VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,
       domain        VARCHAR(253) NOT NULL,
       email         VARCHAR(320),
       extra_contact VARCHAR(1024),
       begin_ts      DATETIME NOT NULL,
       end_ts        DATETIME NOT NULL,
       day           DATE NOT NULL,
       policy        TEXT NOT NULL CHECK (JSON_VALID(policy)),
       errors        TEXT NOT NULL CHECK (JSON_VALID(errors)),
       raw_xml       LONGTEXT NOT NULL,
       src_from      VARCHAR(320),
       src_subject   TEXT,
       src_filename  VARCHAR(1024),
       src_mailbox   VARCHAR(191),
       received_at   DATETIME,
       created_at    DATETIME NOT NULL,
       UNIQUE KEY dmarc_reports_unique (org_name, report_id, domain),
       KEY dmarc_reports_day (day),
       KEY dmarc_reports_domain (domain)
     )`,
    `CREATE TABLE dmarc_records (
       id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       report_ref    INT UNSIGNED NOT NULL,
       source_ip     VARCHAR(64)  NOT NULL,
       count         INT UNSIGNED NOT NULL,
       disposition   VARCHAR(16)  NOT NULL,
       dkim_eval     VARCHAR(16)  NOT NULL,
       spf_eval      VARCHAR(16)  NOT NULL,
       reasons       TEXT NOT NULL CHECK (JSON_VALID(reasons)),
       header_from   VARCHAR(255) NOT NULL,
       envelope_from VARCHAR(255),
       envelope_to   VARCHAR(255),
       dkim_results  TEXT NOT NULL CHECK (JSON_VALID(dkim_results)),
       spf_results   TEXT NOT NULL CHECK (JSON_VALID(spf_results)),
       KEY dmarc_records_ip (source_ip),
       CONSTRAINT dmarc_records_report FOREIGN KEY (report_ref) REFERENCES dmarc_reports (id) ON DELETE CASCADE
     )`,
    // DMARC failure reports (ruf, RFC 6591): report fields and the original headers, no bodies.
    `CREATE TABLE failure_reports (
       id                     INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       msg_key                VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
       reporter               VARCHAR(320),
       received_at            DATETIME,
       feedback_type          VARCHAR(32),
       auth_failure           VARCHAR(64),
       reported_domain        VARCHAR(253),
       source_ip              VARCHAR(64),
       arrival_date           VARCHAR(128),
       original_mail_from     VARCHAR(320),
       original_rcpt_to       VARCHAR(320),
       dkim_domain            VARCHAR(253),
       dkim_selector          VARCHAR(128),
       delivery_result        VARCHAR(32),
       identity_alignment     VARCHAR(64),
       authentication_results TEXT,
       header_from            VARCHAR(512),
       subject                TEXT,
       fields                 TEXT NOT NULL CHECK (JSON_VALID(fields)),
       headers                MEDIUMTEXT,
       src_subject            TEXT,
       src_mailbox            VARCHAR(191),
       created_at             DATETIME NOT NULL,
       UNIQUE KEY failure_reports_key (msg_key),
       KEY failure_reports_domain (reported_domain),
       KEY failure_reports_received (received_at)
     )`,
    // Delivery tests: one row per message sent from a domain to a recipient.
    `CREATE TABLE probes (
       id              INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       token           CHAR(24) NOT NULL,
       sender          VARCHAR(253) NOT NULL,
       recipient       VARCHAR(255) NOT NULL,
       sent_at         DATETIME NOT NULL,
       status          ENUM('sending', 'sent', 'inbox', 'spam', 'lost', 'send-failed') NOT NULL,
       smtp_response   TEXT,
       error           TEXT,
       received_at     DATETIME,
       folder          VARCHAR(255),
       latency_seconds INT,
       auth            TEXT CHECK (auth IS NULL OR JSON_VALID(auth)),
       client_ip       VARCHAR(64),
       dkim_selectors  TEXT CHECK (dkim_selectors IS NULL OR JSON_VALID(dkim_selectors)),
       headers         MEDIUMTEXT,
       UNIQUE KEY probes_token (token),
       KEY probes_pair (sender, recipient, sent_at),
       KEY probes_status (status),
       KEY probes_sent (sent_at)
     )`,
    `CREATE TABLE alerts (
       id                  INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       k                   VARCHAR(191) NOT NULL,
       kind                ENUM('check', 'delivery', 'report', 'sync') NOT NULL,
       code                VARCHAR(64)  NOT NULL,
       domain              VARCHAR(253),
       subject             VARCHAR(255) NOT NULL,
       title               VARCHAR(255) NOT NULL,
       severity            ENUM('info', 'warning', 'error') NOT NULL,
       detail              TEXT,
       refs                TEXT NOT NULL CHECK (JSON_VALID(refs)),
       started_at          DATETIME NOT NULL,
       last_seen_at        DATETIME NOT NULL,
       resolved_at         DATETIME,
       notified_start_at   DATETIME,
       notified_resolve_at DATETIME,
       acked_at            DATETIME,
       acked_by            VARCHAR(320),
       silenced            BOOLEAN NOT NULL DEFAULT FALSE,
       KEY alerts_open (resolved_at),
       KEY alerts_key (k),
       KEY alerts_started (started_at)
     )`,
    `CREATE TABLE snoozes (
       k          VARCHAR(191) NOT NULL PRIMARY KEY,
       title      VARCHAR(255) NOT NULL,
       until      DATETIME     NOT NULL,
       created_by VARCHAR(320),
       created_at DATETIME     NOT NULL
     )`,
    `CREATE TABLE sessions (
       token_hash CHAR(64) NOT NULL PRIMARY KEY,
       sub        VARCHAR(255) NOT NULL,
       email      VARCHAR(320),
       name       VARCHAR(255),
       can_edit   BOOLEAN NOT NULL,
       id_token   TEXT,
       created_at DATETIME NOT NULL,
       expires_at DATETIME NOT NULL,
       KEY sessions_expiry (expires_at)
     )`,
    `CREATE TABLE oidc_logins (
       state         VARCHAR(128) NOT NULL PRIMARY KEY,
       code_verifier VARCHAR(128) NOT NULL,
       nonce         VARCHAR(128) NOT NULL,
       return_to     VARCHAR(2048) NOT NULL,
       created_at    DATETIME NOT NULL
     )`,
  ],
];

// --- Row types ------------------------------------------------------------------------

export interface TlsReportRow {
  id: number;
  org: string;
  reportId: string;
  contactInfo: string | null;
  start: string;
  end: string;
  day: string;
  receivedAt: string | null;
  policies: TlsPolicyRow[];
}

export interface TlsPolicyRow {
  id: number;
  type: string;
  domain: string;
  policyString: string[];
  mxHosts: string[];
  mode: string | null;
  successful: number;
  failed: number;
  failures: NormalizedFailure[];
}

export interface DmarcReportRow {
  id: number;
  org: string;
  reportId: string;
  domain: string;
  email: string | null;
  extraContact: string | null;
  begin: string;
  end: string;
  day: string;
  receivedAt: string | null;
  policy: DmarcPolicyPublished;
  errors: string[];
  records: DmarcRecordRow[];
}

export interface MessageRecord {
  mailbox: string;
  uidvalidity: string;
  uid: number;
  messageId: string | null;
  from: string | null;
  subject: string | null;
  date: string | null;
  kind: string | null;
  status: 'ok' | 'duplicate' | 'no-report' | 'error';
  error: string | null;
}

export interface ReportSrc {
  from: string | null;
  subject: string | null;
  filename: string | null;
  mailbox: string;
  receivedAt: string | null;
}

export interface SessionRecord {
  sub: string;
  email: string | null;
  name: string | null;
  canEdit: boolean;
  idToken: string | null;
}

export interface PendingLogin {
  codeVerifier: string;
  nonce: string;
  returnTo: string;
}

export interface DbConfig {
  host: string;
  port: number;
  user: string;
  password?: string | undefined;
  database: string;
  connectionLimit?: number;
  ssl?: boolean;
}

/** A new alert, or the fields of an open alert that change while it is active. */
export interface AlertWrite {
  key: string;
  kind: AlertKind;
  code: string;
  domain: string | null;
  subject: string;
  title: string;
  severity: Severity;
  detail: string | null;
  refs: RfcRef[];
}

/** An alert with its notification bookkeeping. */
export interface AlertState extends Alert {
  notifiedStartAt: string | null;
  notifiedResolveAt: string | null;
}

// The driver returns loosely typed rows.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Row = Record<string, any>;

// DATETIME columns hold UTC. They are exchanged with the driver as 'YYYY-MM-DD HH:MM:SS'
// strings (dateStrings), because the driver otherwise converts using the process time zone.
export const iso = (s: string | null | undefined): string | null =>
  s ? new Date(`${s.replace(' ', 'T')}Z`).toISOString() : null;
export const dbTime = (s: string | number | Date | null | undefined): string | null =>
  s === null || s === undefined ? null : new Date(s).toISOString().slice(0, 19).replace('T', ' ');
const clip = (s: string | null | undefined, n: number): string | null =>
  s === null || s === undefined ? null : s.length > n ? s.slice(0, n) : s;
const json = <T>(v: unknown, fallback: T): T => {
  if (v === null || v === undefined) return fallback;
  return typeof v === 'string' ? (JSON.parse(v) as T) : (v as T);
};

const SNOOZE_JOIN = 'LEFT JOIN snoozes s ON s.k = a.k AND s.until > UTC_TIMESTAMP()';

function toAlert(r: Row): AlertState {
  return {
    id: Number(r.id),
    key: r.k,
    kind: r.kind,
    code: r.code,
    domain: r.domain ?? null,
    subject: r.subject,
    title: r.title,
    severity: r.severity,
    detail: r.detail ?? null,
    refs: json<RfcRef[]>(r.refs, []),
    startedAt: iso(r.started_at)!,
    lastSeenAt: iso(r.last_seen_at)!,
    resolvedAt: iso(r.resolved_at),
    notified: r.notified_start_at !== null && !r.silenced,
    ackedAt: iso(r.acked_at),
    ackedBy: r.acked_by ?? null,
    silenced: Boolean(r.silenced),
    snoozedUntil: iso(r.snoozed_until),
    notifiedStartAt: iso(r.notified_start_at),
    notifiedResolveAt: iso(r.notified_resolve_at),
  };
}

function toProbe(r: Row, withHeaders = false): DeliveryProbe {
  return {
    id: Number(r.id),
    sender: r.sender,
    recipient: r.recipient,
    token: r.token,
    sentAt: iso(r.sent_at)!,
    status: r.status,
    smtpResponse: r.smtp_response ?? null,
    error: r.error ?? null,
    receivedAt: iso(r.received_at),
    folder: r.folder ?? null,
    latencySeconds: r.latency_seconds === null ? null : Number(r.latency_seconds),
    auth: json<ProbeAuth | null>(r.auth, null),
    clientIp: r.client_ip ?? null,
    dkimSelectors: json<string[]>(r.dkim_selectors, []),
    headers: withHeaders ? (r.headers ?? null) : null,
  };
}

function toFailure(r: Row): FailureReport {
  return {
    id: Number(r.id),
    reporter: r.reporter ?? null,
    receivedAt: iso(r.received_at),
    feedbackType: r.feedback_type ?? null,
    authFailure: r.auth_failure ?? null,
    reportedDomain: r.reported_domain ?? null,
    sourceIp: r.source_ip ?? null,
    arrivalDate: r.arrival_date ?? null,
    originalMailFrom: r.original_mail_from ?? null,
    originalRcptTo: r.original_rcpt_to ?? null,
    dkimDomain: r.dkim_domain ?? null,
    dkimSelector: r.dkim_selector ?? null,
    deliveryResult: r.delivery_result ?? null,
    identityAlignment: r.identity_alignment ?? null,
    authenticationResults: r.authentication_results ?? null,
    headerFrom: r.header_from ?? null,
    subject: r.subject ?? null,
  };
}

function dayFilters(f: Filters, dayCol: string, domainCol: string | null, orgCol: string) {
  const where: string[] = [];
  const params: unknown[] = [];
  if (f.from) {
    where.push(`${dayCol} >= ?`);
    params.push(f.from);
  }
  if (f.to) {
    where.push(`${dayCol} <= ?`);
    params.push(f.to);
  }
  if (f.org) {
    where.push(`${orgCol} = ?`);
    params.push(f.org);
  }
  if (f.domain && domainCol) {
    where.push(`${domainCol} = ?`);
    params.push(f.domain);
  }
  return { where, params };
}

export class Store {
  readonly pool: Pool;

  private constructor(pool: Pool) {
    this.pool = pool;
  }

  /** Connects and applies pending migrations. */
  static async connect(cfg: DbConfig): Promise<Store> {
    const pool = mariadb.createPool({
      host: cfg.host,
      port: cfg.port,
      user: cfg.user,
      password: cfg.password,
      database: cfg.database,
      connectionLimit: cfg.connectionLimit ?? 5,
      ssl: cfg.ssl ? { rejectUnauthorized: true } : undefined,
      dateStrings: true,
      bigIntAsNumber: true,
      insertIdAsNumber: true,
      decimalAsNumber: true,
      charset: 'utf8mb4',
      initSql: "SET time_zone = '+00:00'",
    });
    const store = new Store(pool);
    try {
      await store.migrate();
    } catch (e) {
      await pool.end();
      throw e;
    }
    return store;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  private async migrate(): Promise<void> {
    await this.withConnection(async (conn) => {
      // Serialise migrations when several instances start at once.
      const [lock] = await conn.query<Row[]>("SELECT GET_LOCK('mailwatch_migrate', 60) AS ok");
      if (lock?.ok !== 1) throw new Error('could not acquire the migration lock');
      try {
        await conn.query(
          'CREATE TABLE IF NOT EXISTS schema_migrations (version INT UNSIGNED NOT NULL PRIMARY KEY, applied_at DATETIME NOT NULL)',
        );
        const [row] = await conn.query<Row[]>('SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations');
        for (let v = Number(row?.v ?? 0); v < MIGRATIONS.length; v++) {
          // DDL commits implicitly in MariaDB, so a failed migration must be fixed by hand.
          for (const stmt of MIGRATIONS[v]!) await conn.query(stmt);
          await conn.query('INSERT INTO schema_migrations (version, applied_at) VALUES (?, UTC_TIMESTAMP())', [v + 1]);
        }
      } finally {
        await conn.query("SELECT RELEASE_LOCK('mailwatch_migrate')");
      }
    });
  }

  private async withConnection<T>(fn: (conn: PoolConnection) => Promise<T>): Promise<T> {
    const conn = await this.pool.getConnection();
    try {
      return await fn(conn);
    } finally {
      await conn.release();
    }
  }

  private async transaction<T>(fn: (conn: PoolConnection) => Promise<T>): Promise<T> {
    return this.withConnection(async (conn) => {
      await conn.beginTransaction();
      try {
        const r = await fn(conn);
        await conn.commit();
        return r;
      } catch (e) {
        await conn.rollback();
        throw e;
      }
    });
  }

  /**
   * Runs fn while holding a named server-side lock, so only one instance does it at a time.
   * Returns null without running fn when another holder has the lock (after waiting up to
   * `waitSeconds`).
   */
  async withExclusiveLock<T>(name: string, fn: () => Promise<T>, waitSeconds = 0): Promise<T | null> {
    return this.withConnection(async (conn) => {
      const [lock] = await conn.query<Row[]>('SELECT GET_LOCK(?, ?) AS ok', [name, waitSeconds]);
      if (lock?.ok !== 1) return null;
      try {
        return await fn();
      } finally {
        await conn.query('SELECT RELEASE_LOCK(?)', [name]);
      }
    });
  }

  async getMeta(key: string): Promise<string | null> {
    const [row] = await this.pool.query<Row[]>('SELECT v FROM meta WHERE k = ?', [key]);
    return (row?.v as string) ?? null;
  }

  async setMeta(key: string, value: string): Promise<void> {
    await this.pool.query('INSERT INTO meta (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)', [key, value]);
  }

  // --- Check results ------------------------------------------------------------------

  async saveCheckResults(results: CheckResult[]): Promise<void> {
    if (!results.length) return;
    await this.pool.batch(
      `INSERT INTO check_results (domain, check_kind, checked_at, level, duration_ms, findings, data)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE checked_at = VALUES(checked_at), level = VALUES(level),
         duration_ms = VALUES(duration_ms), findings = VALUES(findings), data = VALUES(data)`,
      results.map((r) => [
        r.domain,
        r.check,
        dbTime(r.checkedAt),
        r.level,
        r.durationMs,
        JSON.stringify(r.findings),
        JSON.stringify(r.data ?? null),
      ]),
    );
  }

  async checkResults(opts: { domain?: string; check?: CheckKind; withData?: boolean } = {}): Promise<CheckResult[]> {
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.domain) {
      where.push('domain = ?');
      params.push(opts.domain);
    }
    if (opts.check) {
      where.push('check_kind = ?');
      params.push(opts.check);
    }
    const withData = opts.withData ?? true;
    const rows = await this.pool.query<Row[]>(
      `SELECT domain, check_kind, checked_at, level, duration_ms, findings${withData ? ', data' : ''}
       FROM check_results ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY domain`,
      params,
    );
    return rows.map((r) => ({
      domain: r.domain,
      check: r.check_kind,
      checkedAt: iso(r.checked_at)!,
      level: r.level,
      durationMs: Number(r.duration_ms),
      findings: json(r.findings, []),
      data: withData ? json(r.data, null) : null,
    }));
  }

  /** Removes results of domains that are no longer configured. */
  async pruneCheckResults(domains: string[]): Promise<void> {
    if (!domains.length) await this.pool.query('DELETE FROM check_results');
    else await this.pool.query('DELETE FROM check_results WHERE domain NOT IN (?)', [domains]);
  }

  async recordChange(
    domain: string,
    check: CheckKind,
    before: string | null,
    after: string | null,
    at: string,
  ): Promise<void> {
    await this.pool.query(
      'INSERT INTO record_changes (domain, check_kind, at, before_value, after_value) VALUES (?, ?, ?, ?, ?)',
      [domain, check, dbTime(at), before, after],
    );
  }

  async changes(opts: { domain?: string; check?: CheckKind; limit?: number } = {}): Promise<RecordChange[]> {
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.domain) {
      where.push('domain = ?');
      params.push(opts.domain);
    }
    if (opts.check) {
      where.push('check_kind = ?');
      params.push(opts.check);
    }
    const rows = await this.pool.query<Row[]>(
      `SELECT * FROM record_changes ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY at DESC, id DESC LIMIT ?`,
      [...params, opts.limit ?? 100],
    );
    return rows.map((r) => ({
      id: Number(r.id),
      domain: r.domain,
      check: r.check_kind,
      at: iso(r.at)!,
      before: r.before_value ?? null,
      after: r.after_value ?? null,
    }));
  }

  /**
   * Counts consecutive sightings: keys in `present` are incremented, the other keys of the
   * scope are forgotten. Returns the new count of every present key.
   */
  async updateStreaks(scope: string, present: string[]): Promise<Map<string, number>> {
    return this.transaction(async (conn) => {
      const rows = await conn.query<Row[]>('SELECT k, n FROM finding_streaks WHERE scope = ? FOR UPDATE', [scope]);
      const old = new Map(rows.map((r) => [r.k as string, Number(r.n)]));
      const keep = new Set(present);
      const gone = [...old.keys()].filter((k) => !keep.has(k));
      if (gone.length) await conn.query('DELETE FROM finding_streaks WHERE k IN (?)', [gone]);
      const out = new Map<string, number>();
      for (const k of keep) out.set(k, (old.get(k) ?? 0) + 1);
      if (out.size) {
        await conn.batch(
          `INSERT INTO finding_streaks (k, scope, n, updated_at) VALUES (?, ?, ?, UTC_TIMESTAMP())
           ON DUPLICATE KEY UPDATE n = VALUES(n), updated_at = VALUES(updated_at)`,
          [...out].map(([k, n]) => [k, scope, n]),
        );
      }
      return out;
    });
  }

  // --- Mailbox messages -----------------------------------------------------------------

  async recordMessage(m: MessageRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO messages (mailbox, uidvalidity, uid, message_id, from_addr, subject, date, kind, status, error, processed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())
       ON DUPLICATE KEY UPDATE
         message_id = VALUES(message_id), from_addr = VALUES(from_addr), subject = VALUES(subject), date = VALUES(date),
         kind = VALUES(kind), status = VALUES(status), error = VALUES(error), processed_at = VALUES(processed_at)`,
      [
        m.mailbox,
        m.uidvalidity,
        m.uid,
        m.messageId,
        clip(m.from, 320),
        m.subject,
        dbTime(m.date),
        m.kind,
        m.status,
        m.error,
      ],
    );
  }

  /** Of the given UIDs, those whose reports are safely stored and which are still in the mailbox. */
  async importedUids(mailbox: string, uidvalidity: string, uids: number[]): Promise<Set<number>> {
    const found = new Set<number>();
    for (let i = 0; i < uids.length; i += 500) {
      const rows = await this.pool.query<Row[]>(
        `SELECT uid FROM messages
         WHERE mailbox = ? AND uidvalidity = ? AND status IN ('ok', 'duplicate') AND deleted_at IS NULL AND uid IN (?)`,
        [mailbox, uidvalidity, uids.slice(i, i + 500)],
      );
      for (const r of rows) found.add(Number(r.uid));
    }
    return found;
  }

  async markDeleted(mailbox: string, uidvalidity: string, uids: number[]): Promise<void> {
    if (!uids.length) return;
    await this.pool.query(
      'UPDATE messages SET deleted_at = UTC_TIMESTAMP() WHERE mailbox = ? AND uidvalidity = ? AND uid IN (?)',
      [mailbox, uidvalidity, uids],
    );
  }

  async messageIssues(mailbox: string, limit = 50): Promise<MessageIssue[]> {
    const rows = await this.pool.query<Row[]>(
      `SELECT uid, from_addr, subject, date, status, error FROM messages
       WHERE mailbox = ? AND uidvalidity = (SELECT v FROM meta WHERE k = CONCAT('uidvalidity:', ?))
         AND status IN ('no-report', 'error')
       ORDER BY uid DESC LIMIT ?`,
      [mailbox, mailbox, limit],
    );
    return rows.map((r) => ({
      uid: Number(r.uid),
      from: r.from_addr ?? null,
      subject: r.subject ?? null,
      date: iso(r.date),
      status: r.status,
      error: r.error ?? null,
    }));
  }

  async messageCount(mailbox: string): Promise<number> {
    const [row] = await this.pool.query<Row[]>('SELECT COUNT(*) AS n FROM messages WHERE mailbox = ?', [mailbox]);
    return Number(row?.n ?? 0);
  }

  // --- TLS reports --------------------------------------------------------------------

  /** Inserts a report; returns false when (organisation, report-id) is already stored. */
  async insertTlsReport(r: NormalizedReport, raw: unknown, src: ReportSrc): Promise<boolean> {
    return this.transaction(async (conn) => {
      const res = await conn.query(
        `INSERT INTO tls_reports
           (org_name, report_id, contact_info, start_ts, end_ts, day, raw_json, src_from, src_subject, src_filename,
            src_mailbox, received_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())
         ON DUPLICATE KEY UPDATE id = id`,
        [
          clip(r.organizationName, 255),
          clip(r.reportId, 255),
          clip(r.contactInfo, 1024),
          dbTime(r.start),
          dbTime(r.end),
          r.start.slice(0, 10),
          JSON.stringify(raw),
          clip(src.from, 320),
          src.subject,
          clip(src.filename, 1024),
          clip(src.mailbox, 191),
          dbTime(src.receivedAt),
        ],
      );
      // On a duplicate no row is inserted and insertId is 0 (affectedRows is not reliable here).
      if (!res.insertId) return false;
      const reportRef = Number(res.insertId);
      for (const p of r.policies) {
        const pr = await conn.query(
          `INSERT INTO tls_policies (report_ref, policy_type, policy_domain, policy_string, mx_hosts, sts_mode, success_count, failure_count)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            reportRef,
            clip(p.type, 32),
            clip(p.domain, 255),
            JSON.stringify(p.policyString),
            JSON.stringify(p.mxHosts),
            clip(p.mode, 32),
            p.successful,
            p.failed,
          ],
        );
        if (p.failures.length) {
          await conn.batch(
            `INSERT INTO tls_failures (policy_ref, result_type, sending_mta_ip, receiving_mx_hostname, receiving_mx_helo,
                                       receiving_ip, failed_session_count, additional_information, failure_reason_code)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            p.failures.map((f) => [
              Number(pr.insertId),
              clip(f.resultType, 64),
              clip(f.sendingMtaIp, 64),
              clip(f.receivingMxHostname, 255),
              clip(f.receivingMxHelo, 255),
              clip(f.receivingIp, 64),
              f.failedSessionCount,
              f.additionalInformation,
              clip(f.failureReasonCode, 255),
            ]),
          );
        }
      }
      return true;
    });
  }

  async tlsFilterOptions(): Promise<ReportFilterOptions> {
    const [domains, orgs, [range]] = await Promise.all([
      this.pool.query<Row[]>('SELECT DISTINCT policy_domain AS d FROM tls_policies ORDER BY 1'),
      this.pool.query<Row[]>('SELECT DISTINCT org_name AS o FROM tls_reports ORDER BY 1'),
      this.pool.query<Row[]>(
        "SELECT DATE_FORMAT(MIN(day), '%Y-%m-%d') AS a, DATE_FORMAT(MAX(day), '%Y-%m-%d') AS b FROM tls_reports",
      ),
    ]);
    return {
      domains: domains.map((r) => r.d),
      orgs: orgs.map((r) => r.o),
      firstDay: range?.a ?? null,
      lastDay: range?.b ?? null,
    };
  }

  /** Reports matching the filters with their policies and failures; with a domain filter, only that domain's policies. */
  async loadTlsReports(f: Filters & { id?: number }): Promise<TlsReportRow[]> {
    const { where, params } = dayFilters(f, 'r.day', 'p.policy_domain', 'r.org_name');
    if (f.id !== undefined) {
      where.push('r.id = ?');
      params.push(f.id);
    }
    const cond = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const rows = await this.pool.query<Row[]>(
      `SELECT r.id, r.org_name, r.report_id, r.contact_info, r.start_ts, r.end_ts,
              DATE_FORMAT(r.day, '%Y-%m-%d') AS day, r.received_at,
              p.id AS pid, p.policy_type, p.policy_domain, p.policy_string, p.mx_hosts, p.sts_mode,
              p.success_count, p.failure_count
       FROM tls_reports r JOIN tls_policies p ON p.report_ref = r.id
       ${cond}
       ORDER BY r.start_ts, r.id, p.id`,
      params,
    );
    const reports = new Map<number, TlsReportRow>();
    const policies = new Map<number, TlsPolicyRow>();
    for (const row of rows) {
      const id = Number(row.id);
      let rep = reports.get(id);
      if (!rep) {
        rep = {
          id,
          org: row.org_name,
          reportId: row.report_id,
          contactInfo: row.contact_info ?? null,
          start: iso(row.start_ts)!,
          end: iso(row.end_ts)!,
          day: row.day,
          receivedAt: iso(row.received_at),
          policies: [],
        };
        reports.set(id, rep);
      }
      const pol: TlsPolicyRow = {
        id: Number(row.pid),
        type: row.policy_type,
        domain: row.policy_domain,
        policyString: json<string[]>(row.policy_string, []),
        mxHosts: json<string[]>(row.mx_hosts, []),
        mode: row.sts_mode ?? null,
        successful: Number(row.success_count),
        failed: Number(row.failure_count),
        failures: [],
      };
      rep.policies.push(pol);
      policies.set(pol.id, pol);
    }
    if (policies.size) {
      const failures = await this.pool.query<Row[]>(
        `SELECT f.* FROM tls_failures f
         JOIN tls_policies p ON p.id = f.policy_ref
         JOIN tls_reports r ON r.id = p.report_ref
         ${cond} ORDER BY f.id`,
        params,
      );
      for (const fr of failures) {
        policies.get(Number(fr.policy_ref))?.failures.push({
          resultType: fr.result_type,
          sendingMtaIp: fr.sending_mta_ip ?? null,
          receivingMxHostname: fr.receiving_mx_hostname ?? null,
          receivingMxHelo: fr.receiving_mx_helo ?? null,
          receivingIp: fr.receiving_ip ?? null,
          failedSessionCount: Number(fr.failed_session_count),
          additionalInformation: fr.additional_information ?? null,
          failureReasonCode: fr.failure_reason_code ?? null,
        });
      }
    }
    return [...reports.values()];
  }

  async tlsReportSource(id: number) {
    const [row] = await this.pool.query<Row[]>(
      'SELECT raw_json, src_from, src_subject, src_filename, src_mailbox FROM tls_reports WHERE id = ?',
      [id],
    );
    if (!row) return null;
    return {
      raw: json<unknown>(row.raw_json, null),
      from: row.src_from ?? null,
      subject: row.src_subject ?? null,
      filename: row.src_filename ?? null,
      mailbox: row.src_mailbox ?? null,
    };
  }

  // --- DMARC aggregate reports ------------------------------------------------------------

  /** Inserts a report; returns false when (organisation, report id, domain) is already stored. */
  async insertDmarcReport(r: NormalizedDmarcReport, xml: string, src: ReportSrc): Promise<boolean> {
    return this.transaction(async (conn) => {
      const res = await conn.query(
        `INSERT INTO dmarc_reports
           (org_name, report_id, domain, email, extra_contact, begin_ts, end_ts, day, policy, errors, raw_xml,
            src_from, src_subject, src_filename, src_mailbox, received_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())
         ON DUPLICATE KEY UPDATE id = id`,
        [
          clip(r.orgName, 255),
          clip(r.reportId, 255),
          clip(r.policy.domain, 253),
          clip(r.email, 320),
          clip(r.extraContact, 1024),
          dbTime(r.begin),
          dbTime(r.end),
          r.begin.slice(0, 10),
          JSON.stringify(r.policy),
          JSON.stringify(r.errors),
          xml,
          clip(src.from, 320),
          src.subject,
          clip(src.filename, 1024),
          clip(src.mailbox, 191),
          dbTime(src.receivedAt),
        ],
      );
      if (!res.insertId) return false;
      const ref = Number(res.insertId);
      if (r.records.length) {
        await conn.batch(
          `INSERT INTO dmarc_records (report_ref, source_ip, count, disposition, dkim_eval, spf_eval, reasons, header_from,
                                      envelope_from, envelope_to, dkim_results, spf_results)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          r.records.map((x) => [
            ref,
            clip(x.sourceIp, 64),
            x.count,
            clip(x.disposition, 16),
            clip(x.dkim, 16),
            clip(x.spf, 16),
            JSON.stringify(x.reasons),
            clip(x.headerFrom, 255),
            clip(x.envelopeFrom, 255),
            clip(x.envelopeTo, 255),
            JSON.stringify(x.dkimResults),
            JSON.stringify(x.spfResults),
          ]),
        );
      }
      return true;
    });
  }

  async dmarcFilterOptions(): Promise<ReportFilterOptions> {
    const [domains, orgs, [range]] = await Promise.all([
      this.pool.query<Row[]>('SELECT DISTINCT domain AS d FROM dmarc_reports ORDER BY 1'),
      this.pool.query<Row[]>('SELECT DISTINCT org_name AS o FROM dmarc_reports ORDER BY 1'),
      this.pool.query<Row[]>(
        "SELECT DATE_FORMAT(MIN(day), '%Y-%m-%d') AS a, DATE_FORMAT(MAX(day), '%Y-%m-%d') AS b FROM dmarc_reports",
      ),
    ]);
    return {
      domains: domains.map((r) => r.d),
      orgs: orgs.map((r) => r.o),
      firstDay: range?.a ?? null,
      lastDay: range?.b ?? null,
    };
  }

  async loadDmarcReports(f: Filters & { id?: number }, withRecords = true): Promise<DmarcReportRow[]> {
    const { where, params } = dayFilters(f, 'r.day', 'r.domain', 'r.org_name');
    if (f.id !== undefined) {
      where.push('r.id = ?');
      params.push(f.id);
    }
    const cond = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const rows = await this.pool.query<Row[]>(
      `SELECT r.id, r.org_name, r.report_id, r.domain, r.email, r.extra_contact, r.begin_ts, r.end_ts,
              DATE_FORMAT(r.day, '%Y-%m-%d') AS day, r.received_at, r.policy, r.errors
       FROM dmarc_reports r ${cond} ORDER BY r.begin_ts, r.id`,
      params,
    );
    const reports = new Map<number, DmarcReportRow>();
    for (const row of rows) {
      reports.set(Number(row.id), {
        id: Number(row.id),
        org: row.org_name,
        reportId: row.report_id,
        domain: row.domain,
        email: row.email ?? null,
        extraContact: row.extra_contact ?? null,
        begin: iso(row.begin_ts)!,
        end: iso(row.end_ts)!,
        day: row.day,
        receivedAt: iso(row.received_at),
        policy: json(row.policy, {} as DmarcPolicyPublished),
        errors: json(row.errors, []),
        records: [],
      });
    }
    if (withRecords && reports.size) {
      const recs = await this.pool.query<Row[]>(
        `SELECT x.* FROM dmarc_records x JOIN dmarc_reports r ON r.id = x.report_ref ${cond} ORDER BY x.id`,
        params,
      );
      for (const x of recs) {
        reports.get(Number(x.report_ref))?.records.push({
          sourceIp: x.source_ip,
          count: Number(x.count),
          disposition: x.disposition,
          dkim: x.dkim_eval,
          spf: x.spf_eval,
          reasons: json(x.reasons, []),
          headerFrom: x.header_from,
          envelopeFrom: x.envelope_from ?? null,
          envelopeTo: x.envelope_to ?? null,
          dkimResults: json(x.dkim_results, []),
          spfResults: json(x.spf_results, []),
        });
      }
    }
    return [...reports.values()];
  }

  async dmarcReportSource(id: number) {
    const [row] = await this.pool.query<Row[]>(
      'SELECT raw_xml, src_from, src_subject, src_filename, src_mailbox FROM dmarc_reports WHERE id = ?',
      [id],
    );
    if (!row) return null;
    return {
      raw: String(row.raw_xml),
      from: row.src_from ?? null,
      subject: row.src_subject ?? null,
      filename: row.src_filename ?? null,
      mailbox: row.src_mailbox ?? null,
    };
  }

  /** DKIM selectors seen for a domain in aggregate reports of the last `days` days. */
  async dmarcSelectors(domain: string, days: number): Promise<string[]> {
    const rows = await this.pool.query<Row[]>(
      `SELECT x.dkim_results FROM dmarc_records x JOIN dmarc_reports r ON r.id = x.report_ref
       WHERE r.day >= UTC_DATE() - INTERVAL ? DAY AND x.dkim_results LIKE ?`,
      [days, `%${domain.replace(/[%_\\]/g, '\\$&')}%`],
    );
    const out = new Set<string>();
    for (const r of rows) {
      for (const d of json<{ domain: string; selector?: string | null }[]>(r.dkim_results, [])) {
        if (d.selector && d.domain === domain) out.add(d.selector.toLowerCase());
      }
    }
    return [...out];
  }

  // --- DMARC failure reports ----------------------------------------------------------

  async insertFailureReport(r: NormalizedFailureReport & { key: string }, src: ReportSrc): Promise<boolean> {
    const res = await this.pool.query(
      `INSERT INTO failure_reports
         (msg_key, reporter, received_at, feedback_type, auth_failure, reported_domain, source_ip, arrival_date,
          original_mail_from, original_rcpt_to, dkim_domain, dkim_selector, delivery_result, identity_alignment,
          authentication_results, header_from, subject, fields, headers, src_subject, src_mailbox, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())
       ON DUPLICATE KEY UPDATE id = id`,
      [
        r.key,
        clip(src.from, 320),
        dbTime(src.receivedAt),
        clip(r.feedbackType, 32),
        clip(r.authFailure, 64),
        clip(r.reportedDomain, 253),
        clip(r.sourceIp, 64),
        clip(r.arrivalDate, 128),
        clip(r.originalMailFrom, 320),
        clip(r.originalRcptTo, 320),
        clip(r.dkimDomain, 253),
        clip(r.dkimSelector, 128),
        clip(r.deliveryResult, 32),
        clip(r.identityAlignment, 64),
        r.authenticationResults,
        clip(r.headerFrom, 512),
        r.subject,
        JSON.stringify(r.fields),
        r.headers,
        src.subject,
        clip(src.mailbox, 191),
      ],
    );
    return Boolean(res.insertId);
  }

  async failureReports(f: Filters, limit = 500): Promise<FailureReport[]> {
    const { where, params } = dayFilters(f, 'DATE(received_at)', 'reported_domain', 'reporter');
    const rows = await this.pool.query<Row[]>(
      `SELECT * FROM failure_reports ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
       ORDER BY received_at DESC, id DESC LIMIT ?`,
      [...params, limit],
    );
    return rows.map(toFailure);
  }

  async failureReport(id: number): Promise<FailureReportDetail | null> {
    const [r] = await this.pool.query<Row[]>('SELECT * FROM failure_reports WHERE id = ?', [id]);
    if (!r) return null;
    return {
      ...toFailure(r),
      fields: json(r.fields, []),
      headers: r.headers ?? null,
      source: {
        from: r.reporter ?? null,
        subject: r.src_subject ?? null,
        filename: null,
        mailbox: r.src_mailbox ?? null,
      },
    };
  }

  // --- Delivery probes ------------------------------------------------------------------

  async createProbe(p: { token: string; sender: string; recipient: string; sentAt: string }): Promise<number> {
    const res = await this.pool.query(
      `INSERT INTO probes (token, sender, recipient, sent_at, status) VALUES (?, ?, ?, ?, 'sending')`,
      [p.token, p.sender, clip(p.recipient, 255), dbTime(p.sentAt)],
    );
    return Number(res.insertId);
  }

  async updateProbe(
    id: number,
    u: Partial<{
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
    }>,
  ): Promise<void> {
    const cols: string[] = [];
    const params: unknown[] = [];
    const set = (c: string, v: unknown) => {
      cols.push(`${c} = ?`);
      params.push(v);
    };
    if (u.status !== undefined) set('status', u.status);
    if (u.smtpResponse !== undefined) set('smtp_response', u.smtpResponse);
    if (u.error !== undefined) set('error', u.error);
    if (u.receivedAt !== undefined) set('received_at', dbTime(u.receivedAt));
    if (u.folder !== undefined) set('folder', clip(u.folder, 255));
    if (u.latencySeconds !== undefined) set('latency_seconds', u.latencySeconds);
    if (u.auth !== undefined) set('auth', u.auth === null ? null : JSON.stringify(u.auth));
    if (u.clientIp !== undefined) set('client_ip', clip(u.clientIp, 64));
    if (u.dkimSelectors !== undefined) set('dkim_selectors', JSON.stringify(u.dkimSelectors));
    if (u.headers !== undefined) set('headers', u.headers);
    if (!cols.length) return;
    await this.pool.query(`UPDATE probes SET ${cols.join(', ')} WHERE id = ?`, [...params, id]);
  }

  /** Probes sent and not found yet. */
  async pendingProbes(): Promise<DeliveryProbe[]> {
    const rows = await this.pool.query<Row[]>("SELECT * FROM probes WHERE status = 'sent' ORDER BY sent_at");
    return rows.map((r) => toProbe(r));
  }

  /** Probes stuck in "sending" (the process died while sending) become send failures. */
  async failStaleSending(olderThanMinutes: number): Promise<void> {
    await this.pool.query(
      `UPDATE probes SET status = 'send-failed', error = COALESCE(error, 'interrupted while sending')
       WHERE status = 'sending' AND sent_at < UTC_TIMESTAMP() - INTERVAL ? MINUTE`,
      [olderThanMinutes],
    );
  }

  async lastSentAt(sender: string): Promise<string | null> {
    const [row] = await this.pool.query<Row[]>('SELECT MAX(sent_at) AS t FROM probes WHERE sender = ?', [sender]);
    return iso(row?.t);
  }

  async probes(opts: {
    sinceDays: number;
    sender?: string;
    recipient?: string;
    limit?: number;
  }): Promise<DeliveryProbe[]> {
    const where = ['sent_at >= UTC_TIMESTAMP() - INTERVAL ? DAY'];
    const params: unknown[] = [opts.sinceDays];
    if (opts.sender) {
      where.push('sender = ?');
      params.push(opts.sender);
    }
    if (opts.recipient) {
      where.push('recipient = ?');
      params.push(opts.recipient);
    }
    const rows = await this.pool.query<Row[]>(
      `SELECT * FROM probes WHERE ${where.join(' AND ')} ORDER BY sent_at DESC, id DESC LIMIT ?`,
      [...params, opts.limit ?? 5000],
    );
    return rows.map((r) => toProbe(r));
  }

  async probeByToken(token: string): Promise<DeliveryProbe | null> {
    const [row] = await this.pool.query<Row[]>('SELECT * FROM probes WHERE token = ?', [token]);
    return row ? toProbe(row) : null;
  }

  async probe(id: number): Promise<DeliveryProbe | null> {
    const [row] = await this.pool.query<Row[]>('SELECT * FROM probes WHERE id = ?', [id]);
    return row ? toProbe(row, true) : null;
  }

  /** The latest finished probe of every sender/recipient pair. */
  async latestProbes(): Promise<DeliveryProbe[]> {
    const rows = await this.pool.query<Row[]>(
      `SELECT p.* FROM probes p
       JOIN (SELECT sender, recipient, MAX(sent_at) AS t FROM probes WHERE status NOT IN ('sending', 'sent') GROUP BY sender, recipient) l
         ON l.sender = p.sender AND l.recipient = p.recipient AND l.t = p.sent_at
       WHERE p.status NOT IN ('sending', 'sent')`,
    );
    return rows.map((r) => toProbe(r));
  }

  /** DKIM selectors and client IPs seen in delivered probes of a sender domain. */
  async probeFacts(sender: string, days: number): Promise<{ selectors: string[]; ips: string[] }> {
    const rows = await this.pool.query<Row[]>(
      `SELECT dkim_selectors, client_ip FROM probes
       WHERE sender = ? AND status IN ('inbox', 'spam') AND sent_at >= UTC_TIMESTAMP() - INTERVAL ? DAY`,
      [sender, days],
    );
    const sel = new Set<string>();
    const ips = new Set<string>();
    for (const r of rows) {
      for (const s of json<string[]>(r.dkim_selectors, [])) sel.add(s.toLowerCase());
      if (r.client_ip) ips.add(r.client_ip);
    }
    return { selectors: [...sel], ips: [...ips] };
  }

  async purgeProbes(days: number): Promise<void> {
    if (days > 0) await this.pool.query('DELETE FROM probes WHERE sent_at < UTC_TIMESTAMP() - INTERVAL ? DAY', [days]);
  }

  // --- Alerts ---------------------------------------------------------------------

  async openAlerts(): Promise<AlertState[]> {
    const rows = await this.pool.query<Row[]>(
      `SELECT a.*, s.until AS snoozed_until FROM alerts a ${SNOOZE_JOIN} WHERE a.resolved_at IS NULL ORDER BY a.started_at`,
    );
    return rows.map(toAlert);
  }

  async alert(id: number): Promise<Alert | null> {
    const [row] = await this.pool.query<Row[]>(
      `SELECT a.*, s.until AS snoozed_until FROM alerts a ${SNOOZE_JOIN} WHERE a.id = ?`,
      [id],
    );
    return row ? toAlert(row) : null;
  }

  async listAlerts(opts: { active?: boolean; since?: string; limit?: number; domain?: string } = {}): Promise<Alert[]> {
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.active) where.push('a.resolved_at IS NULL');
    if (opts.since) {
      where.push('(a.resolved_at IS NULL OR a.resolved_at >= ?)');
      params.push(dbTime(opts.since));
    }
    if (opts.domain) {
      where.push('a.domain = ?');
      params.push(opts.domain);
    }
    const rows = await this.pool.query<Row[]>(
      `SELECT a.*, s.until AS snoozed_until FROM alerts a ${SNOOZE_JOIN}
       ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
       ORDER BY a.resolved_at IS NULL DESC, a.started_at DESC LIMIT ?`,
      [...params, opts.limit ?? 500],
    );
    return rows.map(toAlert);
  }

  async openAlert(a: AlertWrite, at: string): Promise<number> {
    const res = await this.pool.query(
      `INSERT INTO alerts (k, kind, code, domain, subject, title, severity, detail, refs, started_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        a.key,
        a.kind,
        clip(a.code, 64),
        a.domain,
        clip(a.subject, 255),
        clip(a.title, 255),
        a.severity,
        a.detail,
        JSON.stringify(a.refs),
        dbTime(at),
        dbTime(at),
      ],
    );
    return Number(res.insertId);
  }

  /** Records that an open alert is still active; title, severity and detail follow the latest finding. */
  async touchAlert(id: number, a: AlertWrite, at: string): Promise<void> {
    await this.pool.query(
      'UPDATE alerts SET last_seen_at = ?, title = ?, severity = ?, detail = ?, refs = ? WHERE id = ?',
      [dbTime(at), clip(a.title, 255), a.severity, a.detail, JSON.stringify(a.refs), id],
    );
  }

  async resolveAlert(id: number, at: string, opts: { silent?: boolean } = {}): Promise<void> {
    await this.pool.query(
      `UPDATE alerts SET resolved_at = ?, notified_resolve_at = IF(?, ?, notified_resolve_at)
       WHERE id = ? AND resolved_at IS NULL`,
      [dbTime(at), Boolean(opts.silent), dbTime(at), id],
    );
  }

  /** Acknowledges an open alert; returns false when it is resolved or already acknowledged. */
  async ackAlert(id: number, by: string | null): Promise<boolean> {
    const res = await this.pool.query(
      'UPDATE alerts SET acked_at = UTC_TIMESTAMP(), acked_by = ? WHERE id = ? AND resolved_at IS NULL AND acked_at IS NULL',
      [clip(by, 320), id],
    );
    return Number(res.affectedRows) > 0;
  }

  /** Marks an alert as never announced (snoozed, below the Telegram threshold): its end is not announced either. */
  async silenceAlert(id: number): Promise<void> {
    await this.pool.query(
      'UPDATE alerts SET silenced = TRUE, notified_start_at = COALESCE(notified_start_at, UTC_TIMESTAMP()) WHERE id = ?',
      [id],
    );
  }

  /** Alerts whose start or resolution has not been announced yet. */
  async alertsToNotify(since: string): Promise<AlertState[]> {
    const rows = await this.pool.query<Row[]>(
      `SELECT a.*, s.until AS snoozed_until FROM alerts a ${SNOOZE_JOIN}
       WHERE (a.resolved_at IS NULL AND a.notified_start_at IS NULL AND a.started_at >= ?)
          OR (a.resolved_at >= ? AND a.notified_start_at IS NOT NULL AND a.notified_resolve_at IS NULL)
       ORDER BY a.started_at`,
      [dbTime(since), dbTime(since)],
    );
    return rows.map(toAlert);
  }

  async markNotified(id: number, what: 'start' | 'resolve'): Promise<void> {
    await this.pool.query(
      what === 'start'
        ? 'UPDATE alerts SET notified_start_at = COALESCE(notified_start_at, UTC_TIMESTAMP()) WHERE id = ?'
        : 'UPDATE alerts SET notified_resolve_at = UTC_TIMESTAMP() WHERE id = ?',
      [id],
    );
  }

  // --- Snoozes --------------------------------------------------------------------

  async snooze(key: string, title: string, minutes: number, by: string | null): Promise<void> {
    await this.pool.query(
      `INSERT INTO snoozes (k, title, until, created_by, created_at)
       VALUES (?, ?, UTC_TIMESTAMP() + INTERVAL ? MINUTE, ?, UTC_TIMESTAMP())
       ON DUPLICATE KEY UPDATE until = VALUES(until), created_by = VALUES(created_by), created_at = VALUES(created_at),
         title = VALUES(title)`,
      [key, clip(title, 255), minutes, clip(by, 320)],
    );
  }

  async unsnooze(key: string): Promise<boolean> {
    const res = await this.pool.query('DELETE FROM snoozes WHERE k = ?', [key]);
    return Number(res.affectedRows) > 0;
  }

  /** Active snoozes (expired ones are deleted). */
  async snoozes(): Promise<Snooze[]> {
    await this.pool.query('DELETE FROM snoozes WHERE until <= UTC_TIMESTAMP()');
    const rows = await this.pool.query<Row[]>('SELECT * FROM snoozes ORDER BY until');
    return rows.map((r) => ({
      key: r.k,
      title: r.title,
      until: iso(r.until)!,
      createdBy: r.created_by ?? null,
      createdAt: iso(r.created_at)!,
    }));
  }

  // --- OIDC sessions ---------------------------------------------------------------

  /** Expiry is computed with the database clock, like every other session time check. */
  async createSession(tokenHash: string, s: SessionRecord, ttlSeconds: number): Promise<void> {
    await this.pool.query(
      `INSERT INTO sessions (token_hash, sub, email, name, can_edit, id_token, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL ? SECOND)`,
      [tokenHash, clip(s.sub, 255), clip(s.email, 320), clip(s.name, 255), s.canEdit, s.idToken, ttlSeconds],
    );
  }

  async getSession(tokenHash: string): Promise<SessionRecord | null> {
    const [row] = await this.pool.query<Row[]>(
      'SELECT sub, email, name, can_edit, id_token FROM sessions WHERE token_hash = ? AND expires_at > UTC_TIMESTAMP()',
      [tokenHash],
    );
    if (!row) return null;
    return { sub: row.sub, email: row.email, name: row.name, canEdit: Boolean(row.can_edit), idToken: row.id_token };
  }

  async deleteSession(tokenHash: string): Promise<SessionRecord | null> {
    const [row] = await this.pool.query<Row[]>(
      'DELETE FROM sessions WHERE token_hash = ? RETURNING sub, email, name, can_edit, id_token',
      [tokenHash],
    );
    if (!row) return null;
    return { sub: row.sub, email: row.email, name: row.name, canEdit: Boolean(row.can_edit), idToken: row.id_token };
  }

  async createLogin(state: string, l: PendingLogin): Promise<void> {
    await this.pool.query(
      'INSERT INTO oidc_logins (state, code_verifier, nonce, return_to, created_at) VALUES (?, ?, ?, ?, UTC_TIMESTAMP())',
      [state, l.codeVerifier, l.nonce, clip(l.returnTo, 2048)],
    );
  }

  /** Consumes a pending login (single use); logins expire after 10 minutes. */
  async takeLogin(state: string): Promise<PendingLogin | null> {
    const [row] = await this.pool.query<Row[]>(
      `DELETE FROM oidc_logins WHERE state = ? AND created_at > UTC_TIMESTAMP() - INTERVAL 10 MINUTE
       RETURNING code_verifier, nonce, return_to`,
      [state],
    );
    return row ? { codeVerifier: row.code_verifier, nonce: row.nonce, returnTo: row.return_to } : null;
  }

  async purgeExpiredAuth(): Promise<void> {
    await this.pool.query('DELETE FROM sessions WHERE expires_at <= UTC_TIMESTAMP()');
    await this.pool.query('DELETE FROM oidc_logins WHERE created_at <= UTC_TIMESTAMP() - INTERVAL 10 MINUTE');
  }
}
