import { getServers } from 'node:dns';
import { hostname } from 'node:os';
import { resolve } from 'node:path';

type Env = Record<string, string | undefined>;

function str(name: string, fallback?: string, env: Env = process.env): string | undefined {
  const v = env[name]?.trim();
  return v ? v : fallback;
}

function int(name: string, fallback: number, env: Env = process.env): number {
  const v = str(name, undefined, env);
  if (v === undefined) return fallback;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) throw new Error(`${name} must be an integer, got "${v}"`);
  return n;
}

function bool(name: string, fallback: boolean, env: Env = process.env): boolean {
  const v = str(name, undefined, env)?.toLowerCase();
  if (v === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(v);
}

function list(name: string, fallback = '', env: Env = process.env): string[] {
  const raw = env[name] === undefined ? fallback : (env[name] ?? '');
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Client authentication methods at the token endpoint (RFC 8414 names). */
export const TOKEN_AUTH_METHODS = ['client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'none'] as const;
export type TokenAuthMethod = (typeof TOKEN_AUTH_METHODS)[number];

export type ImapAuth =
  | { kind: 'password'; user: string; pass: string }
  | {
      kind: 'oauth2';
      user: string;
      tokenUrl: string;
      clientId: string;
      clientSecret: string | null;
      refreshToken: string;
      scope: string | null;
    };

export interface ImapConfig {
  host: string;
  port: number;
  /** Implicit TLS (993); STARTTLS otherwise. */
  secure: boolean;
  rejectUnauthorized: boolean;
  auth: ImapAuth;
}

export interface SmtpConfig {
  host: string;
  port: number;
  /** Implicit TLS (465); STARTTLS is required otherwise. */
  secure: boolean;
  user: string;
  pass: string;
  rejectUnauthorized: boolean;
}

export interface DomainConfig {
  /** The n in DOMAIN_<n>_…; fixes the order. */
  n: number;
  name: string;
  /** DKIM selectors to check besides the common ones and those seen in reports and probes. */
  dkimSelectors: string[];
  /** Outbound IPs to check against blocklists (besides those seen in delivery tests). */
  senderIps: string[];
  /** SMTP submission for delivery tests; null = the domain is only checked, not used to send. */
  smtp: SmtpConfig | null;
  from: string | null;
  sendIntervalMinutes: number;
}

export interface RecipientConfig {
  n: number;
  name: string;
  address: string;
  imap: ImapConfig;
  /** Folders searched for probes; null = INBOX plus the special-use \Junk folder. */
  folders: string[] | null;
  /** Leave found probes in the mailbox instead of moving them to the trash. */
  keepMessages: boolean;
}

export interface MailboxConfig {
  n: number;
  /** Stable key of the mailbox in the database: user@host/folder. */
  key: string;
  name: string;
  address: string | null;
  imap: ImapConfig;
  folder: string;
  maxMessageSize: number;
  /** Opt-in cleanup: delete imported messages sent more than this many months ago; 0 = never. */
  deleteAfterMonths: number;
  deleteDryRun: boolean;
}

const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const ADDRESS_RE = /^[^\s@]+@[^\s@]+$/;

export const isHostname = (s: string) => HOST_RE.test(s);

/** The numbers n for which some <PREFIX>_<n>_* variable is set, in ascending order. */
function numbers(env: Env, prefix: string): number[] {
  const ns = new Set<number>();
  const re = new RegExp(`^${prefix}_(\\d+)_[A-Z0-9_]+$`);
  for (const key of Object.keys(env)) {
    const m = re.exec(key);
    if (m && env[key]?.trim()) ns.add(Number(m[1]));
  }
  return [...ns].sort((a, b) => a - b);
}

/** IMAP settings of a numbered block (RECIPIENT_<n>_IMAP…, MAILBOX_<n>_IMAP…). */
function imapConfig(p: string, env: Env): ImapConfig {
  const get = (k: string) => str(`${p}_${k}`, undefined, env);
  const host = get('IMAPHOST');
  const user = get('IMAPUSER');
  if (!host) throw new Error(`${p}_IMAPHOST is required`);
  if (!user) throw new Error(`${p}_IMAPUSER is required`);
  const port = int(`${p}_IMAPPORT`, 993, env);
  const pass = get('IMAPPASSWORD') ?? get('IMAPPASS');
  const refreshToken = get('OAUTH_REFRESH_TOKEN');
  let auth: ImapAuth;
  if (refreshToken) {
    const tokenUrl = get('OAUTH_TOKEN_URL');
    const clientId = get('OAUTH_CLIENT_ID');
    if (!tokenUrl || !clientId) {
      throw new Error(`${p}: OAuth2 needs ${p}_OAUTH_TOKEN_URL, ${p}_OAUTH_CLIENT_ID and ${p}_OAUTH_REFRESH_TOKEN`);
    }
    if (pass) throw new Error(`${p}: configure either a password or OAuth2, not both`);
    auth = {
      kind: 'oauth2',
      user,
      tokenUrl,
      clientId,
      clientSecret: get('OAUTH_CLIENT_SECRET') ?? null,
      refreshToken,
      scope: get('OAUTH_SCOPE') ?? null,
    };
  } else {
    if (!pass) throw new Error(`${p}_IMAPPASSWORD (or ${p}_IMAPPASS, or OAuth2 settings) is required`);
    auth = { kind: 'password', user, pass };
  }
  return {
    host,
    port,
    secure: bool(`${p}_IMAPTLS`, port === 993, env),
    rejectUnauthorized: bool(`${p}_TLS_REJECT_UNAUTHORIZED`, true, env),
    auth,
  };
}

/**
 * Reads DOMAIN_<n>_* variables. Numbers need not be contiguous; domains are ordered by n.
 * The SMTP settings are optional, but all or none of them must be given.
 */
export function parseDomains(env: Env, defaultInterval: number): DomainConfig[] {
  const out: DomainConfig[] = [];
  for (const n of numbers(env, 'DOMAIN')) {
    const p = `DOMAIN_${n}`;
    const get = (k: string) => str(`${p}_${k}`, undefined, env);
    const name = get('NAME')?.toLowerCase().replace(/\.$/, '');
    if (!name) throw new Error(`${p}_NAME is required (the domain, e.g. example.com)`);
    if (!isHostname(name)) throw new Error(`${p}_NAME must be a domain name, got "${name}"`);
    if (out.some((d) => d.name === name)) throw new Error(`${p}_NAME: domain "${name}" is configured twice`);

    const host = get('SMTPHOST');
    const user = get('SMTPUSER');
    const pass = get('SMTPPASSWORD') ?? get('SMTPPASS');
    let smtp: SmtpConfig | null = null;
    if (host || user || pass) {
      if (!host || !user || !pass) {
        throw new Error(`${p}: SMTPHOST, SMTPUSER and SMTPPASS must be set together (or none of them)`);
      }
      const port = int(`${p}_SMTPPORT`, 465, env);
      smtp = {
        host,
        port,
        secure: bool(`${p}_SMTPTLS`, port === 465, env),
        user,
        pass,
        rejectUnauthorized: bool(`${p}_TLS_REJECT_UNAUTHORIZED`, true, env),
      };
    }
    const from = get('FROM') ?? (user && ADDRESS_RE.test(user) ? user : null);
    if (smtp && !from) throw new Error(`${p}_FROM is required when ${p}_SMTPUSER is not an e-mail address`);
    if (from && !ADDRESS_RE.test(from)) throw new Error(`${p}_FROM must be an e-mail address, got "${from}"`);
    const interval = int(`${p}_SEND_INTERVAL_MINUTES`, defaultInterval, env);
    if (smtp && interval < 5 && interval !== 0) {
      throw new Error(`${p}_SEND_INTERVAL_MINUTES must be 0 (off) or at least 5`);
    }
    out.push({
      n,
      name,
      dkimSelectors: list(`${p}_DKIM_SELECTORS`, '', env).map((s) => s.toLowerCase()),
      senderIps: list(`${p}_SENDER_IPS`, '', env),
      smtp,
      from,
      sendIntervalMinutes: interval,
    });
  }
  return out;
}

export function parseRecipients(env: Env): RecipientConfig[] {
  const out: RecipientConfig[] = [];
  for (const n of numbers(env, 'RECIPIENT')) {
    const p = `RECIPIENT_${n}`;
    const imap = imapConfig(p, env);
    const address = str(`${p}_ADDRESS`, undefined, env) ?? imap.auth.user;
    if (!ADDRESS_RE.test(address)) {
      throw new Error(`${p}_ADDRESS is required when ${p}_IMAPUSER is not an e-mail address`);
    }
    const name = str(`${p}_NAME`, undefined, env) ?? address;
    if (out.some((r) => r.name === name)) throw new Error(`${p}_NAME: recipient "${name}" is configured twice`);
    const folders = list(`${p}_FOLDERS`, '', env);
    out.push({
      n,
      name,
      address: address.toLowerCase(),
      imap,
      folders: folders.length ? folders : null,
      keepMessages: bool(`${p}_KEEP_MESSAGES`, false, env),
    });
  }
  return out;
}

export function parseMailboxes(env: Env): MailboxConfig[] {
  const out: MailboxConfig[] = [];
  for (const n of numbers(env, 'MAILBOX')) {
    const p = `MAILBOX_${n}`;
    const imap = imapConfig(p, env);
    const folder = str(`${p}_FOLDER`, 'INBOX', env)!;
    const key = `${imap.auth.user}@${imap.host}/${folder}`.slice(0, 191);
    if (out.some((m) => m.key === key)) throw new Error(`${p}: mailbox ${key} is configured twice`);
    const address = str(`${p}_ADDRESS`, undefined, env) ?? (ADDRESS_RE.test(imap.auth.user) ? imap.auth.user : null);
    const months = int(`${p}_DELETE_AFTER_MONTHS`, 0, env);
    if (months < 0) throw new Error(`${p}_DELETE_AFTER_MONTHS must be 0 (never delete) or a positive number`);
    out.push({
      n,
      key,
      name: str(`${p}_NAME`, undefined, env) ?? address ?? key,
      address: address?.toLowerCase() ?? null,
      imap,
      folder,
      maxMessageSize: int(`${p}_MAX_MESSAGE_BYTES`, 25 * 1024 * 1024, env),
      deleteAfterMonths: months,
      deleteDryRun: bool(`${p}_DELETE_DRY_RUN`, false, env),
    });
  }
  return out;
}

function validTimezone(tz: string): string {
  try {
    new Intl.DateTimeFormat('en', { timeZone: tz });
    return tz;
  } catch {
    throw new Error(`TIMEZONE must be an IANA time zone such as Europe/Oslo, got "${tz}"`);
  }
}

/** DNS_RESOLVERS: IP addresses (optionally ip:port), or "system" for the operating system's resolvers. */
function resolvers(env: Env): string[] {
  const v = list('DNS_RESOLVERS', '1.1.1.1,8.8.8.8', env);
  if (v.length === 1 && v[0]!.toLowerCase() === 'system') return getServers();
  return v;
}

/** Common DKIM selectors tried for every domain (DKIM selectors cannot be listed from DNS). */
export const COMMON_SELECTORS = [
  'default',
  'dkim',
  'mail',
  'selector1',
  'selector2',
  'google',
  's1',
  's2',
  'k1',
  'k2',
  'key1',
  'smtp',
  'mx',
  'everlytickey1',
  'mandrill',
  'mailjet',
  'sendgrid',
  'zoho',
  'protonmail',
  'fm1',
  'fm2',
  'fm3',
];

/** Blocklists queried for MX and sender IPs, and for the domain itself (RFC 5782). */
export const DEFAULT_IP_ZONES = ['zen.spamhaus.org', 'bl.spamcop.net', 'psbl.surriel.com', 'bl.mailspike.net'];
export const DEFAULT_DOMAIN_ZONES = ['dbl.spamhaus.org', 'multi.surbl.org'];

export function loadConfig(env: Env = process.env) {
  const pub = str('PUBLIC_URL', undefined, env)?.replace(/\/+$/, '');
  const interval = int('DELIVERY_INTERVAL_MINUTES', 60, env);
  return {
    domains: parseDomains(env, interval),
    recipients: parseRecipients(env),
    mailboxes: parseMailboxes(env),
    /** Serves the data already in the database (npm run demo): no checks, syncs or sending. */
    demo: bool('MAILWATCH_DEMO', false, env),
    db: {
      host: str('DB_HOST', '127.0.0.1', env)!,
      port: int('DB_PORT', 3306, env),
      user: str('DB_USER', 'mailwatch', env)!,
      password: str('DB_PASSWORD', undefined, env),
      database: str('DB_NAME', 'mailwatch', env)!,
      connectionLimit: int('DB_POOL_SIZE', 5, env),
      ssl: bool('DB_TLS', false, env),
    },
    http: {
      host: str('LISTEN_HOST', '127.0.0.1', env)!,
      port: int('PORT', 3000, env),
      /** External origin (scheme + host), used for the OIDC redirect URI and links in alerts. */
      publicUrl: pub,
    },
    oidc: {
      issuer: str('OIDC_ISSUER', undefined, env),
      clientId: str('OIDC_CLIENT_ID', undefined, env),
      clientSecret: str('OIDC_CLIENT_SECRET', undefined, env),
      /** Must match the client registration at the provider; "none" = public client. */
      tokenAuthMethod: str('OIDC_TOKEN_AUTH_METHOD', 'client_secret_basic', env)!.toLowerCase() as TokenAuthMethod,
      scopes: str('OIDC_SCOPES', 'openid profile email', env)!,
      /** Members of at least one of these groups may open the dashboard. Required. */
      allowedGroups: list('OIDC_ALLOWED_GROUPS', '', env),
      /** Members may change settings; empty = every allowed user may. */
      editorGroups: list('OIDC_EDITOR_GROUPS', '', env),
      groupsClaim: str('OIDC_GROUPS_CLAIM', 'groups', env)!,
      sessionTtlHours: int('SESSION_TTL_HOURS', 12, env),
      /** Development only: allow an http:// issuer (e.g. a local mock provider). */
      allowInsecureIssuer: bool('OIDC_ALLOW_INSECURE_ISSUER', false, env),
    },
    telegram: {
      token: str('TELEGRAM_TOKEN', undefined, env),
      chatId: str('TELEGRAM_CHAT_ID', undefined, env),
      /** Topic in a forum supergroup (message_thread_id), optional. */
      threadId: str('TELEGRAM_THREAD_ID', undefined, env),
    },
    checks: {
      /** How often every domain is checked. 0 = manual only. */
      intervalMinutes: int('CHECK_INTERVAL_MINUTES', 15, env),
      /** Domains checked in parallel. */
      concurrency: int('CHECK_CONCURRENCY', 4, env),
      resolvers: resolvers(env),
      dnsTimeoutMs: int('DNS_TIMEOUT_MS', 4000, env),
      /** Connect to every MX on port 25 (STARTTLS, certificate, DANE). */
      smtpProbe: bool('SMTP_PROBE', true, env),
      smtpTimeoutMs: int('SMTP_PROBE_TIMEOUT_MS', 20_000, env),
      /** The name sent in EHLO. */
      heloName: str('SMTP_HELO_NAME', undefined, env) ?? (pub ? new URL(pub).hostname : hostname()),
      commonSelectors: list('DKIM_COMMON_SELECTORS', COMMON_SELECTORS.join(','), env).map((s) => s.toLowerCase()),
      ipZones: list('DNSBL_ZONES', DEFAULT_IP_ZONES.join(','), env),
      domainZones: list('DNSBL_DOMAIN_ZONES', DEFAULT_DOMAIN_ZONES.join(','), env),
      /** Certificates expiring within this many days are a warning (within 7 days an error). */
      certWarnDays: int('CERT_WARN_DAYS', 21, env),
      httpTimeoutMs: int('HTTP_TIMEOUT_MS', 10_000, env),
    },
    reports: {
      /** How often the report mailboxes are synced. 0 = manual / CLI only. */
      intervalMinutes: int('REPORT_SYNC_INTERVAL_MINUTES', 30, env),
      /** Report findings (and their alerts) look at this many days. */
      analysisDays: int('REPORT_ANALYSIS_DAYS', 7, env),
    },
    delivery: {
      intervalMinutes: interval,
      /** A probe not found in any recipient folder after this long is "lost". */
      timeoutMinutes: int('DELIVERY_TIMEOUT_MINUTES', 30, env),
      /** How often the recipient mailboxes are searched while probes are pending. */
      pollSeconds: int('DELIVERY_POLL_SECONDS', 60, env),
      /** Probes older than this are deleted from the database; 0 keeps everything. */
      retentionDays: int('DELIVERY_RETENTION_DAYS', 90, env),
    },
    alerts: {
      /** A check finding must be seen in this many consecutive checks before it alerts. */
      confirmations: int('ALERT_CONFIRMATIONS', 2, env),
    },
    /** Times in the UI and in alerts. */
    timezone: validTimezone(str('TIMEZONE', 'UTC', env)!),
    // Relative to this file, so the bundle works whatever the working directory is.
    staticDir: resolve(str('STATIC_DIR', undefined, env) ?? resolve(import.meta.dirname, '../../dist/web')),
  };
}

export type Config = ReturnType<typeof loadConfig>;

export const config: Config = loadConfig();

export function telegramConfigured(cfg: Config = config): boolean {
  return Boolean(cfg.telegram.token && cfg.telegram.chatId);
}

/**
 * Fails fast on configuration that would otherwise break later. The web server always
 * requires OIDC login; `server: false` is for CLI tools that never serve HTTP.
 */
export function validateConfig({ server }: { server: boolean }, cfg: Config = config): void {
  const missing: string[] = [];
  if (!cfg.db.password) missing.push('DB_PASSWORD');
  if (server) {
    if (!cfg.oidc.issuer) missing.push('OIDC_ISSUER');
    if (!cfg.oidc.clientId) missing.push('OIDC_CLIENT_ID');
    if (!cfg.oidc.allowedGroups.length) missing.push('OIDC_ALLOWED_GROUPS');
    if (!cfg.http.publicUrl) missing.push('PUBLIC_URL');
  }
  if (server && cfg.oidc.tokenAuthMethod !== 'none' && !cfg.oidc.clientSecret) missing.push('OIDC_CLIENT_SECRET');
  if (missing.length) {
    throw new Error(`missing required configuration: ${missing.join(', ')} (login via OIDC is mandatory)`);
  }
  if (Boolean(cfg.telegram.token) !== Boolean(cfg.telegram.chatId)) {
    throw new Error('TELEGRAM_TOKEN and TELEGRAM_CHAT_ID must be set together');
  }
  if (!cfg.checks.resolvers.length) throw new Error('DNS_RESOLVERS is empty');
  if (cfg.checks.concurrency < 1) throw new Error('CHECK_CONCURRENCY must be at least 1');
  if (cfg.alerts.confirmations < 1) throw new Error('ALERT_CONFIRMATIONS must be at least 1');
  if (cfg.delivery.timeoutMinutes < 1) throw new Error('DELIVERY_TIMEOUT_MINUTES must be at least 1');
  if (cfg.delivery.pollSeconds < 15) throw new Error('DELIVERY_POLL_SECONDS must be at least 15');
  if (server) {
    const method = cfg.oidc.tokenAuthMethod;
    if (!TOKEN_AUTH_METHODS.includes(method)) {
      throw new Error(`OIDC_TOKEN_AUTH_METHOD must be one of ${TOKEN_AUTH_METHODS.join(', ')}, got "${method}"`);
    }
    if (method === 'none' && cfg.oidc.clientSecret) {
      throw new Error('OIDC_CLIENT_SECRET is set but OIDC_TOKEN_AUTH_METHOD is "none" (public client)');
    }
    const u = new URL(cfg.http.publicUrl!);
    if (u.pathname !== '/' || u.search) {
      throw new Error('PUBLIC_URL must be an origin without a path, e.g. https://mailwatch.example.com');
    }
  }
}
