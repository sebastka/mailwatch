import { readFileSync } from 'node:fs';
import mariadb from 'mariadb';
import type { CheckKind, CheckResult } from '../src/shared/types.ts';
import { runDomainChecks } from '../src/server/checks/index.ts';
import type { KnownFacts } from '../src/server/checks/util.ts';
import { loadConfig } from '../src/server/config.ts';
import { Store, type TlsReportRow } from '../src/server/db.ts';
import { normalizeReport } from '../src/server/reports/tlsrpt.ts';
import { DnsClient, type DnsResult, normalizeName, type RecordType } from '../src/server/dns.ts';

export const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(new URL(`fixtures/${name}`, import.meta.url), 'utf8'));
export const fixtureText = (name: string): string => readFileSync(new URL(`fixtures/${name}`, import.meta.url), 'utf8');

/** "name TYPE" → records, or a failure such as { rcode: 'SERVFAIL' }. */
export type Zone = Record<string, unknown[] | { rcode: string }>;

/**
 * A DNS client answering from a fixed zone: unknown names are NXDOMAIN, known names without
 * records of the asked type are NODATA. Every answer is "secure" unless listed in `insecure`.
 */
export class FakeDns extends DnsClient {
  private readonly zone: Zone;
  private readonly insecure: Set<string>;
  asked: string[] = [];

  constructor(zone: Zone, insecure: string[] = []) {
    super(['127.0.0.1']);
    this.zone = Object.fromEntries(Object.entries(zone).map(([k, v]) => [k.toLowerCase(), v]));
    this.insecure = new Set(insecure.map((s) => s.toLowerCase()));
  }

  // Overrides the network step only, so that DnsClient's cache works as in production and
  // `asked` lists the questions that would actually be sent.
  protected override async lookup(rawName: string, type: RecordType): Promise<DnsResult<unknown>> {
    const name = normalizeName(rawName);
    this.asked.push(`${name} ${type}`);
    const v = this.zone[`${name} ${type}`.toLowerCase()];
    const secure = !this.insecure.has(name);
    if (v && !Array.isArray(v)) return { name, type, rcode: v.rcode, secure: false, records: [], cnames: [] };
    if (v) return { name, type, rcode: 'NOERROR', secure, records: v, cnames: [] };
    const exists = Object.keys(this.zone).some(
      (k) => k.split(' ')[0] === name || k.split(' ')[0]!.endsWith(`.${name}`),
    );
    return { name, type, rcode: exists ? 'NOERROR' : 'NXDOMAIN', secure, records: [], cnames: [] };
  }
}

export const checksConfig = () => ({
  ...loadConfig({ DB_PASSWORD: 'x' }).checks,
  smtpProbe: false,
  rdap: false,
  nsProbe: false,
  commonSelectors: ['default'],
  ipZones: [],
  domainZones: [],
});

/** Runs every check of a domain against a fake zone (no network, no SMTP probes). */
export async function checkWith(
  zone: Zone,
  domain = 'example.com',
  opts: { known?: Partial<KnownFacts>; selectors?: string[]; insecure?: string[]; previous?: CheckResult[] } = {},
): Promise<Map<CheckKind, CheckResult>> {
  const results = await runDomainChecks(
    { name: domain, dkimSelectors: opts.selectors ?? [], senderIps: [] },
    checksConfig(),
    {
      dns: new FakeDns(zone, opts.insecure),
      known: { reportSelectors: [], probeSelectors: [], probeIps: [], monitoredAddresses: [], ...opts.known },
      previous: opts.previous ?? [],
    },
  );
  return new Map(results.map((r) => [r.check, r]));
}

export const codes = (r: CheckResult | undefined) => (r?.findings ?? []).map((f) => f.code);

const env = process.env;
export const testDb = (suffix = '') => ({
  host: env.TEST_DB_HOST ?? '',
  port: Number(env.TEST_DB_PORT ?? 3306),
  user: env.TEST_DB_USER ?? 'root',
  password: env.TEST_DB_PASSWORD,
  database: `${env.TEST_DB_NAME ?? 'mailwatch_test'}${suffix}`,
});

export async function freshDatabase(cfg: ReturnType<typeof testDb>): Promise<Store> {
  if (!/^\w+$/.test(cfg.database) || !cfg.database.includes('_test'))
    throw new Error('TEST_DB_NAME must contain _test');
  const conn = await mariadb.createConnection({
    host: cfg.host,
    port: cfg.port,
    user: cfg.user,
    password: cfg.password,
  });
  await conn.query(`DROP DATABASE IF EXISTS \`${cfg.database}\``);
  await conn.query(`CREATE DATABASE \`${cfg.database}\` CHARACTER SET utf8mb4`);
  await conn.end();
  return Store.connect(cfg);
}

/** Builds the rows Store.loadTlsReports would return, without a database. */
export function tlsRows(...names: string[]): TlsReportRow[] {
  let pid = 0;
  return names
    .map((name, i) => {
      const r = normalizeReport(fixture(name));
      return {
        id: i + 1,
        org: r.organizationName,
        reportId: r.reportId,
        contactInfo: r.contactInfo,
        start: r.start,
        end: r.end,
        day: r.start.slice(0, 10),
        receivedAt: null,
        policies: r.policies.map((p) => ({ ...p, id: ++pid })),
      };
    })
    .sort((a, b) => a.start.localeCompare(b.start));
}
