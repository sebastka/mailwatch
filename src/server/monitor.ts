// Schedules the three jobs and feeds their results to the alerts:
//   checks    every CHECK_INTERVAL_MINUTES: all DNS/server checks of every domain
//   reports   every REPORT_SYNC_INTERVAL_MINUTES: report mailboxes, then report findings
//   delivery  every minute: send due probes; every DELIVERY_POLL_SECONDS: search recipients
import type { CheckResult, JobStatus } from '../shared/types.ts';
import type { Alerts } from './alerts.ts';
import { newRun, type RunShared, runDomainChecks } from './checks/index.ts';
import { recordSignature } from './checks/signature.ts';
import { mapLimit } from './checks/util.ts';
import type { Config, DomainConfig } from './config.ts';
import type { Store } from './db.ts';
import type { Delivery } from './delivery.ts';
import { reportFindings } from './reports/findings.ts';
import type { ReportSyncer } from './sync.ts';

type Log = (msg: string) => void;

class Job {
  running: Promise<void> | null = null;
  lastRunAt: string | null = null;
  lastSuccessAt: string | null = null;
  lastError: string | null = null;
  nextRunAt: string | null = null;
  timer: NodeJS.Timeout | null = null;
  readonly intervalMinutes: number;

  constructor(intervalMinutes: number) {
    this.intervalMinutes = intervalMinutes;
  }

  status(): JobStatus {
    return {
      running: this.running !== null,
      lastRunAt: this.lastRunAt,
      lastSuccessAt: this.lastSuccessAt,
      lastError: this.lastError,
      nextRunAt: this.nextRunAt,
      intervalMinutes: this.intervalMinutes,
    };
  }

  /** Runs fn, or joins the run in progress. */
  run(fn: () => Promise<void>, log: Log): Promise<void> {
    this.running ??= (async () => {
      this.lastRunAt = new Date().toISOString();
      try {
        await fn();
        this.lastError = null;
        this.lastSuccessAt = new Date().toISOString();
      } catch (e) {
        this.lastError = (e as Error).message;
        log(`failed: ${this.lastError}`);
      }
    })().finally(() => {
      this.running = null;
    });
    return this.running;
  }
}

export class Monitor {
  readonly checks: Job;
  readonly reports: Job;
  readonly delivery: Job;
  private stopping = false;
  private readonly timers: NodeJS.Timeout[] = [];

  private readonly store: Store;
  private readonly cfg: Config;
  private readonly alerts: Alerts;
  private readonly syncer: ReportSyncer;
  private readonly sender: Delivery;
  private readonly log: Log;

  constructor(
    deps: { store: Store; cfg: Config; alerts: Alerts; syncer: ReportSyncer; delivery: Delivery },
    log: Log = (m) => console.log(`[monitor] ${m}`),
  ) {
    this.store = deps.store;
    this.cfg = deps.cfg;
    this.alerts = deps.alerts;
    this.syncer = deps.syncer;
    this.sender = deps.delivery;
    this.log = log;
    this.checks = new Job(this.cfg.checks.intervalMinutes);
    this.reports = new Job(this.cfg.reports.intervalMinutes);
    this.delivery = new Job(this.cfg.delivery.intervalMinutes);
  }

  private get domains(): DomainConfig[] {
    return this.cfg.domains;
  }

  /** Checks all domains (or one). Serialised across replicas. */
  runChecks(only?: string): Promise<void> {
    return this.checks.run(
      async () => {
        const ran = await this.store.withExclusiveLock('mailwatch_checks', async () => {
          const domains = this.domains.filter((d) => !only || d.name === only);
          await this.store.pruneCheckResults(this.domains.map((d) => d.name));
          await this.alerts.pruneDomains(this.domains.map((d) => d.name));
          const monitored = this.cfg.mailboxes.map((m) => m.address).filter((a): a is string => Boolean(a));
          const errors: string[] = [];
          // One set of caches per run: domains sharing MX hosts share their DNS answers and probes.
          const shared = newRun(this.cfg.checks);
          await mapLimit(domains, this.cfg.checks.concurrency, async (d) => {
            if (this.stopping) return;
            try {
              await this.checkDomain(d, monitored, shared);
            } catch (e) {
              errors.push(`${d.name}: ${(e as Error).message}`);
              this.log(errors.at(-1)!);
            }
          });
          await this.alerts.notify();
          if (errors.length) throw new Error(errors.join('; '));
          return true;
        });
        if (ran === null) this.log('another instance is running the checks, skipped');
      },
      (m) => this.log(`checks ${m}`),
    );
  }

  private async checkDomain(d: DomainConfig, monitoredAddresses: string[], shared: RunShared): Promise<CheckResult[]> {
    const [previous, reportSelectors, facts] = await Promise.all([
      this.store.checkResults({ domain: d.name }),
      this.store.dmarcSelectors(d.name, 30),
      this.store.probeFacts(d.name, 30),
    ]);
    const results = await runDomainChecks(
      { name: d.name, dkimSelectors: d.dkimSelectors, senderIps: d.senderIps },
      this.cfg.checks,
      {
        known: { reportSelectors, probeSelectors: facts.selectors, probeIps: facts.ips, monitoredAddresses },
        previous,
        ...shared,
      },
    );
    await this.store.saveCheckResults(results);

    // Log (and announce) changed records. The first check of a domain is not a change.
    const prev = new Map(previous.map((r) => [r.check, r]));
    for (const r of results) {
      const before = prev.get(r.check);
      if (!before) continue;
      const a = recordSignature(before);
      const b = recordSignature(r);
      if (a === undefined || b === undefined || a === b) continue;
      const change = { domain: d.name, check: r.check, at: r.checkedAt, before: a, after: b };
      await this.store.recordChange(change.domain, change.check, change.before, change.after, change.at);
      this.log(`${d.name}: ${r.check} changed`);
      await this.alerts.announceChange(change);
    }
    await this.alerts.checks(d.name, results);
    return results;
  }

  /** Syncs the report mailboxes, then re-evaluates the report findings. */
  runReports(opts: { full?: boolean } = {}): Promise<void> {
    return this.reports.run(
      async () => {
        if (this.cfg.mailboxes.length) await this.syncer.run(opts);
        await this.store.withExclusiveLock(
          'mailwatch_alerts',
          async () => {
            const findings = await reportFindings(
              this.store,
              this.domains.map((d) => d.name),
              this.cfg.reports.analysisDays,
            );
            await this.alerts.reports(findings);
            await this.syncAlerts();
            await this.alerts.notify();
          },
          30,
        );
        if (this.syncer.lastError) throw new Error(this.syncer.lastError);
      },
      (m) => this.log(`reports ${m}`),
    );
  }

  private async syncAlerts(): Promise<void> {
    const mailboxes = (await this.syncer.status())
      .filter((m) => m.lastError)
      .map((m) => ({ code: 'sync.mailbox' as const, subject: m.name, error: m.lastError! }));
    const recipients = [...(await this.sender.recipientErrors())].map(([subject, error]) => ({
      code: 'sync.recipient' as const,
      subject,
      error,
    }));
    await this.alerts.syncs([...mailboxes, ...recipients]);
  }

  /** Sends due probes (or all now, with force), searches the recipients, evaluates the delivery alerts. */
  runDelivery(opts: { force?: boolean; send?: boolean } = {}): Promise<void> {
    return this.delivery.run(
      async () => {
        if (opts.send !== false) await this.sender.sendDue(new Date(), { force: opts.force ?? false });
        await this.sender.poll(new Date());
        await this.store.withExclusiveLock(
          'mailwatch_alerts',
          async () => {
            await this.alerts.delivery(
              await this.store.latestProbes(),
              this.cfg.domains.filter((d) => d.smtp && d.sendIntervalMinutes > 0).map((d) => d.name),
              this.cfg.recipients.map((r) => r.name),
              this.cfg.delivery.timeoutMinutes,
            );
            await this.syncAlerts();
            await this.alerts.notify();
          },
          30,
        );
        if (this.sender.lastError) throw new Error(this.sender.lastError);
      },
      (m) => this.log(`delivery ${m}`),
    );
  }

  /** Starts the schedules; the first runs happen right away (staggered a little). */
  start(): void {
    const every = (ms: number, fn: () => void, firstAfterMs: number) => {
      const first = setTimeout(() => {
        fn();
        const t = setInterval(() => !this.stopping && fn(), ms);
        t.unref();
        this.timers.push(t);
      }, firstAfterMs);
      first.unref();
      this.timers.push(first);
    };
    const schedule = (job: Job, minutes: number, fn: () => Promise<void>, firstAfterMs: number) => {
      if (minutes <= 0) return;
      const tick = () => {
        job.nextRunAt = new Date(Date.now() + minutes * 60_000).toISOString();
        void fn();
      };
      every(minutes * 60_000, tick, firstAfterMs);
      job.nextRunAt = new Date(Date.now() + firstAfterMs).toISOString();
    };
    schedule(this.checks, this.cfg.checks.intervalMinutes, () => this.runChecks(), 2_000);
    schedule(this.reports, this.cfg.reports.intervalMinutes, () => this.runReports(), 10_000);
    if (this.sender.enabled || this.cfg.recipients.length) {
      // Sending is checked every minute (each domain has its own interval); searching more often.
      every(60_000, () => void this.runDelivery(), 20_000);
      every(this.cfg.delivery.pollSeconds * 1000, () => void this.runDelivery({ send: false }), 50_000);
      this.delivery.nextRunAt = new Date(Date.now() + 20_000).toISOString();
    }
  }

  async stop(): Promise<void> {
    this.stopping = true;
    for (const t of this.timers) clearTimeout(t);
    await Promise.all([this.syncer.stop(), this.sender.stop()]);
    await Promise.all(
      [this.checks.running, this.reports.running, this.delivery.running].map((p) => p?.catch(() => {})),
    );
  }
}
