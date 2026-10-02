// Turns findings into alerts (open while the finding persists, resolved when it is gone),
// keeps their lifecycle in the database and announces them on Telegram. The lifecycle,
// snoozes, acknowledgements and quiet hours work as in zdwatch.
import { createHash } from 'node:crypto';
import type {
  Alert,
  AlertKind,
  CheckKind,
  CheckResult,
  DeliveryProbe,
  Finding,
  RecordChange,
} from '../shared/types.ts';
import { alertPath, areaOf, CHECK_LABEL, checkOfKey } from '../shared/paths.ts';
import { refLabel } from '../shared/rfcs.ts';
import { config } from './config.ts';
import type { AlertState, AlertWrite, Store } from './db.ts';
import { isQuiet, loadSettings, quietPeriod, SEVERITY_ORDER } from './settings.ts';
import { esc, type Notifier } from './telegram.ts';

/** Notifications that could not be sent are retried for this long, then dropped. */
const NOTIFY_WINDOW_MS = 3_600_000;

/** Alert keys must fit the 191-character index; long ones keep a readable prefix and a digest. */
export function alertKey(parts: (string | null | undefined)[]): string {
  const k = parts.map((p) => p ?? '').join('|');
  return k.length <= 191 ? k : `${k.slice(0, 150)}#${createHash('sha256').update(k).digest('hex').slice(0, 40)}`;
}

type Log = (msg: string) => void;

export interface AlertOptions {
  log?: Log;
  now?: () => number;
  publicUrl?: string;
  timezone?: string;
  confirmations?: number;
}

const truncate = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export class Alerts {
  private readonly store: Store;
  private readonly notifier: Notifier;
  private readonly log: Log;
  private readonly now: () => number;
  private readonly publicUrl: string | undefined;
  private readonly timezone: string;
  private readonly confirmations: number;
  lastNotifyError: string | null = null;

  constructor(store: Store, notifier: Notifier, opts: AlertOptions = {}) {
    this.store = store;
    this.notifier = notifier;
    this.log = opts.log ?? ((m) => console.log(`[alerts] ${m}`));
    this.now = opts.now ?? Date.now;
    this.publicUrl = opts.publicUrl ?? config.http.publicUrl;
    this.timezone = opts.timezone ?? config.timezone;
    this.confirmations = opts.confirmations ?? config.alerts.confirmations;
  }

  private nowIso(): string {
    return new Date(this.now()).toISOString();
  }

  /**
   * Opens, touches and resolves the alerts in `scope` so that exactly `desired` are open.
   * Open alerts for which `keep` is true are left alone (their state is unknown right now).
   */
  private async reconcile(
    scope: (a: AlertState) => boolean,
    desired: AlertWrite[],
    keep: (a: AlertState) => boolean = () => false,
  ) {
    const at = this.nowIso();
    const open = new Map<string, AlertState>();
    for (const a of (await this.store.openAlerts()).filter(scope)) {
      // Should two open alerts ever share a key (a race between replicas), keep the oldest.
      if (open.has(a.key)) await this.store.resolveAlert(a.id, at, { silent: true });
      else open.set(a.key, a);
    }
    for (const w of desired) {
      const cur = open.get(w.key);
      if (cur && SEVERITY_ORDER[w.severity] > SEVERITY_ORDER[cur.severity] && cur.notifiedStartAt) {
        // An escalation (e.g. a certificate now expiring within 7 days) is announced again,
        // also when the weaker alert was below the Telegram threshold and silenced.
        await this.store.resolveAlert(cur.id, at, { silent: true });
        await this.store.openAlert(w, at);
        open.delete(w.key);
        this.log(`${w.domain ?? '-'} ${w.code}: escalated to ${w.severity}`);
      } else if (cur) {
        await this.store.touchAlert(cur.id, w, at);
        open.delete(w.key);
      } else {
        await this.store.openAlert(w, at);
        this.log(`${w.domain ?? '-'} ${w.code}: ${w.title}`);
      }
    }
    for (const a of open.values()) {
      if (keep(a)) continue;
      await this.store.resolveAlert(a.id, at);
      this.log(`${a.domain ?? '-'} ${a.code}: resolved`);
    }
  }

  private findingAlert(kind: AlertKind, domain: string, f: Finding, keyParts: string[]): AlertWrite {
    return {
      key: alertKey([kind, ...keyParts, f.code, domain, f.subject ?? '']),
      kind,
      code: f.code,
      domain,
      subject: f.subject ?? '',
      title: f.title,
      severity: f.level === 'error' ? 'error' : 'warning',
      detail: f.detail || null,
      refs: f.refs ?? [],
    };
  }

  /** Warnings and errors of one domain's checks, after ALERT_CONFIRMATIONS consecutive checks. */
  async checks(domain: string, results: CheckResult[]): Promise<void> {
    const candidates: AlertWrite[] = [];
    const indeterminate = new Set<CheckKind>();
    const has = (check: CheckKind, test: (code: string) => boolean) =>
      results.some((r) => r.check === check && r.findings.some((f) => test(f.code)));
    for (const r of results) {
      if (r.findings.some((f) => f.code.endsWith('lookup-failed') || f.code === 'internal-error'))
        indeterminate.add(r.check);
      for (const f of r.findings) {
        if (f.level === 'warning' || f.level === 'error')
          candidates.push(this.findingAlert('check', domain, f, [r.check]));
      }
    }
    // Checks that build on the MX results (certificates, TLSA matches, MX addresses) cannot
    // conclude when the MX lookup failed or no MX could be reached: keep their alerts as they are.
    if (indeterminate.has('mx') || has('mx', (c) => c === 'smtp.unreachable-all')) {
      for (const c of ['dane', 'mta-sts', 'dnsbl'] as const) indeterminate.add(c);
    }
    const streaks = await this.store.updateStreaks(
      `check|${domain}`,
      candidates.map((c) => c.key),
    );
    const open = new Set(
      (await this.store.openAlerts()).filter((a) => a.kind === 'check' && a.domain === domain).map((a) => a.key),
    );
    const desired = candidates.filter((c) => open.has(c.key) || (streaks.get(c.key) ?? 0) >= this.confirmations);
    await this.reconcile(
      (a) => a.kind === 'check' && a.domain === domain,
      desired,
      (a) => indeterminate.has(checkOfKey(a.key)!),
    );
  }

  /** Alerts of domains that are no longer configured are closed without a message. */
  async pruneDomains(configured: string[]): Promise<void> {
    const at = this.nowIso();
    for (const a of await this.store.openAlerts()) {
      if (
        (a.kind === 'check' || a.kind === 'report' || a.kind === 'delivery') &&
        a.domain &&
        !configured.includes(a.domain)
      ) {
        await this.store.resolveAlert(a.id, at, { silent: true });
      }
    }
  }

  /** Report-based findings per domain (DMARC and TLS reports of the last days). */
  async reports(perDomain: Map<string, Finding[]>): Promise<void> {
    const desired = [...perDomain].flatMap(([domain, fs]) =>
      fs
        .filter((f) => f.level === 'warning' || f.level === 'error')
        .map((f) => this.findingAlert('report', domain, f, [])),
    );
    await this.reconcile((a) => a.kind === 'report', desired);
  }

  /** The latest result of every sender/recipient pair of the delivery tests. */
  async delivery(
    latest: DeliveryProbe[],
    senders: string[],
    recipients: string[],
    timeoutMinutes: number,
  ): Promise<void> {
    const desired: AlertWrite[] = [];
    for (const p of latest) {
      if (!senders.includes(p.sender) || !recipients.includes(p.recipient)) continue;
      const add = (
        code: string,
        severity: 'warning' | 'error',
        title: string,
        detail: string,
        refs: AlertWrite['refs'] = [],
      ) =>
        desired.push({
          key: alertKey(['delivery', code, p.sender, p.recipient]),
          kind: 'delivery',
          code,
          domain: p.sender,
          subject: p.recipient,
          title,
          severity,
          detail,
          refs,
        });
      const pair = `${p.sender} → ${p.recipient}`;
      if (p.status === 'send-failed') {
        add(
          'delivery.send-failed',
          'error',
          `${pair}: the test message could not be sent`,
          p.error ?? p.smtpResponse ?? 'unknown error',
          [{ doc: 'rfc5321' }],
        );
      } else if (p.status === 'lost') {
        add(
          'delivery.lost',
          'error',
          `${pair}: the test message did not arrive`,
          `Not found in the Inbox or Junk folder within ${timeoutMinutes} minutes (sent ${p.sentAt}). ${p.smtpResponse ? `The submission server answered: ${p.smtpResponse}` : ''}`.trim(),
        );
      } else if (p.status === 'spam') {
        add(
          'delivery.spam',
          'warning',
          `${pair}: the test message landed in Junk`,
          `Folder ${p.folder ?? '?'}; spf=${p.auth?.spf ?? '?'}, dkim=${p.auth?.dkim ?? '?'}, dmarc=${p.auth?.dmarc ?? '?'}.`,
          [{ doc: 'rfc8601' }],
        );
      }
      if ((p.status === 'inbox' || p.status === 'spam') && p.auth?.dmarc && p.auth.dmarc !== 'pass') {
        add(
          'delivery.dmarc',
          'warning',
          `${pair}: DMARC ${p.auth.dmarc} at the recipient`,
          `The recipient recorded spf=${p.auth.spf ?? '?'}, dkim=${p.auth.dkim ?? '?'}, dmarc=${p.auth.dmarc}. Check SPF and DKIM alignment for ${p.sender}.`,
          [{ doc: 'rfc7489', section: '3.1' }, { doc: 'rfc8601' }],
        );
      }
    }
    await this.reconcile((a) => a.kind === 'delivery', desired);
  }

  /** Mailbox access problems: report mailboxes and delivery-test recipients. */
  async syncs(problems: { code: 'sync.mailbox' | 'sync.recipient'; subject: string; error: string }[]): Promise<void> {
    await this.reconcile(
      (a) => a.kind === 'sync',
      problems.map((p) => ({
        key: alertKey(['sync', p.code, p.subject]),
        kind: 'sync' as const,
        code: p.code,
        domain: null,
        subject: p.subject,
        title:
          p.code === 'sync.mailbox'
            ? `Report mailbox ${p.subject} cannot be read`
            : `Recipient mailbox ${p.subject} cannot be searched`,
        severity: 'warning' as const,
        detail: p.error,
        refs: [],
      })),
    );
  }

  // --- Telegram ---------------------------------------------------------------------

  private time(iso: string): string {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: this.timezone,
      day: 'numeric',
      month: 'short',
      hour: '2-digit',
      minute: '2-digit',
    }).format(new Date(iso));
  }

  private link(path: string, domain: string | null): string {
    if (!this.publicUrl) return '';
    const q = domain ? `?${new URLSearchParams({ domain })}` : '';
    return `\n<a href="${esc(`${this.publicUrl}${path}${q}`)}">Open MailWatch</a>`;
  }

  /** One message per domain and cycle: new problems, or problems resolved. */
  message(alerts: AlertState[], what: 'start' | 'resolve'): string {
    const first = alerts[0]!;
    const who = esc(first.domain ?? 'MailWatch');
    const refs = (a: AlertState) => (a.refs.length ? ` <i>(${esc(a.refs.map(refLabel).join(', '))})</i>` : '');
    if (what === 'resolve') {
      const lines = alerts.map((a) => `• ${esc(areaOf(a))}: ${esc(a.title)} <i>(since ${this.time(a.startedAt)})</i>`);
      return `✅ <b>Resolved</b> · ${who}\n${lines.join('\n')}${this.link(alertPath(first), first.domain)}`;
    }
    const sorted = [...alerts].sort((x, y) => SEVERITY_ORDER[y.severity] - SEVERITY_ORDER[x.severity]);
    const top = sorted[0]!.severity;
    const icon = top === 'error' ? '🔴' : top === 'warning' ? '🟠' : 'ℹ️';
    if (sorted.length === 1) {
      const a = sorted[0]!;
      return (
        `${icon} <b>${esc(areaOf(a))}: ${esc(a.title)}</b> · ${who}\n` +
        `${a.detail ? `${esc(truncate(a.detail, 500))}\n` : ''}` +
        `${a.refs.length ? `<i>${esc(a.refs.map(refLabel).join(', '))}</i>` : ''}${this.link(alertPath(a), a.domain)}`
      );
    }
    const lines = sorted.map((a) => `• <b>${esc(areaOf(a))}</b>: ${esc(a.title)}${refs(a)}`);
    return `${icon} <b>${sorted.length} problems</b> · ${who}\n${lines.join('\n')}${this.link(alertPath(sorted[0]!), first.domain)}`;
  }

  /** Announces new and resolved alerts. Serialised across jobs and replicas, so nothing is sent twice. */
  async notify(): Promise<void> {
    if (!this.notifier.configured) return;
    await this.store.withExclusiveLock('mailwatch_notify', () => this.doNotify(), 30);
  }

  private async doNotify(): Promise<void> {
    const now = this.now();
    const settings = await loadSettings(this.store);
    const q = settings.quietHours;
    const period = q.enabled ? quietPeriod(q, now, this.timezone) : null;
    const quiet = period?.active ?? false;
    // Right after quiet hours, what was held back overnight is still due.
    let since = now - NOTIFY_WINDOW_MS;
    if (period && !quiet && now - period.end < NOTIFY_WINDOW_MS) since = Math.min(since, period.start);
    const holds = (a: AlertState) => quiet && !(q.exemptErrors && a.severity === 'error');
    const held = (a: AlertState) =>
      period !== null && !quiet && Date.parse(a.startedAt) >= period.start && Date.parse(a.startedAt) < period.end;
    const below = (a: AlertState) => SEVERITY_ORDER[a.severity] < SEVERITY_ORDER[settings.notifyMinSeverity];

    const groups = new Map<string, { what: 'start' | 'resolve'; alerts: AlertState[] }>();
    const add = (what: 'start' | 'resolve', a: AlertState) => {
      const key = `${what}|${a.domain ?? ''}`;
      const g = groups.get(key) ?? { what, alerts: [] };
      g.alerts.push(a);
      groups.set(key, g);
    };
    for (const a of await this.store.alertsToNotify(new Date(since).toISOString())) {
      if (!a.resolvedAt && !a.notifiedStartAt) {
        // Snoozed or below the threshold: never announced (nor its end). Quiet: held.
        if (a.snoozedUntil || below(a)) await this.store.silenceAlert(a.id);
        else if (!holds(a)) add('start', a);
      } else if (a.resolvedAt && a.notifiedStartAt && !a.notifiedResolveAt) {
        if (a.silenced || a.snoozedUntil) await this.store.markNotified(a.id, 'resolve');
        else if (!holds(a)) add('resolve', a);
      }
    }
    for (const { what, alerts } of groups.values()) {
      try {
        let text = this.message(alerts, what);
        if (what === 'start' && alerts.some(held)) text += '\n<i>Held back during quiet hours.</i>';
        await this.notifier.send(text);
        for (const a of alerts) await this.store.markNotified(a.id, what);
        this.lastNotifyError = null;
      } catch (e) {
        this.lastNotifyError = (e as Error).message;
        this.log(`notification failed: ${this.lastNotifyError}`);
        return; // retry next cycle
      }
    }
  }

  async quietNow(): Promise<boolean> {
    const { quietHours } = await loadSettings(this.store);
    return isQuiet(quietHours, this.now(), this.timezone);
  }

  /** Announces a changed DNS record (when enabled and not quiet). Failures are logged, not thrown. */
  async announceChange(c: Omit<RecordChange, 'id'>): Promise<void> {
    if (!this.notifier.configured) return;
    const s = await loadSettings(this.store);
    if (!s.notifyChanges || (await this.quietNow())) return;
    const show = (v: string | null) => (v ? `<code>${esc(truncate(v, 600))}</code>` : '<i>(none)</i>');
    try {
      await this.notifier.send(
        `🔁 <b>${esc(CHECK_LABEL[c.check])} changed</b> · ${esc(c.domain)}\nBefore: ${show(c.before)}\nNow: ${show(c.after)}${this.link(`/${c.check}`, c.domain)}`,
      );
    } catch (e) {
      this.lastNotifyError = (e as Error).message;
      this.log(`notification failed: ${this.lastNotifyError}`);
    }
  }

  /** Tells the chat that someone took an announced alert. */
  async announceAck(a: Alert, by: string, snoozedUntil: string | null = null): Promise<void> {
    if (!this.notifier.configured || !a.notified || (await this.quietNow())) return;
    const what = snoozedUntil ? `Snoozed until ${this.time(snoozedUntil)}` : 'Acknowledged';
    try {
      await this.notifier.send(
        `👀 <b>${esc(areaOf(a))}: ${esc(a.title)}</b> · ${esc(a.domain ?? 'MailWatch')}\n${what} by ${esc(by)}`,
      );
    } catch (e) {
      this.lastNotifyError = (e as Error).message;
      this.log(`notification failed: ${this.lastNotifyError}`);
    }
  }

  async sendTest(user: string): Promise<void> {
    await this.notifier.send(`🧪 <b>MailWatch test message</b>\nSent by ${esc(user)} from the dashboard.`);
  }
}
