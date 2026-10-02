// HTTP API, OIDC login routes and (in production) the static UI.
import { Hono } from 'hono';
import { secureHeaders } from 'hono/secure-headers';
import { serveStatic } from '@hono/node-server/serve-static';
import { existsSync } from 'node:fs';
import { relative } from 'node:path';
import type {
  CheckKind,
  CheckSummary,
  DeliveryOverview,
  DeliveryPair,
  DmarcReportDetail,
  DomainInfo,
  DomainOverview,
  Filters,
  Level,
  Me,
  Status,
  TlsReportDetail,
} from '../shared/types.ts';
import type { Alerts } from './alerts.ts';
import { type AppEnv, Auth, requireEditor, sameOriginGuard } from './auth.ts';
import { CHECK_ORDER } from './checks/index.ts';
import { worst } from './checks/util.ts';
import type { Config } from './config.ts';
import type { Store } from './db.ts';
import type { Delivery } from './delivery.ts';
import type { Monitor } from './monitor.ts';
import { PtrCache } from './ptr-cache.ts';
import { buildDmarcOverview, summarizeDmarc } from './reports/dmarc-analysis.ts';
import { buildTlsOverview, summarizeReport } from './reports/tls-analysis.ts';
import { loadSettings, parseSettings, saveSettings } from './settings.ts';
import type { ReportSyncer } from './sync.ts';

const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

export function parseFilters(q: Record<string, string>): Filters {
  const f: Filters = {};
  if (q.from && DAY_RE.test(q.from)) f.from = q.from;
  if (q.to && DAY_RE.test(q.to)) f.to = q.to;
  if (q.domain) f.domain = q.domain.toLowerCase();
  if (q.org) f.org = q.org;
  return f;
}

const actor = (u: { email: string | null; name: string | null; sub: string } | null) =>
  u?.email ?? u?.name ?? u?.sub ?? null;

export interface Services {
  store: Store;
  cfg: Config;
  monitor: Pick<Monitor, 'runChecks' | 'runReports' | 'runDelivery' | 'checks' | 'reports' | 'delivery'>;
  syncer: Pick<ReportSyncer, 'status'>;
  delivery: Pick<Delivery, 'recipientStatus' | 'enabled'>;
  alerts: Pick<Alerts, 'lastNotifyError' | 'quietNow' | 'announceAck' | 'sendTest'>;
  telegramConfigured: boolean;
}

export function domainInfo(cfg: Config): DomainInfo[] {
  return cfg.domains.map((d) => ({
    n: d.n,
    name: d.name,
    sender: Boolean(d.smtp) && d.sendIntervalMinutes > 0,
    from: d.from,
    sendIntervalMinutes: d.smtp ? d.sendIntervalMinutes : null,
    dkimSelectors: d.dkimSelectors,
  }));
}

const median = (xs: number[]) => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m]! : Math.round((s[m - 1]! + s[m]!) / 2);
};

export function createApp(s: Services): Hono<AppEnv> {
  const { store, cfg } = s;
  const app = new Hono<AppEnv>();
  const auth = new Auth(store);
  const editor = requireEditor();
  const ptr = new PtrCache(cfg.checks.resolvers, cfg.checks.dnsTimeoutMs);
  const domains = new Set(cfg.domains.map((d) => d.name));

  app.onError((err, c) => {
    console.error(err);
    return c.json({ error: 'internal error' }, 500);
  });

  app.use('*', secureHeaders({ crossOriginEmbedderPolicy: false }));
  app.use('*', sameOriginGuard());
  app.use('*', auth.middleware());
  auth.routes(app);

  app.get('/api/health', (c) => c.json({ ok: true }));

  // The auth middleware guarantees a user on every /api route except /api/health.
  app.get('/api/me', (c) => c.json<Me>({ user: c.get('user')! }));

  app.get('/api/status', async (c) => {
    const status: Status = {
      demo: cfg.demo,
      timezone: cfg.timezone,
      domains: domainInfo(cfg),
      checks: s.monitor.checks.status(),
      reports: s.monitor.reports.status(),
      delivery: { ...s.monitor.delivery.status(), timeoutMinutes: cfg.delivery.timeoutMinutes },
      mailboxes: await s.syncer.status(),
      recipients: await s.delivery.recipientStatus(),
      telegram: {
        configured: s.telegramConfigured,
        lastError: s.alerts.lastNotifyError,
        quiet: await s.alerts.quietNow(),
      },
      dns: {
        resolvers: cfg.checks.resolvers,
        blocklistResolvers: cfg.checks.blocklistResolvers,
        // Whether a key is set, never the key itself.
        spamhausDqs: cfg.checks.spamhausDqsKey !== null,
      },
      smtpProbe: cfg.checks.smtpProbe,
    };
    return c.json(status);
  });

  // --- Checks --------------------------------------------------------------------

  app.get('/api/overview', async (c) => {
    const results = await store.checkResults({ withData: false });
    const byDomain = new Map<string, CheckSummary[]>();
    for (const r of results) {
      const counts: Record<Level, number> = { ok: 0, info: 0, warning: 0, error: 0 };
      for (const f of r.findings) counts[f.level]++;
      byDomain.set(r.domain, [
        ...(byDomain.get(r.domain) ?? []),
        { check: r.check, level: r.level, checkedAt: r.checkedAt, counts },
      ]);
    }
    const overview: DomainOverview[] = domainInfo(cfg).map((d) => {
      const checks = (byDomain.get(d.name) ?? []).sort(
        (a, b) => CHECK_ORDER.indexOf(a.check) - CHECK_ORDER.indexOf(b.check),
      );
      return { ...d, checks, level: checks.length ? worst(checks.map((x) => x.level)) : null };
    });
    return c.json(overview);
  });

  app.get('/api/checks/:check', async (c) => {
    const check = c.req.param('check') as CheckKind;
    if (!CHECK_ORDER.includes(check)) return c.json({ error: 'unknown check' }, 404);
    const domain = c.req.query('domain');
    const rows = await store.checkResults({ check, ...(domain ? { domain } : {}) });
    return c.json(rows.filter((r) => domains.has(r.domain)));
  });

  app.post('/api/checks/run', async (c) => {
    if (cfg.demo) return c.json({ error: 'nothing is checked in demo mode' }, 400);
    const body = (await c.req.json().catch(() => ({}))) as { domain?: unknown };
    const domain = typeof body.domain === 'string' && domains.has(body.domain) ? body.domain : undefined;
    // Fire and forget; the UI polls /api/status.
    void s.monitor.runChecks(domain);
    return c.json({ ok: true }, 202);
  });

  app.get('/api/changes', async (c) => {
    const check = c.req.query('check') as CheckKind | undefined;
    return c.json(
      await store.changes({
        ...(c.req.query('domain') ? { domain: c.req.query('domain') } : {}),
        ...(check && CHECK_ORDER.includes(check) ? { check } : {}),
        limit: Math.min(500, Number(c.req.query('limit') ?? 100) || 100),
      }),
    );
  });

  // --- Reports -------------------------------------------------------------------

  app.post('/api/reports/sync', (c) => {
    if (cfg.demo) return c.json({ error: 'nothing is synced in demo mode' }, 400);
    void s.monitor.runReports({ full: c.req.query('full') === '1' });
    return c.json({ ok: true }, 202);
  });

  app.get('/api/tls/filters', async (c) => c.json(await store.tlsFilterOptions()));
  app.get('/api/tls/overview', async (c) => {
    const f = parseFilters(c.req.query());
    return c.json(buildTlsOverview(await store.loadTlsReports(f), f));
  });
  app.get('/api/tls/reports', async (c) => {
    const rows = (await store.loadTlsReports(parseFilters(c.req.query()))).map(summarizeReport);
    return c.json(rows.sort((a, b) => b.start.localeCompare(a.start) || b.id - a.id));
  });
  app.get('/api/tls/reports/:id', async (c) => {
    const id = Number(c.req.param('id'));
    if (!Number.isInteger(id) || id <= 0) return c.json({ error: 'not found' }, 404);
    const [[row], src] = await Promise.all([store.loadTlsReports({ id }), store.tlsReportSource(id)]);
    if (!row || !src) return c.json({ error: 'not found' }, 404);
    const detail: TlsReportDetail = {
      ...summarizeReport(row),
      contactInfo: row.contactInfo,
      policies: row.policies.map(({ id: _id, ...p }) => p),
      source: { from: src.from, subject: src.subject, filename: src.filename, mailbox: src.mailbox },
      raw: src.raw,
    };
    return c.json(detail);
  });

  app.get('/api/dmarc/filters', async (c) => c.json(await store.dmarcFilterOptions()));
  app.get('/api/dmarc/overview', async (c) => {
    const f = parseFilters(c.req.query());
    const reports = await store.loadDmarcReports(f);
    // Reverse DNS of the busiest sources helps recognise them.
    const first = buildDmarcOverview(reports, f);
    const names = await ptr.resolve(first.bySource.slice(0, 200).map((x) => x.ip));
    return c.json(buildDmarcOverview(reports, f, new Date(), (ip) => names.get(ip) ?? null));
  });
  app.get('/api/dmarc/reports', async (c) => {
    const rows = (await store.loadDmarcReports(parseFilters(c.req.query()))).map(summarizeDmarc);
    return c.json(rows.sort((a, b) => b.start.localeCompare(a.start) || b.id - a.id));
  });
  app.get('/api/dmarc/reports/:id', async (c) => {
    const id = Number(c.req.param('id'));
    if (!Number.isInteger(id) || id <= 0) return c.json({ error: 'not found' }, 404);
    const [[row], src] = await Promise.all([store.loadDmarcReports({ id }), store.dmarcReportSource(id)]);
    if (!row || !src) return c.json({ error: 'not found' }, 404);
    const detail: DmarcReportDetail = {
      ...summarizeDmarc(row),
      email: row.email,
      extraContact: row.extraContact,
      errors: row.errors,
      policy: row.policy,
      records: row.records,
      source: { from: src.from, subject: src.subject, filename: src.filename, mailbox: src.mailbox },
      raw: src.raw,
    };
    return c.json(detail);
  });
  app.get('/api/dmarc/failures', async (c) => c.json(await store.failureReports(parseFilters(c.req.query()))));
  app.get('/api/dmarc/failures/:id', async (c) => {
    const id = Number(c.req.param('id'));
    const r = Number.isInteger(id) && id > 0 ? await store.failureReport(id) : null;
    return r ? c.json(r) : c.json({ error: 'not found' }, 404);
  });

  // --- Delivery ------------------------------------------------------------------

  app.get('/api/delivery', async (c) => {
    const days = Math.min(90, Math.max(1, Number(c.req.query('days') ?? 7) || 7));
    const probes = await store.probes({ sinceDays: days });
    const senders = cfg.domains.filter((d) => d.smtp && d.sendIntervalMinutes > 0).map((d) => d.name);
    const pairs: DeliveryPair[] = [];
    for (const sender of senders) {
      for (const r of cfg.recipients) {
        const mine = probes.filter((p) => p.sender === sender && p.recipient === r.name);
        const finished = mine.filter((p) => p.status !== 'sending' && p.status !== 'sent');
        pairs.push({
          sender,
          recipient: r.name,
          latest: mine[0] ?? null,
          sent: mine.length,
          inbox: finished.filter((p) => p.status === 'inbox').length,
          spam: finished.filter((p) => p.status === 'spam').length,
          lost: finished.filter((p) => p.status === 'lost').length,
          failed: finished.filter((p) => p.status === 'send-failed').length,
          medianLatencySeconds: median(finished.map((p) => p.latencySeconds).filter((x): x is number => x !== null)),
        });
      }
    }
    return c.json<DeliveryOverview>({ days, pairs, recent: probes.slice(0, 200) });
  });
  app.get('/api/delivery/probes/:id', async (c) => {
    const id = Number(c.req.param('id'));
    const p = Number.isInteger(id) && id > 0 ? await store.probe(id) : null;
    return p ? c.json(p) : c.json({ error: 'not found' }, 404);
  });
  // Sending test messages to real mailboxes is an editor action.
  app.post('/api/delivery/run', editor, (c) => {
    if (cfg.demo) return c.json({ error: 'nothing is sent in demo mode' }, 400);
    if (!s.delivery.enabled) return c.json({ error: 'no sender domain or recipient is configured' }, 400);
    void s.monitor.runDelivery({ force: true });
    return c.json({ ok: true }, 202);
  });

  // --- Alerts --------------------------------------------------------------------

  app.get('/api/alerts', async (c) => {
    const days = Math.min(400, Math.max(1, Number(c.req.query('days') ?? 30) || 30));
    return c.json(
      await store.listAlerts({
        active: c.req.query('active') === '1',
        since: new Date(Date.now() - days * 86_400_000).toISOString(),
        ...(c.req.query('domain') ? { domain: c.req.query('domain') } : {}),
        limit: 500,
      }),
    );
  });

  // Acknowledging and snoozing are on-call actions: every logged-in user may do them.
  app.post('/api/alerts/:id/ack', async (c) => {
    const id = Number(c.req.param('id'));
    const who = actor(c.get('user')) ?? 'unknown';
    if (!Number.isInteger(id) || !(await store.ackAlert(id, who)))
      return c.json({ error: 'no such open, unacknowledged alert' }, 404);
    const a = (await store.alert(id))!;
    await s.alerts.announceAck(a, who);
    return c.json(a);
  });

  app.post('/api/alerts/:id/snooze', async (c) => {
    const id = Number(c.req.param('id'));
    const body = (await c.req.json().catch(() => null)) as { minutes?: unknown } | null;
    const minutes = Number(body?.minutes);
    if (!Number.isInteger(minutes) || minutes < 15 || minutes > 90 * 1440) {
      return c.json({ error: 'minutes must be an integer between 15 and 129600' }, 400);
    }
    const a = Number.isInteger(id) ? await store.alert(id) : null;
    if (!a) return c.json({ error: 'not found' }, 404);
    const who = actor(c.get('user')) ?? 'unknown';
    await store.snooze(a.key, `${a.domain ? `${a.domain}: ` : ''}${a.title}`, minutes, who);
    if (!a.resolvedAt) await store.ackAlert(id, who);
    const updated = (await store.alert(id))!;
    await s.alerts.announceAck(updated, who, updated.snoozedUntil);
    return c.json(updated);
  });

  app.get('/api/snoozes', async (c) => c.json(await store.snoozes()));
  app.delete('/api/snoozes/:key', async (c) => {
    const ok = await store.unsnooze(decodeURIComponent(c.req.param('key')));
    return ok ? c.json({ ok: true }) : c.json({ error: 'not found' }, 404);
  });

  app.get('/api/settings', async (c) => c.json(await loadSettings(store)));
  app.put('/api/settings', editor, async (c) => {
    const parsed = parseSettings(await c.req.json().catch(() => null));
    if (typeof parsed === 'string') return c.json({ error: parsed }, 400);
    await saveSettings(store, parsed);
    return c.json(parsed);
  });

  app.post('/api/telegram/test', editor, async (c) => {
    if (!s.telegramConfigured) return c.json({ error: 'Telegram is not configured' }, 400);
    try {
      await s.alerts.sendTest(actor(c.get('user')) ?? 'unknown');
    } catch (e) {
      return c.json({ error: (e as Error).message }, 502);
    }
    return c.json({ ok: true });
  });

  app.all('/api/*', (c) => c.json({ error: 'not found' }, 404));

  if (existsSync(cfg.staticDir)) {
    // serveStatic resolves paths relative to the working directory.
    const root = relative(process.cwd(), cfg.staticDir) || '.';
    app.use('/*', serveStatic({ root }));
    app.get('*', serveStatic({ root, path: 'index.html' }));
  } else {
    app.get('/', (c) =>
      c.text('UI not built. Run "npm run build", or use "npm run dev" and open the Vite dev server.', 404),
    );
  }

  return app;
}
