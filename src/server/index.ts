import { serve } from '@hono/node-server';
import { Alerts } from './alerts.ts';
import { createApp } from './app.ts';
import { type Config, config, validateConfig } from './config.ts';
import { Store } from './db.ts';
import { Delivery } from './delivery.ts';
import { Monitor } from './monitor.ts';
import { ReportSyncer } from './sync.ts';
import { Telegram } from './telegram.ts';

validateConfig({ server: true });
const store = await Store.connect(config.db);

/**
 * The demo serves the domains, senders and recipients found in its database (seeded by
 * scripts/seed-demo.ts) instead of the configured ones; nothing is checked, synced or sent.
 */
async function demoConfig(): Promise<Config> {
  const [domains] = await Promise.all([
    store.pool.query<{ d: string }[]>('SELECT DISTINCT domain AS d FROM check_results ORDER BY 1'),
  ]);
  const pairs = await store.pool.query<{ s: string; r: string }[]>(
    'SELECT DISTINCT sender AS s, recipient AS r FROM probes',
  );
  const senders = new Set(pairs.map((p) => p.s));
  const smtp = { host: 'smtp.invalid', port: 465, secure: true, user: 'demo', pass: 'demo', rejectUnauthorized: true };
  return {
    ...config,
    domains: domains.map((d, i) => ({
      n: i + 1,
      name: d.d,
      dkimSelectors: [],
      senderIps: [],
      smtp: senders.has(d.d) ? smtp : null,
      from: senders.has(d.d) ? `monitor@${d.d}` : null,
      sendIntervalMinutes: senders.has(d.d) ? 60 : 0,
    })),
    recipients: [...new Set(pairs.map((p) => p.r))].sort().map((name, i) => ({
      n: i + 1,
      name,
      address: `test@${name.toLowerCase()}.example`,
      imap: {
        host: 'imap.invalid',
        port: 993,
        secure: true,
        rejectUnauthorized: true,
        auth: { kind: 'password' as const, user: 'demo', pass: 'demo' },
      },
      folders: null,
      keepMessages: false,
    })),
    mailboxes: [],
  };
}
const cfg = config.demo ? await demoConfig() : config;

const telegram = new Telegram();
// The demo serves what is in its database: no mailboxes, recipients or senders.
const mailboxes = cfg.mailboxes;
const recipients = cfg.recipients;
const syncer = new ReportSyncer(store, mailboxes);
const delivery = new Delivery(store, cfg.domains, recipients, cfg.delivery);
const alerts = new Alerts(store, telegram);
const monitor = new Monitor({ store, cfg, alerts, syncer, delivery });
const app = createApp({
  store,
  cfg,
  monitor,
  syncer,
  delivery,
  alerts,
  telegramConfigured: telegram.configured,
});

const server = serve({ fetch: app.fetch, hostname: config.http.host, port: config.http.port }, (info) => {
  const senders = cfg.domains.filter((d) => d.smtp && d.sendIntervalMinutes > 0).length;
  console.log(
    `MailWatch listening on http://${info.address}:${info.port} (public URL ${config.http.publicUrl}, ` +
      `db ${config.db.user}@${config.db.host}:${config.db.port}/${config.db.database}, ` +
      `${cfg.domains.length} domain(s), ${senders} sender(s), ${recipients.length} recipient(s), ${mailboxes.length} report mailbox(es), ` +
      `DNS via ${config.checks.resolvers.join(', ')}, Telegram ${telegram.configured ? 'on' : 'off'}, login via ${config.oidc.issuer})`,
  );
});

if (!cfg.domains.length) console.warn('No domain is configured; set DOMAIN_1_NAME etc. (see .env.example).');
if (config.demo) console.log('Demo mode: serving the seeded data; no checks, syncs or delivery tests.');
else monitor.start();

// Graceful shutdown on SIGTERM (docker stop, Kubernetes) and SIGINT (Ctrl+C). Node runs as
// PID 1 in the container, where signals without a handler are ignored, so these handlers are
// what makes the container stop promptly.
const SHUTDOWN_TIMEOUT_MS = 8000; // below Docker's default 10 s grace period
let shuttingDown = false;

async function shutdown(signal: NodeJS.Signals): Promise<void> {
  if (shuttingDown) {
    console.warn(`${signal} received again, exiting immediately`);
    process.exit(1);
  }
  shuttingDown = true;
  console.log(`${signal} received, shutting down`);
  setTimeout(() => {
    console.error(`shutdown did not finish within ${SHUTDOWN_TIMEOUT_MS / 1000} s, exiting`);
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS).unref();

  // Stop accepting connections, let running jobs finish their current step (mailbox syncs
  // resume from the last stored message), then close the database pool.
  const httpClosed = new Promise<void>((resolve) => server.close(() => resolve()));
  await monitor.stop();
  if ('closeAllConnections' in server) server.closeAllConnections();
  await httpClosed;
  await store.close();
  console.log('shutdown complete');
  process.exit(0);
}
process.on('SIGINT', (s) => void shutdown(s));
process.on('SIGTERM', (s) => void shutdown(s));
