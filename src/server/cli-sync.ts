// One-shot sync of the report mailboxes from the command line: `npm run sync [-- --full]`.
import { config, validateConfig } from './config.ts';
import { Store } from './db.ts';
import { ReportSyncer } from './sync.ts';

validateConfig({ server: false });
if (!config.mailboxes.length) {
  console.error('No report mailbox is configured (MAILBOX_<n>_IMAPHOST, …; see .env.example).');
  process.exit(2);
}
const store = await Store.connect(config.db);
const syncer = new ReportSyncer(store, config.mailboxes);
// Ctrl+C / SIGTERM: finish the current message and log out of IMAP; the next run resumes.
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => void syncer.stop());
try {
  const r = await syncer.run({ full: process.argv.includes('--full') });
  console.log(JSON.stringify(r));
  if (syncer.lastError) process.exitCode = 1;
} catch {
  process.exitCode = 1;
} finally {
  await store.close();
}
