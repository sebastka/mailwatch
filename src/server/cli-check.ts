// Checks domains from the command line, without a database:
//   npm run check-domain -- example.com [other.org …] [--json] [--no-smtp]
// Without arguments, the domains configured in DOMAIN_<n>_NAME are checked.
import type { CheckResult, Level } from '../shared/types.ts';
import { refLabel } from '../shared/rfcs.ts';
import { newRun, runDomainChecks } from './checks/index.ts';
import { config } from './config.ts';

const args = process.argv.slice(2);
const json = args.includes('--json');
const cfg = { ...config.checks, smtpProbe: config.checks.smtpProbe && !args.includes('--no-smtp') };
const names = args.filter((a) => !a.startsWith('--'));
const domains = names.length
  ? names.map((name) => ({ name: name.toLowerCase(), dkimSelectors: [], senderIps: [] }))
  : config.domains.map((d) => ({ name: d.name, dkimSelectors: d.dkimSelectors, senderIps: d.senderIps }));
if (!domains.length) {
  console.error('usage: npm run check-domain -- example.com [--json] [--no-smtp]  (or configure DOMAIN_<n>_NAME)');
  process.exit(2);
}

const ICON: Record<Level, string> = { ok: '✔', info: 'ℹ', warning: '⚠', error: '✖' };
const all: Record<string, CheckResult[]> = {};
// Domains sharing MX hosts share DNS answers and SMTP probes within this run.
const shared = newRun(cfg);
for (const d of domains) {
  const results = await runDomainChecks(d, cfg, shared);
  all[d.name] = results;
  if (json) continue;
  console.log(`\n${d.name}`);
  for (const r of results) {
    console.log(`  ${ICON[r.level]} ${r.check} (${r.durationMs} ms)`);
    for (const f of r.findings) {
      const refs = f.refs?.length ? ` [${f.refs.map(refLabel).join(', ')}]` : '';
      console.log(`      ${ICON[f.level]} ${f.title}${refs}`);
      if (f.level !== 'ok' && f.detail) console.log(`        ${f.detail}`);
    }
  }
}
if (json) console.log(JSON.stringify(all, null, 2));
const worst = Object.values(all)
  .flat()
  .some((r) => r.level === 'error');
process.exitCode = worst ? 1 : 0;
