# Design decisions

Decisions taken while building MailWatch without being able to ask. Each lists the choice, why,
and what we could do instead. Entries marked ⚠️ are the ones most worth reviewing together.

## Naming & scope

### D1. The name stays "MailWatch" ⚠️

- **Choice:** package, image and database are `mailwatch`. It matches zdwatch and says what the
  tool does.
- **Alternatives I would consider:** _Postwarden_, _MXray_, _Mailcheck_ (taken by many tools),
  _Deliverwatch_. Renaming later means a new database name and image name; best decided before
  the first deployment.

### D2. Checks I added beyond the brief

You asked for SPF, DMARC, DKIM, MTA-STS, the tlsrpt functions, rua/ruf analysis and delivery
tests. I also added, because they break mail in practice:

- **MX & SMTP:** Null MX, implicit MX, CNAME targets, private IPs, reverse DNS, and a port 25
  probe of every MX (STARTTLS, TLS ≥ 1.2, certificate trust, name and expiry).
- **DANE** (TLSA records matched against the certificate the MX presents) and **DNSSEC**.
- **TLS-RPT record** check (separate from the report analysis).
- **BIMI** (optional, info level when absent).
- **DNS blocklists** for MX IPs, sender IPs and the domain.
- **Record change log**: every published record is compared between checks; changes are listed
  and announced on Telegram (can be switched off).
- **An MTA-STS trap**: a changed policy whose `id` did not change (senders keep the old one).
- **Certificate expiry** warnings for MX hosts, the MTA-STS policy host and the BIMI host.
- **DMARC external destinations** (RFC 7489 §7.1): reports to another domain are only sent when
  that domain authorises them; this is a frequent, silent reason for "no reports".
- **"Is the report mailbox monitored?"**: rua/ruf/TLS-RPT destinations that MailWatch does not
  read are pointed out.
- **CLI** `npm run check-domain -- example.com`: all checks without a database.

Not done (see "Ideas not implemented" at the end).

## Architecture & tooling

### D3. Same stack as tlsrpt and zdwatch

- One npm package; Node 26 runs the TypeScript server directly (type stripping, erasable syntax
  only); `tsc` 7 for typechecking, TypeScript 6 aliased for typescript-eslint.
- Hono API + React 19/Vite 8 UI, hand-drawn SVG charts, MariaDB through the `mariadb` driver
  with versioned migrations under `GET_LOCK`, OIDC login with groups and editor groups
  (zdwatch's `auth.ts`, unchanged), Telegram as in zdwatch, the release workflow, Dockerfile,
  Dependabot and bundle script copied from tlsrpt.
- New dependencies, all pure JS: `nodemailer` (sending), `dns-packet` (D4), `fast-xml-parser`
  (DMARC XML), `fflate` (zip; most DMARC reporters send zip).

### D4. An own DNS stub resolver instead of `node:dns` ⚠️

- **Why:** `node:dns` hides the DNSSEC **AD flag** (needed for DANE and the DNSSEC findings) and
  does not distinguish NXDOMAIN, "no data" and SERVFAIL well. SPF's void-lookup limit and the
  "lookup failed vs. no record" distinction need that.
- **Choice:** `src/server/dns.ts` sends queries with `dns-packet` over UDP (TCP on truncation),
  with the DO and AD bits, to `DNS_RESOLVERS`. Each check run has its own cache.
- **Default resolvers: Cloudflare and Google (`1.1.1.1,8.8.8.8`)**, because they validate DNSSEC.
  The OS resolver often does not (systemd-resolved, Docker's embedded DNS). `DNS_RESOLVERS=system`
  uses the OS resolvers.
- **Blocklists have their own resolvers:** Spamhaus and SURBL refuse queries that reach them
  through big public resolvers (shown as "unknown" with an info finding, never as "listed").
  `DNSBL_RESOLVERS` sends **only the blocklist lookups** to other resolvers, e.g. an own
  recursive Unbound, while every other check keeps the public, validating view of
  `DNS_RESOLVERS`. Setting `DNS_RESOLVERS=system` instead would be wrong behind a split-horizon
  resolver (the checks would see internal addresses) and often loses the DNSSEC AD flag.
- **Spamhaus DQS:** with `SPAMHAUS_DQS_KEY`, Spamhaus zones are queried as
  `<key>.<zone>.dq.spamhaus.net`, which works through any resolver. Findings, the database, the
  UI and logs keep the public zone name (`zen.spamhaus.org`), so the key is never shown to
  dashboard users; the Status tab only says whether DQS is on. Keep the key in a Secret.

### D5. Latest results, not a time series of checks

- **Choice:** `check_results` holds the latest result per domain and check (findings and
  details as JSON). History lives in the alerts (start/end of every problem) and in
  `record_changes`.
- **Alternative:** keep every run for charts like "SPF lookups over time". Easy to add later.

### D6. Check order and shared context

- The checks of a domain run in order (MX → SPF → DKIM → DMARC → MTA-STS → TLS-RPT → DANE →
  BIMI → blocklists) and share one context: MTA-STS and DANE use the certificates of the MX
  probe, BIMI the DMARC result, SPF the Null MX result.
- A bug in one check produces an "internal-error" finding for that check; the others still run.
- **Shared within a run:** all domains of one check run share one DNS cache (one per resolver
  set) and one SMTP probe per MX host. Domains on the same mail provider therefore ask the
  provider's MX addresses, reverse DNS, TLSA and blocklist questions once, and probe its MX
  once (for two domains on `mx.domeneshop.no`: 136 instead of 200 queries, 1 instead of 2
  probe sessions), and they get the same certificate and DANE verdicts. Nothing is kept
  between runs, so every run sees current DNS and servers.

## Levels, RFCs and findings

### D7. Four levels: OK, info, warning, error

- **error** = broken configuration (mail fails or is unprotected: two SPF records, no STARTTLS,
  DANE mismatch, an MX not covered by an enforced MTA-STS policy, …),
- **warning** = works but should be fixed (p=none, 1024-bit DKIM key, expiring certificate,
  9 of 10 SPF lookups, …),
- **info** = worth knowing (MTA-STS in testing mode, BIMI not set up, …),
- **ok** = explicitly verified (shown, can be hidden per card).
- The UI says "Error" where zdwatch says "Critical"; zdwatch's colours and icons are kept, and a
  status is never shown by colour alone.
- **Judgement calls** ⚠️: a missing MTA-STS or TLS-RPT is _info_ (not broken), but TLS-RPT
  missing while MTA-STS is deployed is a _warning_. A missing DMARC record is an _error_; a
  missing SPF record a _warning_ (DMARC can still pass with DKIM). `~all` is OK. An invalid report destination (e.g. `mailto:mailto:…`, checked against RFC 5322) is a _warning_: the policy works, but that destination gets no reports. The thresholds
  are in the check modules and easy to change.

### D8. RFC references on every finding, and per tab

- Every warning and error cites the document and section it is based on
  (e.g. `RFC 7208 §4.6.4`), linked to rfc-editor.org.
- Every tab has a "Relevant specifications" panel listing its documents; those cited by current
  warnings or errors are marked (red/yellow, with the number of findings citing them). It opens
  automatically when one is "broken".
- **DMARCbis** (the revision of RFC 7489) and BIMI are referenced as Internet-Drafts on the IETF
  datatracker. When DMARCbis is published as an RFC, update `src/shared/rfcs.ts`. Checks follow
  RFC 7489 and mention DMARCbis changes (`np=`, `pct=` replaced by `t=`, the tree walk).

## Configuration

### D9. Numbered blocks, as in your example and in zdwatch

- `DOMAIN_n_*`, `RECIPIENT_n_*` and (new) `MAILBOX_n_*` for the report mailboxes.
- Your example mixed `DOMAIN_n_SMTPPASS` and `RECIPIENT_n_IMAPPASSWORD`; both spellings are
  accepted for both (`…PASS` and `…PASSWORD`).
- **A domain without SMTP settings is only checked**; with them it also sends delivery tests.
  So "many domains" and "domains that send tests" are the same list.
- The sender address is `DOMAIN_n_FROM`, defaulting to the SMTP user.
- Invalid or incomplete blocks stop the start with a message (as zdwatch), rather than being
  skipped silently.

### D10. Gmail and Outlook.com specifics ⚠️

- **Gmail's IMAP host is `imap.gmail.com`** (your example had `imap.google.com`). It needs an
  app password.
- **Outlook.com no longer allows passwords over IMAP** (basic authentication was switched off
  in 2024). Recipients and mailboxes therefore support **OAuth2 (XOAUTH2)** with a refresh
  token (`…_OAUTH_TOKEN_URL`, `…_OAUTH_CLIENT_ID`, `…_OAUTH_REFRESH_TOKEN`). Microsoft rotates
  refresh tokens; the newest is stored in the database (`meta`), so that a restart does not fall
  back to an expired token from the environment. A new token in the environment always wins.
- **Not verified against the real services**: I had no credentials. The IMAP side is tested
  end to end against Dovecot, the sending side against a fake submission server.

## Delivery tests

### D11. How a test message is found ⚠️

- The subject is `MailWatch delivery test <24-hex token>`; the token is also in the Message-ID
  and an `X-MailWatch-Probe` header. The recipient is searched with `SEARCH SINCE … SUBJECT`
  (which Gmail and Outlook support), then matched on the token.
- **Folders:** INBOX plus the folder with the special-use flag `\Junk` (Gmail's `[Gmail]/Spam`,
  Outlook's `Junk`), or `RECIPIENT_n_FOLDERS`. Found in Junk = "junk" (warning).
- **Gmail tabs** (Promotions etc.) are not visible over IMAP; they count as inbox.
- **Cleanup:** found messages are **moved to the trash** (`\Trash`), not just expunged: on Gmail
  an IMAP delete only archives, so messages would pile up in "All Mail". Without a trash folder
  they are deleted. `RECIPIENT_n_KEEP_MESSAGES=true` leaves them alone.
- **Timing:** sending is checked every minute; each domain sends when its interval has passed
  (with a minute of slack). Recipients are searched every `DELIVERY_POLL_SECONDS` while messages
  are pending, otherwise every 15 minutes to notice login problems. A message not found after
  `DELIVERY_TIMEOUT_MINUTES` (30) is "not delivered" (error); if it arrives later it is still
  recorded, as "arrived late".
- When a recipient mailbox cannot be searched, its pending messages are **not** marked lost
  (the problem is the mailbox, which alerts by itself).

### D12. What is recorded from the received message

- The topmost `Authentication-Results` (added by the recipient's boundary), `Received-SPF`,
  Microsoft's `compauth` and spam confidence level, the sending IP, and the DKIM selectors used
  by the sender domain. The full received header block is stored (at most 32 KB); the body is
  not.
- Observed selectors and sending IPs feed back into the checks: the DKIM check verifies those
  selectors, the blocklist check those IPs.
- The test message is plain text and marked `Auto-Submitted: auto-generated`. Repeated
  identical automatic messages may eventually be classified as bulk by Gmail; if that happens,
  we could vary the text.

## Reports

### D13. One mailbox type for all reports

- `MAILBOX_n` mailboxes are read like tlsrpt reads its mailbox (EXAMINE, by UID, a database lock
  per mailbox, the opt-in cleanup per mailbox). Each message is classified by content:
  ARF `message/feedback-report` → failure report; otherwise every attachment is decompressed
  (gzip/zip/plain) and sniffed: `{` → TLS-RPT JSON, `<` → DMARC XML.
- **Duplicates:** TLS reports by (organisation, report-id) as in tlsrpt; DMARC aggregate reports
  by (organisation, report id, policy domain); failure reports by the Message-ID of the report.

### D14. Failure reports (ruf) are stored without bodies

- Only the ARF fields and the original **headers** (≤ 16 KB) are stored. Some reporters include
  the whole message, which can contain personal data. Few providers send ruf at all.

### D15. What counts as a DMARC problem in the reports ⚠️

- Failures from unknown sources are usually spoofing that the policy handles, so the overall
  failure rate is only **info**.
- **Warnings** (and alerts) are raised for what you can fix: sources that pass for some mail and
  fail for other mail (≥ 5 failed messages; usually a legitimate sender with a problem), sources
  whose DKIM passes for another domain (a service sending as you without your DKIM key),
  selectors of your domains that only fail, and failing mail delivered under p=none.
- TLS reports alert when the failure rate over `REPORT_ANALYSIS_DAYS` (7) is ≥ 1 % (≥ 5 % =
  error), like tlsrpt's thresholds.
- Source IPs are shown with their reverse DNS name (looked up when the tab is opened, cached for
  6 hours).

## Alerts

### D16. From findings to alerts ⚠️

- A **warning or error** finding becomes an alert once it is seen in `ALERT_CONFIRMATIONS` (2)
  consecutive checks, to avoid alerts from one-off DNS hiccups. It resolves at the first check
  without it. Info findings never alert.
- An alert is identified by check, finding code, domain and subject (e.g. the MX host or DKIM
  selector), so two broken selectors are two alerts.
- If a check's DNS lookup failed, its open alerts are left as they are (neither confirmed nor
  resolved), so a resolver timeout does not produce "resolved" followed by "new".
- Other alert sources: delivery tests (latest result per sender/recipient), report findings,
  unreadable report or recipient mailboxes.

### D17. Telegram, as in zdwatch, grouped per domain

- New alerts of one domain in one cycle are **one message**; resolutions likewise ("✅
  Resolved"). Messages carry the RFC references and a link to the tab with the domain filter.
- **Minimum severity** for Telegram (default warning; info alerts stay in the dashboard),
  **quiet hours** (errors sent anyway, by default) and **record change announcements** are
  settings on the Status tab, stored in the database (editors only).
- Acknowledge and snooze (1 h … 30 days) work as in zdwatch. A snoozed or below-threshold alert
  is never announced, nor its end.
- Not ported: zdwatch's "still growing" follow-ups (no counts here) and its rule editor:
  every check is a fixed rule here.

## UI

### D18. Fourteen tabs

- Overview · MX & SMTP · SPF · DKIM · DMARC · DMARC reports · MTA-STS · TLS-RPT · DANE · BIMI ·
  Blocklists · Delivery · Alerts · Status. Tabs carry the number of domains with errors (red) or
  warnings (yellow).
- SMTP is part of "MX & SMTP" rather than its own tab, since the probes are of the MX hosts.
- The TLS-RPT tab shows the record check and then **the tlsrpt dashboard** (KPIs, findings,
  sessions per day, failure types, reporters, policies, failure details, reports with raw
  JSON/YAML).
- A **global domain filter** (kept in the URL, `?domain=`) applies to every tab. The report tabs
  add date range and reporter filters.
- Colours, icons, chart conventions and dark mode as in tlsrpt/zdwatch; the pass/fail palette
  was re-validated with the dataviz validator (light and dark).

## Security

### D19. Outbound requests the checks make

- MTA-STS and BIMI fetch URLs derived from DNS (`https://mta-sts.<domain>/…`, BIMI `l=`/`a=`),
  for the configured domains only, without following redirects, with a timeout and a size
  limit. Certificates are validated in code so that an invalid one can be reported.
- **One DNS view for everything:** these fetches resolve the host through `DNS_RESOLVERS` (the
  checks' `DnsClient`), not the OS resolver, exactly like the MX probe. Behind a split-horizon
  resolver (e.g. kube-dns forwarding to a LAN resolver that answers internal addresses), the
  OS view gave `mta-sts.<domain>` a private address, which the guard then refused: a false
  "policy cannot be fetched" although senders get the policy. The private-address guard still
  applies to the public answers, and the URL host name is still used for SNI and the
  certificate check. No `dnsPolicy` or `hostAliases` workaround is needed in the deployment.
- Port 25 probes never send `MAIL FROM`: banner, EHLO, STARTTLS, EHLO, QUIT.
- Credentials are only ever read from the environment (plus the rotated OAuth2 refresh tokens
  in the database, D10). They are never sent to the browser.
- Delivery tests on demand are an **editor** action, since they send real mail.

## Development & deployment

### D20. MariaDB 12.3 LTS; development database on port 3308

- **Version:** MariaDB 12.3, the current long-term support release (`mariadb:lts`), in
  `compose.yaml` and in CI, pinned by digest. tlsrpt and zdwatch use 11.4 LTS; MailWatch uses
  nothing version-specific, so 11.4 and later work as well. 13.x are short-lived rolling
  releases. Deploy against 12.3 (what CI tests). `MARIADB_AUTO_UPGRADE=1` in `compose.yaml`
  upgrades an existing development volume in place.

- tlsrpt uses 3306 and zdwatch 3307 for their compose MariaDB; MailWatch uses 3308 so that all
  three can run at once. The compose file also has the mock OIDC provider and the disposable
  Dovecot used by the tests, as in tlsrpt.

### D21. Demo mode

- `npm run demo` seeds `mailwatch_demo` with three example domains (healthy, warnings, broken),
  90 days of DMARC and TLS reports, failure reports, a week of delivery tests, alerts and
  changes, then serves it with `MAILWATCH_DEMO=true`. In demo mode the domains, senders and
  recipients come from the database, and nothing is checked, synced or sent.

### D22. What I verified, and what not ⚠️

- **Verified:** `npm run check` (typecheck, ESLint, Prettier, 83 tests incl. MariaDB, Dovecot
  and a fake SMTP submission server, with `TZ=Europe/Oslo`); the checks against real domains
  (wemail.no, sol.dk, gmail.com, github.com, proton.me) including port 25 probes and DANE
  matching; the server against MariaDB with live checks (alerts opened on the second check, no
  spurious record changes over repeated runs); the UI in Chromium in light and dark mode, at
  desktop and phone width, through the mock OIDC login.
- **Not verified:** the Docker image build (needs a `dhi.io` login), the GitHub workflow,
  delivery to the real Gmail and Outlook.com (no credentials; nothing was sent from your
  domains), Telegram against the real API, OAuth2 against Microsoft.
- Found and fixed while testing: Google publishes two PTR records for some MX addresses (FCrDNS
  now accepts any of them); ImapFlow leaves the socket open after a failed login (now closed, it
  would have leaked a connection per poll); setting the TLS server name to an IP address broke
  sending to an SMTP host given as an IP.
- **An independent review** (a second Claude agent, read-only) then found 15 problems, all fixed
  and most covered by new tests:
  - hangs: a DNS TCP fallback that never settled when the server hung up, and an SMTP probe
    whose timeout did not cover connecting (either could stall the whole check job);
  - duplicates: Telegram messages sent twice when two jobs finished together, duplicate open
    alerts across replicas, duplicate delivery tests across replicas (now one notification
    lock, duplicate-safe reconciliation, "due" decided inside the send lock);
  - flapping: mailbox and recipient state was kept per replica (now shared in the database);
    checks that depend on the MX results (DANE, MTA-STS certificates, blocklists) now keep
    their alerts when the MX lookup fails or no MX is reachable; failed MTA-STS fetches and
    DKIM lookups no longer look like record changes;
  - wrong results: TLSA lookup failures were ignored (DANE senders defer mail then; now an
    error); an MX with several certificates gave a false DANE mismatch; a failed DMARC parent
    lookup became "no DMARC record"; the MTA-STS "changed without new id" warning lasted one
    check (now until the id changes); a new UIDVALIDITY did not reset the last UID;
  - alerts of removed domains never resolved (now closed silently); an alert that escalates
    (warning → error, e.g. a certificate now expiring within 7 days) is announced again;
  - URLs from DNS (BIMI `l=`/`a=`) could point at internal addresses: fetches now refuse
    non-public addresses and have an overall deadline;
  - smaller: an invalid `%`-escape in `rua=` crashed the DMARC check; SMTP replies that arrived
    before they were awaited were lost; send errors did not show in the job status.
- **Organisational domains** ⚠️: report destinations in the same organisational domain need no
  authorisation (RFC 7489 §7.1). Without a Public Suffix List, the organisational domain is
  approximated as the last two labels, or three under `co.uk`-style registries (`orgDomain()`
  in `checks/dmarc.ts`). Rare suffixes may be misjudged; a PSL dependency would fix that.

### D23. Branch

- As in tlsrpt, the workflow triggers on `master` (this repository's current branch); the
  recorded main branch is `main`. If you create `main`, change `push: {branches: [master]}` in
  `release.yaml`.

### D24. GitHub repository rules ⚠️

Copied from zdwatch:

- **Ruleset "master"** (on the default branch):
  - no deletion and no force push;
  - changes go through a pull request, with **0 required approvals** (GitHub does not let you
    approve your own PRs);
  - the **"Check (tsc + eslint + prettier + tests) & build"** job must pass; only the GitHub
    Actions app may report it;
  - squash merge only.
- **Admins bypass the ruleset**, so you can still push to `master` directly. Remove the bypass
  to force every change through a PR.
- **"Require branches to be up to date" is off**, so a merge does not force every open
  Dependabot PR to rebase and rerun CI.
- **Dependabot:** `dependabot-auto-merge.yml` approves minor and patch updates and enables
  auto-merge; majors wait for you. This needs "Allow auto-merge" and "Allow GitHub Actions to
  approve pull requests" (both on). `DHI_USERNAME`/`DHI_TOKEN` are repository secrets and a
  variable here (Actions and Dependabot), since the repository belongs to a user, not to the
  Fjordmail organisation whose secrets zdwatch uses.
- **Other settings:** merged branches are deleted automatically, the "Update branch" button is
  shown, the squash commit takes the PR title and body, merge commits and rebase merges are
  disabled.
- **Difference from zdwatch:** the default `GITHUB_TOKEN` permission stays **read-only**
  (zdwatch: read and write). Both workflows declare the permissions they need.

## Ideas not implemented

- Client autoconfiguration records: SRV `_submission._tcp`/`_imaps._tcp` (RFC 6186), Thunderbird
  autoconfig, Outlook autodiscover.
- REQUIRETLS (RFC 8689) and SMTPUTF8 advertisement as findings (the extensions are already
  listed).
- Certificate and TLS checks of the **submission** server (`DOMAIN_n_SMTPHOST`) beyond "sending
  works".
- Probing IPv6 MX addresses from an IPv6-less host (they are listed as "not probed").
- SPF `check_host()` evaluation of the source IPs in DMARC reports (the reports already carry
  the receivers' SPF results).
- A Public Suffix List for organisational domains (the DMARCbis tree walk makes it unnecessary
  for policy discovery; the external-destination check uses a heuristic, see D22).
- Other notification channels (webhook, e-mail, Slack/Teams), Prometheus metrics.
- History charts of check results (D5).
