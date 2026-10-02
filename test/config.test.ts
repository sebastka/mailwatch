import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig, parseDomains, parseMailboxes, parseRecipients, validateConfig } from '../src/server/config.ts';

// The example from the specification, with both password spellings (SMTPPASS, IMAPPASSWORD).
const EXAMPLE = {
  DOMAIN_1_NAME: 'wemail.no',
  DOMAIN_1_SMTPHOST: 'smtp.wemail.no',
  DOMAIN_1_SMTPPORT: '465',
  DOMAIN_1_SMTPUSER: 'tester@wemail.no',
  DOMAIN_1_SMTPPASS: 'XXX',
  DOMAIN_2_NAME: 'sol.dk',
  DOMAIN_2_SMTPHOST: 'smtp.sol.dk',
  DOMAIN_2_SMTPPORT: '587',
  DOMAIN_2_SMTPUSER: 'tester@sol.dk',
  DOMAIN_2_SMTPPASSWORD: 'XXX',
  DOMAIN_2_SEND_INTERVAL_MINUTES: '30',
  DOMAIN_5_NAME: 'Checked-Only.example.',
  RECIPIENT_1_NAME: 'GMail',
  RECIPIENT_1_IMAPHOST: 'imap.gmail.com',
  RECIPIENT_1_IMAPPORT: '993',
  RECIPIENT_1_IMAPUSER: 'mygmailuser@gmail.com',
  RECIPIENT_1_IMAPPASSWORD: 'YYY',
  RECIPIENT_2_NAME: 'Microsoft',
  RECIPIENT_2_IMAPHOST: 'outlook.office365.com',
  RECIPIENT_2_IMAPUSER: 'myoutlookuser@outlook.com',
  RECIPIENT_2_OAUTH_TOKEN_URL: 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
  RECIPIENT_2_OAUTH_CLIENT_ID: 'cid',
  RECIPIENT_2_OAUTH_REFRESH_TOKEN: 'rt',
};

test('domains, senders and recipients are read from numbered variables', () => {
  const d = parseDomains(EXAMPLE, 60);
  assert.deepEqual(
    d.map((x) => [
      x.n,
      x.name,
      x.smtp?.host ?? null,
      x.smtp?.port ?? null,
      x.smtp?.secure ?? null,
      x.from,
      x.sendIntervalMinutes,
    ]),
    [
      [1, 'wemail.no', 'smtp.wemail.no', 465, true, 'tester@wemail.no', 60],
      [2, 'sol.dk', 'smtp.sol.dk', 587, false, 'tester@sol.dk', 30],
      [5, 'checked-only.example', null, null, null, null, 60],
    ],
  );
  assert.equal(d[1]!.smtp!.pass, 'XXX');
  const r = parseRecipients(EXAMPLE);
  assert.deepEqual(
    r.map((x) => [x.name, x.address, x.imap.host, x.imap.port, x.imap.secure, x.imap.auth.kind]),
    [
      ['GMail', 'mygmailuser@gmail.com', 'imap.gmail.com', 993, true, 'password'],
      ['Microsoft', 'myoutlookuser@outlook.com', 'outlook.office365.com', 993, true, 'oauth2'],
    ],
  );
});

test('incomplete or conflicting definitions are refused', () => {
  assert.throws(() => parseDomains({ DOMAIN_1_SMTPHOST: 'x' }, 60), /DOMAIN_1_NAME is required/);
  assert.throws(() => parseDomains({ DOMAIN_1_NAME: 'a.example', DOMAIN_1_SMTPHOST: 'x' }, 60), /must be set together/);
  assert.throws(() => parseDomains({ DOMAIN_1_NAME: 'not a domain' }, 60), /must be a domain name/);
  assert.throws(() => parseDomains({ DOMAIN_1_NAME: 'a.example', DOMAIN_2_NAME: 'A.example' }, 60), /configured twice/);
  assert.throws(
    () =>
      parseDomains(
        { DOMAIN_1_NAME: 'a.example', DOMAIN_1_SMTPHOST: 'h', DOMAIN_1_SMTPUSER: 'user', DOMAIN_1_SMTPPASS: 'p' },
        60,
      ),
    /_FROM is required/,
  );
  assert.throws(() => parseRecipients({ RECIPIENT_1_IMAPHOST: 'h', RECIPIENT_1_IMAPUSER: 'u@x' }), /IMAPPASSWORD/);
  assert.throws(
    () => parseRecipients({ RECIPIENT_1_IMAPHOST: 'h', RECIPIENT_1_IMAPUSER: 'user', RECIPIENT_1_IMAPPASS: 'p' }),
    /ADDRESS is required/,
  );
  assert.throws(
    () =>
      parseRecipients({
        RECIPIENT_1_IMAPHOST: 'h',
        RECIPIENT_1_IMAPUSER: 'u@x',
        RECIPIENT_1_IMAPPASS: 'p',
        RECIPIENT_1_OAUTH_REFRESH_TOKEN: 'r',
      }),
    /OAUTH_TOKEN_URL/,
  );
});

test('report mailboxes have a stable key and an opt-in cleanup', () => {
  const m = parseMailboxes({
    MAILBOX_1_IMAPHOST: 'imap.example.com',
    MAILBOX_1_IMAPUSER: 'dmarc@example.com',
    MAILBOX_1_IMAPPASS: 'x',
    MAILBOX_1_IMAPPORT: '143',
    MAILBOX_1_DELETE_AFTER_MONTHS: '12',
  });
  assert.deepEqual(
    m.map((x) => [x.key, x.name, x.address, x.folder, x.imap.secure, x.deleteAfterMonths, x.deleteDryRun]),
    [['dmarc@example.com@imap.example.com/INBOX', 'dmarc@example.com', 'dmarc@example.com', 'INBOX', false, 12, false]],
  );
  assert.throws(
    () =>
      parseMailboxes({
        MAILBOX_1_IMAPHOST: 'h',
        MAILBOX_1_IMAPUSER: 'u',
        MAILBOX_1_IMAPPASS: 'p',
        MAILBOX_1_DELETE_AFTER_MONTHS: '-1',
      }),
    /DELETE_AFTER_MONTHS/,
  );
});

test('defaults and validation', () => {
  const c = loadConfig({ DB_PASSWORD: 'x' });
  assert.deepEqual(
    [c.checks.intervalMinutes, c.reports.intervalMinutes, c.delivery.intervalMinutes, c.delivery.timeoutMinutes],
    [15, 30, 60, 30],
  );
  assert.deepEqual(c.checks.resolvers, ['1.1.1.1', '8.8.8.8']);
  assert.equal(c.alerts.confirmations, 2);
  validateConfig({ server: false }, c);
  assert.throws(() => validateConfig({ server: true }, c), /OIDC_ISSUER/);
  assert.throws(
    () => validateConfig({ server: false }, loadConfig({ DB_PASSWORD: 'x', TELEGRAM_TOKEN: 't' })),
    /together/,
  );
  assert.throws(() => loadConfig({ CHECK_INTERVAL_MINUTES: 'often' }), /must be an integer/);
  assert.throws(() => loadConfig({ TIMEZONE: 'Mars/Olympus' }), /IANA/);
});
