// End-to-end delivery tests: every sender domain (DOMAIN_<n>_SMTP…) sends a probe to every
// recipient (RECIPIENT_<n>_…) every SEND_INTERVAL_MINUTES; the recipients' mailboxes are
// searched (Inbox and Junk) to see whether, where and how fast it arrived, and how the
// provider authenticated it.
import { randomBytes } from 'node:crypto';
import type { ImapFlow } from 'imapflow';
import nodemailer from 'nodemailer';
import type { RecipientStatus } from '../shared/types.ts';
import { parseProbeHeaders } from './auth-results.ts';
import type { Config, DomainConfig, RecipientConfig } from './config.ts';
import type { Store } from './db.ts';
import { closeImap, connectImap } from './imap.ts';

type Log = (msg: string) => void;

export const PROBE_SUBJECT = 'MailWatch delivery test';
const TOKEN_RE = /MailWatch delivery test ([0-9a-f]{24})\b/i;
/** Late arrivals of lost probes are still recorded for this long. */
const LATE_DAYS = 2;
const MAX_HEADER_BYTES = 32 * 1024;

export const newToken = () => randomBytes(12).toString('hex');

export function probeMessage(d: DomainConfig, r: RecipientConfig, token: string, now: Date) {
  return {
    from: { name: 'MailWatch', address: d.from! },
    to: r.address,
    subject: `${PROBE_SUBJECT} ${token}`,
    messageId: `<mailwatch.${token}@${d.name}>`,
    date: now,
    headers: { 'X-MailWatch-Probe': token, 'Auto-Submitted': 'auto-generated' },
    text:
      `This message tests the delivery of e-mail from ${d.name} to ${r.name}.\n` +
      `It was sent by MailWatch on ${now.toISOString()} and is removed automatically once it has been found.\n\n` +
      `Probe ${token}\n`,
  };
}

interface RecipientState {
  lastPollAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
}

export class Delivery {
  private readonly store: Store;
  private readonly domains: DomainConfig[];
  private readonly recipients: RecipientConfig[];
  private readonly cfg: Config['delivery'];
  private readonly log: Log;
  private readonly state = new Map<string, RecipientState>();
  private sending: Promise<void> | null = null;
  private polling: Promise<void> | null = null;
  private stopping = false;
  lastRunAt: string | null = null;
  lastError: string | null = null;

  constructor(
    store: Store,
    domains: DomainConfig[],
    recipients: RecipientConfig[],
    cfg: Config['delivery'],
    log: Log = (m) => console.log(`[delivery] ${m}`),
  ) {
    this.store = store;
    this.domains = domains.filter((d) => d.smtp && d.sendIntervalMinutes > 0);
    this.recipients = recipients;
    this.cfg = cfg;
    this.log = log;
    for (const r of recipients) this.state.set(r.name, { lastPollAt: null, lastSuccessAt: null, lastError: null });
  }

  get enabled(): boolean {
    return this.domains.length > 0 && this.recipients.length > 0;
  }

  get isRunning(): boolean {
    return this.sending !== null || this.polling !== null;
  }

  /** The state of a recipient as last recorded by any instance (the one that searched it). */
  private async sharedState(name: string): Promise<RecipientState> {
    const raw = await this.store.getMeta(`recipient:${name}`);
    if (!raw) return this.state.get(name) ?? { lastPollAt: null, lastSuccessAt: null, lastError: null };
    return JSON.parse(raw) as RecipientState;
  }

  async recipientStatus(): Promise<RecipientStatus[]> {
    return Promise.all(
      this.recipients.map(async (r) => {
        const s = await this.sharedState(r.name);
        return {
          n: r.n,
          name: r.name,
          address: r.address,
          auth: r.imap.auth.kind === 'oauth2' ? 'oauth2' : 'password',
          lastPollAt: s.lastPollAt,
          lastSuccessAt: s.lastSuccessAt,
          lastError: s.lastError,
        } satisfies RecipientStatus;
      }),
    );
  }

  /** Errors of the recipient mailboxes, for the alerts. Shared state, so every replica agrees. */
  async recipientErrors(): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    for (const r of await this.recipientStatus()) if (r.lastError) out.set(r.name, r.lastError);
    return out;
  }

  /** Sends the probes that are due. Serialised across replicas per sender domain. */
  sendDue(now = new Date(), opts: { force?: boolean } = {}): Promise<void> {
    if (this.stopping || !this.enabled) return Promise.resolve();
    this.sending ??= this.doSend(now, opts.force ?? false).finally(() => {
      this.sending = null;
    });
    return this.sending;
  }

  private async doSend(now: Date, force: boolean): Promise<void> {
    this.lastRunAt = now.toISOString();
    await this.store.failStaleSending(30);
    const errors: string[] = [];
    for (const d of this.domains) {
      if (this.stopping) return;
      // Decided inside the lock, so that two replicas never both send.
      await this.store.withExclusiveLock(`mailwatch_send:${d.n}`, async () => {
        const last = await this.store.lastSentAt(d.name);
        // A minute of slack, so that a tick that fires a little early still sends.
        const due = force || !last || now.getTime() - Date.parse(last) >= (d.sendIntervalMinutes - 1) * 60_000;
        if (due) errors.push(...(await this.sendFrom(d, now)));
      });
    }
    this.lastError = errors.length ? errors.join('; ') : null;
  }

  /** Sends one probe to every recipient; returns the errors, which the probes also record. */
  private async sendFrom(d: DomainConfig, now: Date): Promise<string[]> {
    const errors: string[] = [];
    const smtp = d.smtp!;
    const transport = nodemailer.createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: smtp.secure,
      requireTLS: !smtp.secure,
      auth: { user: smtp.user, pass: smtp.pass },
      tls: { rejectUnauthorized: smtp.rejectUnauthorized },
      connectionTimeout: 30_000,
      greetingTimeout: 30_000,
      socketTimeout: 60_000,
    });
    try {
      for (const r of this.recipients) {
        const token = newToken();
        const id = await this.store.createProbe({
          token,
          sender: d.name,
          recipient: r.name,
          sentAt: now.toISOString(),
        });
        try {
          const info = await transport.sendMail(probeMessage(d, r, token, now));
          const rejected = (info.rejected ?? []).map(String);
          if (rejected.length) {
            await this.store.updateProbe(id, {
              status: 'send-failed',
              error: `recipient rejected: ${rejected.join(', ')}`,
              smtpResponse: info.response ?? null,
            });
          } else {
            await this.store.updateProbe(id, { status: 'sent', smtpResponse: info.response ?? null });
          }
        } catch (e) {
          const err = e as Error & { response?: string; code?: string };
          await this.store.updateProbe(id, {
            status: 'send-failed',
            error: `${err.code ? `${err.code}: ` : ''}${err.message}`,
            smtpResponse: err.response ?? null,
          });
          this.log(`${d.name} → ${r.name}: sending failed: ${err.message}`);
          errors.push(`${d.name} → ${r.name}: ${err.message}`);
        }
      }
      return errors;
    } finally {
      transport.close();
    }
  }

  /** Searches the recipient mailboxes for pending probes and marks overdue ones as lost. */
  poll(now = new Date()): Promise<void> {
    if (this.stopping || !this.recipients.length) return Promise.resolve();
    this.polling ??= this.doPoll(now).finally(() => {
      this.polling = null;
    });
    return this.polling;
  }

  private async doPoll(now: Date): Promise<void> {
    await this.store.withExclusiveLock('mailwatch_poll', async () => {
      const pending = await this.store.pendingProbes();
      const byRecipient = new Map<string, number>();
      for (const p of pending) byRecipient.set(p.recipient, (byRecipient.get(p.recipient) ?? 0) + 1);
      for (const r of this.recipients) {
        if (this.stopping) return;
        // Poll every recipient now and then, even without pending probes, to notice login problems.
        const s = this.state.get(r.name)!;
        const idle = !byRecipient.has(r.name);
        if (idle && s.lastPollAt && now.getTime() - Date.parse(s.lastPollAt) < 15 * 60_000) continue;
        s.lastPollAt = now.toISOString();
        try {
          await this.searchRecipient(r, now);
          s.lastError = null;
          s.lastSuccessAt = now.toISOString();
        } catch (e) {
          s.lastError = (e as Error).message;
          this.log(`${r.name}: ${s.lastError}`);
        }
        await this.store.setMeta(`recipient:${r.name}`, JSON.stringify(s));
      }
      // Overdue probes are lost (unless the recipient mailbox could not be searched).
      for (const p of await this.store.pendingProbes()) {
        if (this.state.get(p.recipient)?.lastError) continue;
        if (now.getTime() - Date.parse(p.sentAt) >= this.cfg.timeoutMinutes * 60_000) {
          await this.store.updateProbe(p.id, {
            status: 'lost',
            error: `not found within ${this.cfg.timeoutMinutes} minutes`,
          });
          this.log(`${p.sender} → ${p.recipient}: probe ${p.token} lost`);
        }
      }
      await this.store.purgeProbes(this.cfg.retentionDays);
    });
  }

  private async folders(client: ImapFlow, r: RecipientConfig): Promise<{ path: string; junk: boolean }[]> {
    const list = await client.list();
    const junk = list.filter((b) => b.specialUse === '\\Junk').map((b) => b.path);
    if (r.folders) return r.folders.map((path) => ({ path, junk: junk.includes(path) || /junk|spam/i.test(path) }));
    return [{ path: 'INBOX', junk: false }, ...junk.map((path) => ({ path, junk: true }))];
  }

  private async searchRecipient(r: RecipientConfig, now: Date): Promise<void> {
    const client = await connectImap(r.imap, this.store, (m) => this.log(`${r.name}: ${m}`));
    try {
      const list = await client.list();
      const trash = list.find((b) => b.specialUse === '\\Trash')?.path ?? null;
      const since = new Date(now.getTime() - (LATE_DAYS + 1) * 86_400_000);
      for (const folder of await this.folders(client, r)) {
        const lock = await client.getMailboxLock(folder.path).catch(() => null);
        if (!lock) continue; // the folder does not exist
        try {
          const uids = (await client.search({ since, subject: PROBE_SUBJECT }, { uid: true })) || [];
          if (!uids.length) continue;
          const found: { uid: number; token: string; internalDate: Date | null; headers: string }[] = [];
          for await (const msg of client.fetch(
            uids,
            { uid: true, envelope: true, internalDate: true, headers: true },
            { uid: true },
          )) {
            const token = TOKEN_RE.exec(msg.envelope?.subject ?? '')?.[1]?.toLowerCase();
            if (!token) continue;
            found.push({
              uid: msg.uid,
              token,
              internalDate: msg.internalDate ? new Date(msg.internalDate) : null,
              headers: (msg.headers?.toString('utf8') ?? '').slice(0, MAX_HEADER_BYTES),
            });
          }
          const done: number[] = [];
          for (const m of found) {
            const probe = await this.store.probeByToken(m.token);
            if (!probe) continue; // not ours (another MailWatch instance or a stale database)
            done.push(m.uid);
            if (probe.status !== 'sent' && probe.status !== 'lost') continue;
            const parsed = parseProbeHeaders(m.headers, probe.sender);
            const receivedAt = m.internalDate ?? now;
            await this.store.updateProbe(probe.id, {
              status: folder.junk ? 'spam' : 'inbox',
              receivedAt: receivedAt.toISOString(),
              folder: folder.path,
              latencySeconds: Math.max(0, Math.round((receivedAt.getTime() - Date.parse(probe.sentAt)) / 1000)),
              auth: parsed.auth,
              clientIp: parsed.clientIp,
              dkimSelectors: parsed.dkimSelectors,
              headers: m.headers,
              error:
                probe.status === 'lost' ? `arrived late, after the ${this.cfg.timeoutMinutes}-minute timeout` : null,
            });
          }
          if (done.length && !r.keepMessages) {
            const set = done.join(',');
            if (trash && trash !== folder.path) await client.messageMove(set, trash, { uid: true });
            else await client.messageDelete(set, { uid: true });
          }
        } finally {
          lock.release();
        }
      }
    } finally {
      await closeImap(client);
    }
  }

  async stop(): Promise<void> {
    this.stopping = true;
    await Promise.all([this.sending?.catch(() => {}), this.polling?.catch(() => {})]);
  }
}
