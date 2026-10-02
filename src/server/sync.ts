// Incremental, read-only synchronisation of the report mailboxes (TLS-RPT, DMARC aggregate and
// failure reports), plus the opt-in cleanup of old imported messages. Ported from tlsrpt.
import { createHash } from 'node:crypto';
import type { ImapFlow } from 'imapflow';
import type { MailboxStatus, SyncResult } from '../shared/types.ts';
import type { MailboxConfig } from './config.ts';
import type { MessageRecord, Store } from './db.ts';
import { closeImap, connectImap } from './imap.ts';
import { extractReports } from './reports/mail.ts';

type Log = (msg: string) => void;

/**
 * The cleanup deletes messages sent before this date: `months` calendar months before `now`
 * (UTC, start of day). The day is clamped to the target month, e.g. 31 March minus one month
 * is 28/29 February.
 */
export function cleanupCutoff(now: Date, months: number): Date {
  const y = now.getUTCFullYear();
  const m = now.getUTCMonth() - months;
  const lastDay = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  return new Date(Date.UTC(y, m, Math.min(now.getUTCDate(), lastDay)));
}

/**
 * Of the messages the server found older than the cutoff, only those at or below the last
 * processed UID and recorded as imported may be deleted; everything else is kept.
 */
export function selectForDeletion(olderThanCutoff: number[], lastProcessedUid: number, imported: Set<number>) {
  const remove = olderThanCutoff.filter((uid) => uid <= lastProcessedUid && imported.has(uid)).sort((a, b) => a - b);
  return { remove, kept: olderThanCutoff.length - remove.length };
}

const emptyResult = (): SyncResult => ({
  messagesSeen: 0,
  tlsReports: 0,
  dmarcReports: 0,
  failureReports: 0,
  duplicates: 0,
  messagesWithoutReport: 0,
  errors: 0,
  deleted: 0,
});

interface MailboxState {
  running: boolean;
  lastRunAt: string | null;
  lastError: string | null;
  lastResult: SyncResult | null;
}

export class ReportSyncer {
  private running: Promise<SyncResult> | null = null;
  private stopping = false;
  private readonly state = new Map<string, MailboxState>();
  lastRunAt: string | null = null;
  lastError: string | null = null;

  private readonly store: Store;
  private readonly mailboxes: MailboxConfig[];
  private readonly log: Log;

  constructor(store: Store, mailboxes: MailboxConfig[], log: Log = (m) => console.log(`[reports] ${m}`)) {
    this.store = store;
    this.mailboxes = mailboxes;
    this.log = log;
    for (const m of mailboxes)
      this.state.set(m.key, { running: false, lastRunAt: null, lastError: null, lastResult: null });
  }

  get isRunning(): boolean {
    return this.running !== null;
  }

  async status(): Promise<MailboxStatus[]> {
    return Promise.all(
      this.mailboxes.map(async (m) => {
        const s = this.state.get(m.key)!;
        const [lastSuccessAt, lastError, messages, issues] = await Promise.all([
          this.store.getMeta(`lastSuccessAt:${m.key}`),
          // Stored so that every instance shows the error of the instance that synced.
          this.store.getMeta(`lastError:${m.key}`),
          this.store.messageCount(m.key),
          this.store.messageIssues(m.key),
        ]);
        return {
          key: m.key,
          n: m.n,
          name: m.name,
          address: m.address,
          folder: m.folder,
          running: s.running,
          lastRunAt: s.lastRunAt,
          lastSuccessAt,
          // The stored error is shared by all instances; this instance may not have synced.
          lastError: lastError || null,
          lastResult: s.lastResult,
          messages,
          issues,
          cleanup: m.deleteAfterMonths > 0 ? { afterMonths: m.deleteAfterMonths, dryRun: m.deleteDryRun } : null,
        };
      }),
    );
  }

  /** Syncs every mailbox, or joins the run already in progress. */
  run(opts: { full?: boolean } = {}): Promise<SyncResult> {
    if (this.stopping) return Promise.reject(new Error('shutting down'));
    this.running ??= this.doRun(opts).finally(() => {
      this.running = null;
    });
    return this.running;
  }

  /** Asks a running sync to finish after the current message; resolves once it has. */
  async stop(): Promise<void> {
    this.stopping = true;
    await this.running?.catch(() => {});
  }

  private async doRun({ full = false }: { full?: boolean }): Promise<SyncResult> {
    this.lastRunAt = new Date().toISOString();
    const total = emptyResult();
    const errors: string[] = [];
    for (const m of this.mailboxes) {
      if (this.stopping) break;
      const s = this.state.get(m.key)!;
      s.running = true;
      s.lastRunAt = new Date().toISOString();
      const result = emptyResult();
      try {
        // Only one instance talks to a mailbox at a time.
        // Lock names are limited to 64 characters: use a digest of the mailbox key.
        const lockName = `mailwatch_sync:${createHash('sha256').update(m.key).digest('hex').slice(0, 40)}`;
        const ran = await this.store.withExclusiveLock(lockName, () => this.syncMailbox(m, result, full));
        if (ran === null) {
          this.log(`${m.name}: another instance is syncing, skipped`);
        } else {
          s.lastError = null;
          await this.store.setMeta(`lastSuccessAt:${m.key}`, new Date().toISOString());
          await this.store.setMeta(`lastError:${m.key}`, '');
          if (result.messagesSeen || result.deleted) {
            this.log(
              `${m.name}: ${result.messagesSeen} new message(s): ${result.tlsReports} TLS, ${result.dmarcReports} DMARC aggregate, ` +
                `${result.failureReports} failure report(s), ${result.duplicates} duplicate(s), ${result.messagesWithoutReport} without report, ` +
                `${result.errors} error(s)${result.deleted ? `, ${result.deleted} deleted` : ''}`,
            );
          }
        }
      } catch (e) {
        s.lastError = (e as Error).message;
        errors.push(`${m.name}: ${s.lastError}`);
        await this.store.setMeta(`lastError:${m.key}`, s.lastError).catch(() => {});
        this.log(`${m.name}: failed: ${s.lastError}`);
      } finally {
        s.running = false;
        s.lastResult = result;
        for (const k of Object.keys(total) as (keyof SyncResult)[]) total[k] += result[k];
      }
    }
    this.lastError = errors.length ? errors.join('; ') : null;
    return total;
  }

  private async syncMailbox(m: MailboxConfig, result: SyncResult, full: boolean): Promise<true> {
    const client = await connectImap(m.imap, this.store, (msg) => this.log(`${m.name}: ${msg}`));
    try {
      // Importing is read-only (EXAMINE). Only the opt-in cleanup opens the mailbox read-write.
      let importedFrom: string | null = null;
      const lock = await client.getMailboxLock(m.folder, { readOnly: true });
      try {
        const box = client.mailbox;
        if (!box) throw new Error(`folder ${m.folder} could not be opened`);
        const uidValidity = String(box.uidValidity);
        const validityKey = `uidvalidity:${m.key}`;
        const lastUidKey = `lastuid:${m.key}`;
        let lastUid = Number((await this.store.getMeta(lastUidKey)) ?? 0);
        if (full || (await this.store.getMeta(validityKey)) !== uidValidity) {
          if (!full && lastUid > 0) this.log(`${m.name}: UIDVALIDITY changed, rescanning the whole folder`);
          lastUid = 0;
        }
        await this.store.setMeta(validityKey, uidValidity);
        // Stored together, so that an aborted run after a UIDVALIDITY change rescans next time.
        await this.store.setMeta(lastUidKey, String(lastUid));
        if (box.exists === 0) return true;

        // Collect UIDs first; running other commands inside a FETCH stream is not allowed.
        const pending: { uid: number; size: number }[] = [];
        for await (const msg of client.fetch(`${lastUid + 1}:*`, { uid: true, size: true }, { uid: true })) {
          // "N:*" always matches the highest UID, even when it is below N.
          if (msg.uid > lastUid) pending.push({ uid: msg.uid, size: msg.size ?? 0 });
        }
        pending.sort((a, b) => a.uid - b.uid);
        if (pending.length) this.log(`${m.name}: ${pending.length} new message(s)`);

        for (const { uid, size } of pending) {
          if (this.stopping) {
            this.log(`${m.name}: shutting down after ${result.messagesSeen} of ${pending.length} message(s)`);
            break;
          }
          result.messagesSeen++;
          const base = { mailbox: m.key, uidvalidity: uidValidity, uid };
          if (size > m.maxMessageSize) {
            result.errors++;
            await this.store.recordMessage(
              record(base, { status: 'error', error: `message too large (${size} bytes)` }),
            );
          } else {
            const msg = await client.fetchOne(String(uid), { source: true, internalDate: true }, { uid: true });
            if (msg && msg.source) await this.processMessage(m, base, msg.source, msg.internalDate, result);
          }
          // Advance only after the message is stored: a database error aborts the run and the
          // message is retried next time.
          await this.store.setMeta(lastUidKey, String(uid));
        }
        importedFrom = uidValidity;
      } finally {
        lock.release();
      }
      if (importedFrom && m.deleteAfterMonths > 0 && !this.stopping)
        await this.cleanup(client, m, importedFrom, result);
      return true;
    } finally {
      await closeImap(client);
    }
  }

  /**
   * Opt-in cleanup: permanently deletes messages in the folder (and nowhere else) that were
   * sent more than DELETE_AFTER_MONTHS months ago and whose reports are stored. Requires
   * UIDPLUS, so that only the chosen UIDs are expunged.
   */
  private async cleanup(client: ImapFlow, m: MailboxConfig, uidValidity: string, result: SyncResult): Promise<void> {
    if (!client.capabilities.has('UIDPLUS')) {
      this.log(
        `${m.name}: cleanup skipped: the server lacks UIDPLUS, so an expunge could remove messages flagged by others`,
      );
      return;
    }
    const lastUid = Number((await this.store.getMeta(`lastuid:${m.key}`)) ?? 0);
    if (!lastUid) return;
    const cutoff = cleanupCutoff(new Date(), m.deleteAfterMonths);
    const day = cutoff.toISOString().slice(0, 10);
    const lock = await client.getMailboxLock(m.folder);
    try {
      if (String(client.mailbox && client.mailbox.uidValidity) !== uidValidity) {
        this.log(`${m.name}: cleanup skipped: UIDVALIDITY changed since the import`);
        return;
      }
      // SENTBEFORE compares the Date: header (the date the dashboard shows as "Received").
      const old = (await client.search({ sentBefore: cutoff, uid: `1:${lastUid}` }, { uid: true })) || [];
      if (!old.length) return;
      const imported = await this.store.importedUids(m.key, uidValidity, old);
      const { remove, kept } = selectForDeletion(old, lastUid, imported);
      const keptNote = kept ? `, ${kept} older message(s) kept because they were not imported` : '';
      if (m.deleteDryRun) {
        result.deleted += remove.length;
        this.log(`${m.name}: cleanup dry run: would delete ${remove.length} message(s) sent before ${day}${keptNote}`);
        return;
      }
      for (let i = 0; i < remove.length; i += 200) {
        if (this.stopping) break;
        const chunk = remove.slice(i, i + 200);
        if (!(await client.messageDelete(chunk.join(','), { uid: true }))) {
          throw new Error(`cleanup: the server refused to delete messages ${chunk[0]}-${chunk.at(-1)}`);
        }
        await this.store.markDeleted(m.key, uidValidity, chunk);
        result.deleted += chunk.length;
      }
      if (remove.length || kept)
        this.log(`${m.name}: cleanup: deleted ${result.deleted} message(s) sent before ${day}${keptNote}`);
    } finally {
      lock.release();
    }
  }

  private async processMessage(
    m: MailboxConfig,
    base: { mailbox: string; uidvalidity: string; uid: number },
    source: Buffer,
    internalDate: Date | string | undefined,
    result: SyncResult,
  ): Promise<void> {
    let parsed: Awaited<ReturnType<typeof extractReports>>;
    try {
      parsed = await extractReports(source);
    } catch (e) {
      // Unparseable MIME: record it and move on (database errors below are not caught).
      result.errors++;
      await this.store.recordMessage(record(base, { status: 'error', error: (e as Error).message }));
      return;
    }
    // Prefer the Date header: INTERNALDATE changes when messages are copied or migrated.
    const receivedAt = parsed.date ?? (internalDate ? new Date(internalDate).toISOString() : null);
    const src = { from: parsed.from, subject: parsed.subject, mailbox: m.key, receivedAt };
    let added = 0;
    let dupes = 0;
    const kinds: string[] = [];
    for (const r of parsed.tls) {
      kinds.push('tls');
      if (await this.store.insertTlsReport(r.report, r.raw, { ...src, filename: r.filename })) {
        added++;
        result.tlsReports++;
      } else dupes++;
    }
    for (const r of parsed.dmarc) {
      kinds.push('dmarc');
      if (await this.store.insertDmarcReport(r.report, r.xml, { ...src, filename: r.filename })) {
        added++;
        result.dmarcReports++;
      } else dupes++;
    }
    if (parsed.failure) {
      kinds.push('failure');
      if (await this.store.insertFailureReport(parsed.failure, { ...src, filename: null })) {
        added++;
        result.failureReports++;
      } else dupes++;
    }
    result.duplicates += dupes;
    const found = added + dupes;
    let status: MessageRecord['status'];
    if (parsed.errors.length && !found) status = 'error';
    else if (!found) status = 'no-report';
    else if (added === 0) status = 'duplicate';
    else status = 'ok';
    if (status === 'error') result.errors++;
    if (status === 'no-report') result.messagesWithoutReport++;
    await this.store.recordMessage({
      ...base,
      messageId: parsed.messageId,
      from: parsed.from,
      subject: parsed.subject,
      date: parsed.date,
      kind: [...new Set(kinds)].join(',') || null,
      status,
      error: parsed.errors.length ? parsed.errors.join('; ') : null,
    });
  }
}

function record(
  base: { mailbox: string; uidvalidity: string; uid: number },
  r: { status: MessageRecord['status']; error: string },
): MessageRecord {
  return { ...base, messageId: null, from: null, subject: null, date: null, kind: null, ...r };
}
