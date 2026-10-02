// Telegram Bot API notifications (sendMessage with HTML formatting).
import { config, telegramConfigured } from './config.ts';

export const esc = (s: string) =>
  s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);

export interface Notifier {
  readonly configured: boolean;
  send(html: string): Promise<void>;
}

export class Telegram implements Notifier {
  private readonly fetch: typeof fetch;
  private readonly cfg: typeof config.telegram;

  constructor(cfg: typeof config.telegram = config.telegram, f: typeof fetch = fetch) {
    this.cfg = cfg;
    this.fetch = f;
  }

  get configured(): boolean {
    return telegramConfigured({ ...config, telegram: this.cfg });
  }

  async send(html: string): Promise<void> {
    if (!this.configured) throw new Error('Telegram is not configured (TELEGRAM_TOKEN, TELEGRAM_CHAT_ID)');
    const body: Record<string, unknown> = {
      chat_id: this.cfg.chatId,
      text: html,
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true },
    };
    if (this.cfg.threadId) body.message_thread_id = Number(this.cfg.threadId);
    const res = await this.fetch(`https://api.telegram.org/bot${this.cfg.token}/sendMessage`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try {
        const j = (await res.json()) as { description?: string };
        if (j.description) msg += `: ${j.description}`;
      } catch {
        // not JSON
      }
      // Never include the URL: it contains the bot token.
      throw new Error(`Telegram sendMessage failed (${msg})`);
    }
  }
}
