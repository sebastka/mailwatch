// IMAP connections for the report mailboxes and the delivery-test recipients, with password
// or OAuth2 (XOAUTH2) authentication. Microsoft no longer accepts passwords for Outlook.com IMAP.
import { ImapFlow } from 'imapflow';
import type { ImapConfig } from './config.ts';
import type { Store } from './db.ts';

interface Token {
  accessToken: string;
  expiresAt: number;
}

const tokens = new Map<string, Token>();

/**
 * An OAuth2 access token from the refresh token. Providers may rotate the refresh token
 * (Microsoft does); the newest one is kept in the database, so a restart does not fall back
 * to an expired one from the environment.
 */
export async function accessToken(cfg: ImapConfig, store: Store | null, f: typeof fetch = fetch): Promise<string> {
  if (cfg.auth.kind !== 'oauth2') throw new Error('not an OAuth2 mailbox');
  const a = cfg.auth;
  const cacheKey = `${a.user}@${cfg.host}`;
  const cached = tokens.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 60_000) return cached.accessToken;

  const metaKey = `oauth-refresh:${cacheKey}`;
  const stored = store ? await store.getMeta(metaKey) : null;
  // The stored token belongs to the configured one: a new token in the environment wins.
  const parsed = stored ? (JSON.parse(stored) as { from: string; token: string }) : null;
  const refresh = parsed && parsed.from === a.refreshToken ? parsed.token : a.refreshToken;

  const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refresh, client_id: a.clientId });
  if (a.clientSecret) body.set('client_secret', a.clientSecret);
  if (a.scope) body.set('scope', a.scope);
  const res = await f(a.tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body,
    signal: AbortSignal.timeout(20_000),
  });
  const j = (await res.json().catch(() => ({}))) as {
    access_token?: string;
    expires_in?: number;
    refresh_token?: string;
    error?: string;
    error_description?: string;
  };
  if (!res.ok || !j.access_token) {
    throw new Error(
      `OAuth2 token refresh failed: ${j.error ?? `HTTP ${res.status}`}${j.error_description ? ` (${j.error_description.split('\n')[0]})` : ''}`,
    );
  }
  tokens.set(cacheKey, { accessToken: j.access_token, expiresAt: Date.now() + (j.expires_in ?? 3600) * 1000 });
  if (store && j.refresh_token && j.refresh_token !== refresh) {
    await store.setMeta(metaKey, JSON.stringify({ from: a.refreshToken, token: j.refresh_token }));
  }
  return j.access_token;
}

export async function connectImap(cfg: ImapConfig, store: Store | null, log: (m: string) => void): Promise<ImapFlow> {
  const auth =
    cfg.auth.kind === 'password'
      ? { user: cfg.auth.user, pass: cfg.auth.pass }
      : { user: cfg.auth.user, accessToken: await accessToken(cfg, store) };
  const client = new ImapFlow({
    host: cfg.host,
    port: cfg.port,
    secure: cfg.secure,
    auth,
    tls: { rejectUnauthorized: cfg.rejectUnauthorized },
    logger: false,
    // Do not send our identity on login (ID command).
    clientInfo: { name: 'MailWatch' },
  });
  client.on('error', (err: Error) => log(`connection error: ${err.message}`));
  try {
    await client.connect();
  } catch (e) {
    // ImapFlow keeps the socket open after a failed login: close it, or every retry leaks one.
    client.close();
    const err = e as Error & { authenticationFailed?: boolean; responseText?: string };
    if (err.authenticationFailed) {
      throw new Error(
        `login as ${cfg.auth.user} failed${err.responseText ? `: ${err.responseText}` : ' (wrong user name, password or token)'}`,
        { cause: e },
      );
    }
    throw new Error(`cannot connect to ${cfg.host}:${cfg.port}: ${err.responseText ?? err.message}`, { cause: e });
  }
  return client;
}

/** Logs out, or drops the connection when that fails. */
export async function closeImap(client: ImapFlow): Promise<void> {
  await client.logout().catch(() => client.close());
}
