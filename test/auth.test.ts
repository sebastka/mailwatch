import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import * as oidc from 'openid-client';
import { authorize, canEdit, clientAuth, readGroupsClaim, safeReturnTo } from '../src/server/auth.ts';

const groups = (allowedGroups: string[], groupsClaim = 'groups') => ({ allowedGroups, groupsClaim });

test('safeReturnTo only accepts local paths', () => {
  assert.equal(safeReturnTo('/?range=7d'), '/?range=7d');
  for (const bad of [undefined, '', 'https://evil.example', '//evil.example', '/\\evil.example', '/auth/login']) {
    assert.equal(safeReturnTo(bad), '/');
  }
});

test('authorize requires membership of an allowed group', () => {
  const c = groups(['mailwatch-admins', 'noc']);
  assert.equal(authorize({ sub: 'a', groups: ['x', 'noc'] }, c), null);
  assert.equal(authorize({ sub: 'a', groups: 'x mailwatch-admins' }, c), null);
  assert.match(authorize({ sub: 'a', groups: ['x'] }, c)!, /not a member/);
  assert.match(authorize({ sub: 'a', groups: [] }, c)!, /not a member/);
  assert.match(authorize({ sub: 'a' }, c)!, /did not send a "groups" claim/);
});

test('authorize fails closed with an empty allow-list', () => {
  assert.match(authorize({ sub: 'a', groups: ['anything'] }, groups([]))!, /not a member/);
});

const ok = (groups: string[]) => ({ status: 'ok', groups });

test('groups claim can be a nested path or a URL-like claim name', () => {
  assert.deepEqual(readGroupsClaim({ realm_access: { roles: ['a', 'b'] } }, 'realm_access.roles'), ok(['a', 'b']));
  assert.deepEqual(readGroupsClaim({ 'https://example.com/groups': ['a'] }, 'https://example.com/groups'), ok(['a']));
  assert.deepEqual(readGroupsClaim({ realm_access: {} }, 'realm_access.roles'), { status: 'missing' });
  // "@" has no special meaning in lists: e-mail style group names match as-is.
  assert.equal(authorize({ sub: 'a', groups: ['noc@example.com'] }, groups(['noc@example.com'])), null);
});

test('Zitadel project roles are scoped to the organisation that granted them', () => {
  const claim = 'urn:zitadel:iam:org:project:roles';
  const zitadel = {
    [claim]: {
      operations: { '123': 'inbox.com' },
      support_1l: { '123': 'inbox.com', '456': 'partner.example' },
    },
  };
  assert.deepEqual(readGroupsClaim(zitadel, claim), ok(['operations@123', 'support_1l@123', 'support_1l@456']));
  assert.equal(authorize({ sub: 'a', ...zitadel }, groups(['operations@123'], claim)), null);
  // The bare role name never matches, and neither does the role in another organisation.
  assert.match(authorize({ sub: 'a', ...zitadel }, groups(['operations'], claim))!, /not a member/);
  assert.match(authorize({ sub: 'a', ...zitadel }, groups(['operations@456'], claim))!, /not a member/);
  // Present but empty is a membership problem, not a missing mapper: the messages differ.
  assert.deepEqual(readGroupsClaim({ [claim]: {} }, claim), ok([]));
  assert.match(authorize({ sub: 'a', [claim]: {} }, groups(['operations@123'], claim))!, /not a member/);
  assert.match(authorize({ sub: 'a' }, groups(['operations@123'], claim))!, /did not send/);
});

test('claims of other shapes are refused instead of guessed at', () => {
  // Keycloak resource_access is keyed by client: its keys must not become groups.
  const keycloak = { resource_access: { mailwatch: { roles: ['viewer'] }, account: { roles: ['manage-account'] } } };
  assert.deepEqual(readGroupsClaim(keycloak, 'resource_access'), { status: 'unsupported' });
  assert.match(authorize({ sub: 'a', ...keycloak }, groups(['mailwatch'], 'resource_access'))!, /unsupported format/);
  for (const bad of [{ a: 1 }, { a: ['x'] }, { a: { org: 1 } }, [{ name: 'x' }], 42, true]) {
    assert.deepEqual(readGroupsClaim({ groups: bad }, 'groups'), { status: 'unsupported' }, JSON.stringify(bad));
  }
});

test('every route except login, callback, logout and health requires a session', async () => {
  const { createApp } = await import('../src/server/app.ts');
  const { loadConfig } = await import('../src/server/config.ts');
  const hash = (t: string) => createHash('sha256').update(t).digest('hex');
  const sessions: Record<string, { sub: string; email: string; name: string; canEdit: boolean; idToken: null }> = {
    [hash('editor')]: { sub: 'u1', email: 'u@x', name: 'U', canEdit: true, idToken: null },
    [hash('viewer')]: { sub: 'u2', email: 'v@x', name: 'V', canEdit: false, idToken: null },
  };
  // Only the calls made by the auth middleware and the routes below are needed.
  const store = {
    getSession: async (h: string) => sessions[h] ?? null,
    checkResults: async () => [],
    changes: async () => [],
  };
  const cfg = loadConfig({ DB_PASSWORD: 'x', DOMAIN_1_NAME: 'example.com', STATIC_DIR: '/nonexistent' });
  let delivered = 0;
  const services = {
    store,
    cfg,
    monitor: { runChecks: async () => {}, runReports: async () => {}, runDelivery: async () => void delivered++ },
    syncer: { status: async () => [] },
    delivery: { recipientStatus: async () => [], enabled: true },
    alerts: {
      lastNotifyError: null,
      quietNow: async () => false,
      announceAck: async () => {},
      sendTest: async () => {},
    },
    telegramConfigured: false,
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const app = createApp(services as any);

  for (const path of ['/', '/index.html', '/assets/app.js', '/auth/other', '/spf']) {
    const res = await app.request(path);
    assert.equal(res.status, 302, path);
    assert.match(res.headers.get('location')!, /^\/auth\/login\?returnTo=/, path);
  }
  for (const path of [
    '/api/overview',
    '/api/checks/spf',
    '/api/changes',
    '/api/alerts',
    '/api/status',
    '/api/me',
    '/api/tls/overview',
    '/api/dmarc/overview',
    '/api/dmarc/failures',
    '/api/delivery',
    '/api/snoozes',
    '/api/settings',
  ]) {
    assert.equal((await app.request(path)).status, 401, path);
  }
  for (const path of [
    '/api/checks/run',
    '/api/reports/sync',
    '/api/delivery/run',
    '/api/telegram/test',
    '/api/alerts/1/ack',
    '/api/alerts/1/snooze',
  ]) {
    assert.equal((await app.request(path, { method: 'POST' })).status, 401, path);
  }
  assert.equal((await app.request('/api/health')).status, 200);
  assert.equal((await app.request('/api/me', { headers: { cookie: 'mailwatch_session=forged' } })).status, 401);

  const as = (who: string, init: RequestInit = {}) => ({
    ...init,
    headers: { cookie: `mailwatch_session=${who}`, 'content-type': 'application/json', ...init.headers },
  });
  const me = await app.request('/api/me', as('editor'));
  assert.equal(me.status, 200);
  assert.deepEqual(await me.json(), { user: { sub: 'u1', email: 'u@x', name: 'U', canEdit: true } });
  assert.equal((await app.request('/api/checks/spf', as('viewer'))).status, 200);
  assert.equal((await app.request('/api/checks/nonsense', as('viewer'))).status, 404);

  // Only editors may send test messages, change settings or send a Telegram test.
  assert.equal((await app.request('/api/delivery/run', as('viewer', { method: 'POST' }))).status, 403);
  assert.equal((await app.request('/api/telegram/test', as('viewer', { method: 'POST' }))).status, 403);
  assert.equal((await app.request('/api/settings', as('viewer', { method: 'PUT', body: '{}' }))).status, 403);
  assert.equal(delivered, 0);
  assert.equal((await app.request('/api/delivery/run', as('editor', { method: 'POST' }))).status, 202);
  assert.equal(delivered, 1);
  const invalid = await app.request('/api/settings', as('editor', { method: 'PUT', body: '{}' }));
  assert.equal(invalid.status, 400);
  // Snoozing is open to every user; a bad duration is refused before anything is looked up.
  const bad = await app.request('/api/alerts/1/snooze', as('viewer', { method: 'POST', body: '{"minutes":1}' }));
  assert.equal(bad.status, 400);

  // Cross-site writes are refused before anything else.
  const csrf = await app.request(
    '/api/delivery/run',
    as('editor', { method: 'POST', headers: { 'sec-fetch-site': 'cross-site' } }),
  );
  assert.equal(csrf.status, 403);
  assert.equal(delivered, 1);
});

test('editor groups: everyone edits without OIDC_EDITOR_GROUPS, else only members', () => {
  const claims = { sub: 'a', groups: ['mailwatch'] };
  assert.equal(canEdit(claims, { editorGroups: [], groupsClaim: 'groups' }), true);
  assert.equal(canEdit(claims, { editorGroups: ['mailwatch-admins'], groupsClaim: 'groups' }), false);
  assert.equal(
    canEdit(
      { ...claims, groups: ['mailwatch', 'mailwatch-admins'] },
      { editorGroups: ['mailwatch-admins'], groupsClaim: 'groups' },
    ),
    true,
  );
  assert.equal(canEdit({ sub: 'a' }, { editorGroups: ['mailwatch-admins'], groupsClaim: 'groups' }), false);
});

test('the default is client_secret_basic, and each method authenticates as registered', async () => {
  const { config: fresh } = await import(`../src/server/config.ts?default=${Date.now()}`);
  if (!process.env.OIDC_TOKEN_AUTH_METHOD) assert.equal(fresh.oidc.tokenAuthMethod, 'client_secret_basic');

  // A minimal token endpoint that records how the client authenticated.
  let seen: { authorization?: string; body: URLSearchParams } | null = null;
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen = { authorization: req.headers.authorization, body: new URLSearchParams(body) };
      res.writeHead(400, { 'content-type': 'application/json' }).end('{"error":"invalid_grant"}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as { port: number };
  const as = { issuer: 'http://idp.test', token_endpoint: `http://127.0.0.1:${port}/token` };
  const tokenRequest = async (method: Parameters<typeof clientAuth>[0], secret?: string) => {
    const c = new oidc.Configuration(as, 'mailwatch', undefined, clientAuth(method, secret));
    oidc.allowInsecureRequests(c);
    await assert.rejects(oidc.refreshTokenGrant(c, 'rt'));
    return seen!;
  };
  try {
    const basic = await tokenRequest('client_secret_basic', 's3cret');
    assert.equal(basic.authorization, `Basic ${Buffer.from('mailwatch:s3cret').toString('base64')}`);
    assert.equal(basic.body.get('client_secret'), null);

    const post = await tokenRequest('client_secret_post', 's3cret');
    assert.equal(post.authorization, undefined);
    assert.equal(post.body.get('client_secret'), 's3cret');

    const jwt = await tokenRequest('client_secret_jwt', 's3cret');
    assert.equal(jwt.body.get('client_assertion_type'), 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    assert.equal(jwt.body.get('client_secret'), null);

    const none = await tokenRequest('none');
    assert.equal(none.authorization, undefined);
    assert.equal(none.body.get('client_id'), 'mailwatch');
    assert.equal(none.body.get('client_secret'), null);
  } finally {
    server.close();
  }
});
