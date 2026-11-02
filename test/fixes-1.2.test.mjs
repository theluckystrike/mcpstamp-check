// Engine 1.2.0: one test group per QA defect of run s1102m (P1-1 ... P2-28).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkServer as rawCheck, SSEParser, parseSSE, geminiMetadataUrls, asMetadataUrls, isFirewall, STORE_MEANING, ENGINE_VERSION } from '../src/check.mjs';
import { isPrivateIp, parseIPv6, redactUrl, secretParts, looksSecret, makeHostGuard, normalizeUrl, resultId, scrubSecrets } from '../src/ssrf.mjs';
import { explainCheck } from '../src/explain.mjs';
import { formatCheck } from '../src/mcp.mjs';
import worker, { STALE_MS } from '../src/worker.mjs';

const PUBLIC_IP = '93.184.215.14';
const checkServer = (u, o = {}) => rawCheck(u, { resolve: async () => [PUBLIC_IP], ...o });
const byId = (r, id) => r.checks.find((c) => c.id === id);

function jsonRes(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}
function mockFetch(handler) {
  const calls = [];
  const f = async (url, init = {}) => {
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url: String(url), method: init.method || 'GET', body });
    return handler(init.method || 'GET', String(url), body, init);
  };
  f.calls = calls;
  return f;
}
const tool = (name, annotations = { readOnlyHint: true, destructiveHint: false, openWorldHint: false }) => ({
  name, title: `Title ${name}`, description: `Call ${name} to do one precise thing and return a structured answer with ids.`,
  inputSchema: { type: 'object', properties: {} }, annotations,
});
const initResult = { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'x', version: '1' }, instructions: 'Example server for tests. It covers widgets and gadgets for teams.' };
const AS_OK = (issuer, extra = {}) => ({
  issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, registration_endpoint: `${issuer}/register`,
  response_types_supported: ['code'], code_challenge_methods_supported: ['S256'], grant_types_supported: ['authorization_code', 'refresh_token'],
  token_endpoint_auth_methods_supported: ['none'], ...extra,
});

/** OAuth-gated server at `url`; `meta` maps metadata URLs to responses (default 404). */
function gated(url, meta, prm) {
  return mockFetch((method, u) => {
    if (u === url) return jsonRes({ error: 'unauthorized' }, 401, { 'www-authenticate': `Bearer resource_metadata="${prm}"` });
    if (meta[u]) return typeof meta[u] === 'function' ? meta[u]() : jsonRes(meta[u]);
    return jsonRes({ error: 'not_found' }, 404);
  });
}

// ---------- P1-1 token leak ----------

test('P1-1: path tokens are redacted everywhere in the result', async () => {
  const token = 'Zx81kQ2mWp7rTt5LbN3vYc9H';
  const url = `https://mcp.example.com/mcp/t/${token}/invoice`;
  const prmUrl = `https://mcp.example.com/.well-known/oauth-protected-resource/mcp/t/${token}/invoice`;
  const f = gated(url, {
    [prmUrl]: { resource: url, authorization_servers: ['https://mcp.example.com'] },
    'https://mcp.example.com/.well-known/oauth-authorization-server': AS_OK('https://mcp.example.com'),
  }, prmUrl);
  const r = await checkServer(url, { fetch: f });
  assert.equal(r.auth, 'oauth');
  const text = JSON.stringify(r);
  assert.ok(!text.includes(token), 'token must not appear in the result');
  assert.equal(r.url, 'https://mcp.example.com/mcp/t/REDACTED/invoice');
  assert.equal(r.redacted, true);
  assert.match(byId(r, 'auth_prm').detail, /REDACTED/);
  assert.equal(byId(r, 'auth_resource').status, 'pass'); // compared on the raw URL, shown redacted
  assert.match(byId(r, 'auth_resource').detail, /REDACTED/);
});

test('P1-1: random path segments and secret query values are redacted; slugs are not', () => {
  assert.equal(redactUrl('https://x.com/mcp/550e8400-e29b-41d4-a716-446655440000'), 'https://x.com/mcp/REDACTED');
  assert.equal(redactUrl('https://x.com/a/deadbeefdeadbeefdeadbeef0123/mcp'), 'https://x.com/a/REDACTED/mcp');
  assert.equal(redactUrl('https://x.com/mcp?u=Zx81kQ2mWp7rTt5LbN3vYc9H&lang=en'), 'https://x.com/mcp?u=REDACTED&lang=en');
  assert.equal(redactUrl('https://x.com/mcp?token=abc&lang=en'), 'https://x.com/mcp?token=REDACTED&lang=en');
  for (const u of ['https://mcp.zovo.one/mcp/invoice/v1', 'https://x.com/mcp-server-2025-11-25-release/mcp', 'https://x.com/invoice-generator-for-small-teams/mcp']) assert.equal(redactUrl(u), u);
  assert.equal(looksSecret('mcp-server-2025-11-25-v1'), false);
  assert.equal(looksSecret('k3j4h5g6f7d8s9a0q1w2e3r4'), true);
  assert.deepEqual(secretParts('https://x.com/t/abcdefgh12/mcp'), ['abcdefgh12']);
  assert.deepEqual(scrubSecrets({ a: ['see /t/abcdefgh12 now'] }, 'https://x.com/t/abcdefgh12/mcp'), { a: ['see /t/REDACTED now'] });
});

test('P1-1: the worker stores no token in KV and old stored results are scrubbed on read', async () => {
  const token = 'Qw3eR5tY7uI9oP1aS3dF5gH7';
  const target = `https://mcp.example.com/mcp/t/${token}`;
  const store = new Map();
  const e = { RESULTS: { get: async (k, t) => (store.has(k) ? (t === 'json' ? JSON.parse(store.get(k)) : store.get(k)) : null), put: async (k, v) => { store.set(k, v); } } };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u, init = {}) => {
    u = String(u);
    if (u.startsWith('https://cloudflare-dns.com/')) return jsonRes({ Status: 0, Answer: u.includes('type=A&') || u.endsWith('type=A') ? [{ type: 1, data: PUBLIC_IP }] : [] });
    if (u === target && init.method === 'POST') {
      const b = JSON.parse(init.body);
      if (b.method === 'initialize') return jsonRes({ jsonrpc: '2.0', id: 1, result: { ...initResult, instructions: `Echoes its own URL ${target} in the instructions text.` } });
      if (b.method === 'tools/list') return jsonRes({ jsonrpc: '2.0', id: 2, result: { tools: [tool('a_b')] } });
      return jsonRes({ jsonrpc: '2.0', id: b.id, error: { code: -32601, message: 'nf' } });
    }
    if (u === target) return new Response('', { status: 405 });
    return jsonRes({}, 404);
  };
  try {
    const res = await worker.fetch(new Request(`https://mcp.zovo.one/stamp/api/check?url=${encodeURIComponent(target)}`, { headers: { 'cf-connecting-ip': '203.0.113.9' } }), e, ctx);
    assert.equal(res.status, 200);
    const body = await res.text();
    assert.ok(!body.includes(token));
    await Promise.all(waits);
    const id = await resultId(normalizeUrl(target));
    assert.ok(store.has(`r:${id}`));
    for (const v of store.values()) assert.ok(!String(v).includes(token), 'KV value leaks the token');
    // a result written by engine 1.1.0 (raw token in url and details) is scrubbed when served
    store.set('r:aaaaaaaaaaaa', JSON.stringify({ id: 'aaaaaaaaaaaa', url: target, score: 90, grade: 'A', checked_at: new Date().toISOString(), checks: [{ id: 'auth_resource', detail: `resource ${target}` }] }));
    const old = await worker.fetch(new Request('https://mcp.zovo.one/stamp/api/result/aaaaaaaaaaaa'), e, ctx);
    const oldText = await old.text();
    assert.ok(!oldText.includes(token));
    assert.match(oldText, /t\/REDACTED/);
  } finally {
    globalThis.fetch = realFetch;
  }
});

// ---------- P1-5 Gemini discovery order ----------

test('P1-5: Gemini URL order appends the well-known suffix to path issuers', () => {
  assert.deepEqual(geminiMetadataUrls('https://auth.example.com'), ['https://auth.example.com/.well-known/oauth-authorization-server', 'https://auth.example.com/.well-known/openid-configuration']);
  assert.deepEqual(geminiMetadataUrls('https://auth.example.com/realms/master/'), ['https://auth.example.com/realms/master/.well-known/oauth-authorization-server', 'https://auth.example.com/realms/master/.well-known/openid-configuration']);
  assert.equal(asMetadataUrls('https://auth.example.com/realms/master')[0], 'https://auth.example.com/.well-known/oauth-authorization-server/realms/master');
});

test('P1-5: path issuer served only in RFC 8414 form is not Gemini-ready', async () => {
  const url = 'https://mcp.example.com/mcp';
  const prm = 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp';
  const iss = 'https://auth.example.com/realms/master';
  const f = gated(url, {
    [prm]: { resource: url, authorization_servers: [iss] },
    'https://auth.example.com/.well-known/oauth-authorization-server/realms/master': AS_OK(iss),
  }, prm);
  const r = await checkServer(url, { fetch: f });
  assert.equal(byId(r, 'auth_as_metadata').status, 'pass');
  assert.equal(byId(r, 'auth_gemini_discovery').status, 'fail');
  assert.match(byId(r, 'auth_gemini_discovery').detail, /realms\/master\/\.well-known\/oauth-authorization-server.*HTTP 404/);
  assert.ok(r.stores.gemini.blockers.includes('auth_gemini_discovery'));
  assert.ok(!r.stores.claude.blockers.includes('auth_gemini_discovery'));
});

test('P1-5: an error on the first Gemini URL blocks Gemini even when the second works', async () => {
  const url = 'https://mcp.example.com/mcp';
  const prm = 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp';
  const iss = 'https://auth.example.com';
  const f = gated(url, {
    [prm]: { resource: url, authorization_servers: [iss] },
    'https://auth.example.com/.well-known/oauth-authorization-server': () => new Response('boom', { status: 500 }),
    'https://auth.example.com/.well-known/openid-configuration': AS_OK(iss),
  }, prm);
  const r = await checkServer(url, { fetch: f });
  assert.equal(byId(r, 'auth_as_metadata').status, 'pass'); // Claude/ChatGPT fall back to OIDC
  assert.equal(byId(r, 'auth_gemini_discovery').status, 'fail');
  assert.match(byId(r, 'auth_gemini_discovery').detail, /HTTP 500/);
  assert.equal(r.stores.gemini.status, 'not_ready');
  // the shared fetch cache means no URL is fetched twice
  const urls = f.calls.map((c) => c.url);
  assert.equal(urls.length, new Set(urls.map((u, i) => `${f.calls[i].method} ${u}`)).size);
});

test('P1-5: a first Gemini URL that does not answer at all lets the second decide', async () => {
  const url = 'https://mcp.example.com/mcp';
  const prm = 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp';
  const iss = 'https://auth.example.com';
  const f = gated(url, {
    [prm]: { resource: url, authorization_servers: [iss] },
    'https://auth.example.com/.well-known/oauth-authorization-server': () => { throw new TypeError('connection reset'); },
    'https://auth.example.com/.well-known/openid-configuration': AS_OK(iss),
  }, prm);
  const r = await checkServer(url, { fetch: f });
  assert.equal(byId(r, 'auth_gemini_discovery').status, 'pass');
});

// ---------- P1-6 API-key gate ----------

test('P1-6: tools behind an API key (no OAuth) are not ready for ChatGPT or Gemini; Claude only warns', async () => {
  const url = 'https://mcp.example.com/mcp';
  const f = mockFetch((method, u, body) => {
    if (u !== url) return jsonRes({}, 404);
    if (method === 'GET') return new Response('', { status: 405 });
    if (body.method === 'initialize') return jsonRes({ jsonrpc: '2.0', id: 1, result: initResult });
    return jsonRes({ error: 'missing x-api-key' }, 401);
  });
  const r = await checkServer(url, { fetch: f });
  assert.equal(r.auth, 'other');
  const am = byId(r, 'auth_method');
  assert.equal(am.status, 'fail');
  assert.equal(am.store_status.claude, 'warn');
  assert.match(am.fix, /ChatGPT and Gemini cannot send a static API key/);
  for (const s of ['chatgpt', 'gemini']) { assert.equal(r.stores[s].ready, false, s); assert.ok(r.stores[s].blockers.includes('auth_method'), s); }
  assert.deepEqual(r.stores.claude.blockers, []);
  assert.equal(r.stores.claude.status, 'unverified'); // tools could not be seen
  assert.equal(r.stores.registry.status, 'ready');
});

// ---------- P1-7 ChatGPT metadata ----------

test('P1-7: ChatGPT needs issuer == authorization_servers entry and token_endpoint_auth_methods_supported', async () => {
  const url = 'https://mcp.example.com/mcp';
  const prm = 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp';
  const mk = (asDoc) => gated(url, {
    [prm]: { resource: url, authorization_servers: ['https://auth.example.com'] },
    'https://auth.example.com/.well-known/oauth-authorization-server': asDoc,
  }, prm);
  let r = await checkServer(url, { fetch: mk(AS_OK('https://auth.example.com', { issuer: 'https://auth.example.com/' })) });
  let c = byId(r, 'auth_chatgpt_metadata');
  assert.equal(c.status, 'fail');
  assert.match(c.detail, /issuer "https:\/\/auth\.example\.com\/" is not exactly/);
  assert.ok(r.stores.chatgpt.blockers.includes('auth_chatgpt_metadata'));
  assert.ok(!r.stores.claude.blockers.includes('auth_chatgpt_metadata'));
  const noTam = AS_OK('https://auth.example.com'); delete noTam.token_endpoint_auth_methods_supported;
  r = await checkServer(url, { fetch: mk(noTam) });
  c = byId(r, 'auth_chatgpt_metadata');
  assert.equal(c.status, 'fail');
  assert.match(c.detail, /token_endpoint_auth_methods_supported missing/);
  r = await checkServer(url, { fetch: mk(AS_OK('https://auth.example.com')) });
  assert.equal(byId(r, 'auth_chatgpt_metadata').status, 'pass');
});

// ---------- P2-11 DNS / redirect guard ----------

test('P2-11: isPrivateIp covers mapped, compat, 6to4, NAT64, site-local and CGNAT forms', () => {
  for (const ip of ['::ffff:7f00:1', '::ffff:127.0.0.1', '::127.0.0.1', '::7f00:1', '::ffff:0:7f00:1', '2002:7f00:1::', '2002:c0a8:0101::1', '2002:0a00:0001::', 'fec0::1', 'feff::1',
    '64:ff9b::7f00:1', '64:ff9b::10.0.0.1', '64:ff9b:1::1', '100.64.0.1', '100.127.255.254', '2001:db8::1', '2001::1', 'fe80::1%en0', '::', '0:0:0:0:0:0:0:1', '[::1]', '256.0.0.1']) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '2606:4700::1111', '2002:0808:0808::1', '64:ff9b::808:808', '::ffff:8.8.8.8', '2001:4860:4860::8888', '100.128.0.1']) assert.equal(isPrivateIp(ip), false, ip);
  assert.deepEqual(parseIPv6('::ffff:1.2.3.4'), [0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304]);
  assert.equal(parseIPv6('1:2:3:4:5:6:7:8:9'), null);
});

test('P2-11: a redirect hop that resolves to a private address is refused before it is fetched', async () => {
  const f = mockFetch((method, u) => {
    if (u.startsWith('https://httpbin.example.org/')) return new Response('', { status: 307, headers: { location: 'https://localhost-alias.example.net/mcp' } });
    return jsonRes({ jsonrpc: '2.0', id: 1, result: initResult });
  });
  const resolve = async (host) => (host === 'localhost-alias.example.net' ? ['127.0.0.1'] : [PUBLIC_IP]);
  const r = await rawCheck('https://httpbin.example.org/redirect', { fetch: f, resolve });
  assert.equal(f.calls.length, 1);
  assert.equal(r.reachable, false);
  assert.equal(r.error_code, 'blocked_host');
  assert.match(r.error, /resolves to a private/);
});

test('P2-11: discovery URLs pass the same guard (resource_metadata on an internal name is not fetched)', async () => {
  const url = 'https://mcp.example.com/mcp';
  const f = mockFetch((method, u) => {
    if (u === url) return jsonRes({}, 401, { 'www-authenticate': 'Bearer resource_metadata="https://meta.corp-dns.example.com/prm"' });
    return jsonRes({}, 404);
  });
  const resolve = async (host) => (host === 'meta.corp-dns.example.com' ? ['10.1.2.3'] : [PUBLIC_IP]);
  const r = await rawCheck(url, { fetch: f, resolve });
  assert.ok(!f.calls.some((c) => c.url.includes('corp-dns')));
  assert.match(byId(r, 'auth_prm').detail, /blocked URL: meta\.corp-dns\.example\.com resolves to a private/);
});

test('P2-11: the default guard resolves through DNS-over-HTTPS and refuses private answers', async () => {
  const doh = async (u) => {
    const name = new URL(u).searchParams.get('name');
    const type = new URL(u).searchParams.get('type');
    const data = { 'rebind.example.com': { A: ['192.168.1.10'], AAAA: [] }, 'v6.example.com': { A: [], AAAA: ['::ffff:7f00:1'] }, 'ok.example.com': { A: [PUBLIC_IP], AAAA: [] } }[name];
    const ans = (data ? data[type] : []).map((d) => ({ type: type === 'A' ? 1 : 28, data: d }));
    return jsonRes({ Status: data ? 0 : 3, Answer: ans });
  };
  const guard = makeHostGuard({ fetch: doh });
  assert.equal((await guard('https://rebind.example.com/mcp')).ok, false);
  assert.equal((await guard('https://v6.example.com/mcp')).ok, false);
  assert.equal((await guard('https://ok.example.com/mcp')).ok, true);
  const nx = await guard('https://nx.example.com/mcp');
  assert.equal(nx.ok, false);
  assert.equal(nx.error, 'unreachable');
  assert.equal((await guard('https://localho.st/mcp')).ok, false); // public wildcard-to-loopback name
  // DoH down: fail closed by default, open only when asked (the Worker has global_fetch_strictly_public)
  const down = async () => { throw new Error('offline'); };
  assert.equal((await makeHostGuard({ fetch: down })('https://ok.example.com/')).ok, false);
  assert.equal((await makeHostGuard({ fetch: down, failClosed: false })('https://ok.example.com/')).ok, true);
});

// ---------- P2-12 workers.dev off ----------

test('P2-12: workers_dev is false; the Action and docs use mcp.zovo.one/stamp', () => {
  const toml = readFileSync(new URL('../wrangler.toml', import.meta.url), 'utf8');
  assert.match(toml, /^workers_dev = false$/m);
  const action = readFileSync(new URL('../action.yml', import.meta.url), 'utf8') + readFileSync(new URL('../action/run.mjs', import.meta.url), 'utf8');
  assert.ok(!action.includes('workers.dev'));
  assert.match(action, /https:\/\/mcp\.zovo\.one\/stamp/);
});

// ---------- P2-13/14 firewall pages ----------

const CF_PAGE = '<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head><body>blocked</body></html>';

test('P2-13/14: a 403 HTML firewall page on initialize is blocked_by_firewall, not sign-in', async () => {
  const f = mockFetch(() => new Response(CF_PAGE, { status: 403, headers: { 'content-type': 'text/html; charset=UTF-8', server: 'cloudflare' } }));
  const r = await checkServer('https://mcp.example.com/mcp', { fetch: f });
  assert.equal(r.reachable, false);
  assert.equal(r.error_code, 'blocked_by_firewall');
  assert.match(r.error, /firewall, bot protection or access rule/);
  assert.doesNotMatch(r.error, /sign-in required|sign in|use MCP OAuth|try again/i);
  assert.ok(r.checks.every((c) => !/Use MCP OAuth/.test(c.fix || '')));
  assert.equal(f.calls.length, 1);
  assert.equal(isFirewall({ status: 403, headers: {}, contentType: 'application/json', text: '{}' }), false);
  assert.equal(isFirewall({ status: 403, headers: { 'www-authenticate': 'Bearer' }, contentType: 'text/html', text: '<html>' }), false);
  assert.equal(isFirewall({ status: 429, headers: { 'cf-mitigated': 'challenge' }, contentType: 'text/html', text: '' }), true);
  // plain-text access-rule page (httpbin.org "Forbidden redirect URL") is a block page, not a credential gate
  assert.equal(isFirewall({ status: 403, headers: {}, contentType: 'text/plain', text: 'Forbidden redirect URL.' }), true);
  assert.equal(isFirewall({ status: 403, headers: {}, contentType: '', text: '{"message":"Forbidden"}' }), false);
});

test('P2-13/14: a firewall page on tools/list is "blocked", not "needs authorization"', async () => {
  const f = mockFetch((method, u, body) => {
    if (method === 'GET') return new Response('', { status: 405 });
    if (body.method === 'initialize') return jsonRes({ jsonrpc: '2.0', id: 1, result: initResult });
    return new Response(CF_PAGE, { status: 403, headers: { 'content-type': 'text/html' } });
  });
  const r = await checkServer('https://mcp.example.com/mcp', { fetch: f });
  assert.equal(r.auth, 'none');
  assert.equal(byId(r, 'tools_list').skip_reason, 'blocked');
  assert.match(byId(r, 'tools_list').detail, /firewall/);
  assert.equal(r.limited, false);
});

test('P2-13/14: the API answers 502 blocked_by_firewall with the honest message', async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u) => {
    if (String(u).startsWith('https://cloudflare-dns.com/')) return jsonRes({ Status: 0, Answer: [{ type: 1, data: PUBLIC_IP }] });
    return new Response(CF_PAGE, { status: 403, headers: { 'content-type': 'text/html' } });
  };
  try {
    const store = new Map();
    const e = { RESULTS: { get: async () => null, put: async (k, v) => { store.set(k, v); } } };
    const res = await worker.fetch(new Request(`https://mcp.zovo.one/stamp/api/check?url=${encodeURIComponent('https://fw.example.com/mcp')}`, { headers: { 'cf-connecting-ip': '203.0.113.10' } }), e, { waitUntil() {} });
    assert.equal(res.status, 502);
    const b = await res.json();
    assert.equal(b.error, 'blocked_by_firewall');
    assert.match(b.detail, /firewall, bot protection or access rule/);
    assert.equal(store.size, 0);
  } finally {
    globalThis.fetch = realFetch;
  }
});

// ---------- P2-15 budget skips ----------

test('P2-15: budget-skipped blockers are "not probed" and make the store unverified', async () => {
  const url = 'https://mcp.example.com/mcp';
  const f = mockFetch((method, u, body) => {
    if (u !== url) return jsonRes({}, 404);
    if (method === 'GET') return new Response('', { status: 405 });
    if (body.method === 'initialize') return jsonRes({ jsonrpc: '2.0', id: 1, result: initResult });
    return jsonRes({ jsonrpc: '2.0', id: body.id, result: { tools: [tool('a_b')] } });
  });
  const r = await checkServer(url, { fetch: f, maxRequests: 1 });
  const tl = byId(r, 'tools_list');
  assert.equal(tl.status, 'skip');
  assert.equal(tl.skip_reason, 'not_probed');
  assert.match(tl.detail, /^Not probed \(request budget\)/);
  assert.doesNotMatch(tl.detail, /sign-in|authorization/);
  assert.equal(r.budget_hit, 'request budget');
  for (const s of ['claude', 'chatgpt', 'gemini']) {
    assert.equal(r.stores[s].status, 'unverified', s);
    assert.equal(r.stores[s].unverified_reasons.tools_list, 'not_probed', s);
  }
  assert.equal(r.limited, false);
  const text = formatCheck({ ...r, badge_url: 'b', report_url: 'r' }).text;
  assert.match(text, /could not verify tools_list, .*\(not probed, request or time budget\)/);
});

test('P2-15: AS metadata cut by the budget is skipped (unverified), not a warning that passes the store', async () => {
  const url = 'https://mcp.example.com/mcp';
  const prm = 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp';
  const f = gated(url, { [prm]: { resource: url, authorization_servers: ['https://auth.example.com/realms/x'] } }, prm);
  const r = await checkServer(url, { fetch: f, maxRequests: 3 });
  const c = byId(r, 'auth_as_metadata');
  assert.equal(c.status, 'skip');
  assert.equal(c.skip_reason, 'not_probed');
  assert.ok(r.stores.gemini.unverified.includes('auth_as_metadata'));
});

// ---------- P2-16 Claude annotation rule ----------

test('P2-16: one hint per tool satisfies Claude; ChatGPT still needs all three', async () => {
  const url = 'https://mcp.example.com/mcp';
  const tools = [tool('read_it', { readOnlyHint: true }), tool('delete_it', { destructiveHint: true })];
  const f = mockFetch((method, u, body) => {
    if (u !== url) return jsonRes({}, 404);
    if (method === 'GET') return new Response('', { status: 405 });
    if (body.method === 'initialize') return jsonRes({ jsonrpc: '2.0', id: 1, result: initResult });
    if (body.method === 'tools/list') return jsonRes({ jsonrpc: '2.0', id: 2, result: { tools } });
    return jsonRes({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'nf' } });
  });
  const r = await checkServer(url, { fetch: f });
  assert.equal(byId(r, 'tool_annotations').status, 'pass');
  assert.equal(byId(r, 'tool_open_world').status, 'fail');
  assert.equal(r.stores.claude.status, 'ready');
  assert.deepEqual(r.stores.chatgpt.blockers, ['tool_open_world']);
});

// ---------- P2-17 legacy SSE ----------

test('P2-17: legacy HTTP+SSE blocks Gemini and ChatGPT, not Claude or the Registry', async () => {
  const url = 'https://mcp.example.com/sse';
  const f = mockFetch((method, u) => {
    if (u !== url) return jsonRes({}, 404);
    if (method === 'GET') {
      return new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('event: endpoint\ndata: /messages?sessionId=abc\n\n')); /* stream stays open */ } }), { headers: { 'content-type': 'text/event-stream' } });
    }
    return new Response('Method Not Allowed', { status: 405, headers: { 'content-type': 'text/plain' } });
  });
  const t0 = Date.now();
  const r = await checkServer(url, { fetch: f });
  assert.ok(Date.now() - t0 < 3000, 'GET stops after the endpoint event');
  const init = byId(r, 'initialize');
  assert.equal(init.status, 'fail');
  assert.match(init.detail, /legacy HTTP\+SSE/);
  assert.deepEqual(init.store_status, { claude: 'warn', registry: 'warn' });
  assert.ok(r.stores.gemini.blockers.includes('initialize'));
  assert.ok(r.stores.chatgpt.blockers.includes('initialize'));
  assert.ok(!r.stores.claude.blockers.includes('initialize'));
  assert.equal(r.stores.claude.status, 'unverified');
  assert.equal(r.stores.registry.status, 'ready');
});

// ---------- P2-18 missing PRM, AS metadata on origin ----------

test('P2-18: no PRM but origin AS metadata (2025-03-26) warns for Claude and blocks ChatGPT', async () => {
  const url = 'https://mcp.example.com/mcp';
  const f = mockFetch((method, u) => {
    if (u === url) return jsonRes({}, 401, { 'www-authenticate': 'Bearer realm="mcp"' });
    if (u === 'https://mcp.example.com/.well-known/oauth-authorization-server') return jsonRes(AS_OK('https://mcp.example.com'));
    return jsonRes({}, 404);
  });
  const r = await checkServer(url, { fetch: f });
  assert.equal(r.auth, 'oauth');
  const prm = byId(r, 'auth_prm');
  assert.equal(prm.status, 'fail');
  assert.equal(prm.store_status.claude, 'warn');
  assert.ok(!r.stores.claude.blockers.includes('auth_prm'));
  assert.ok(r.stores.chatgpt.blockers.includes('auth_prm'));
  assert.equal(byId(r, 'auth_gemini_discovery').status, 'pass');
});

// ---------- P2-19 / P2-20 texts ----------

test('P2-19/20: registry meaning and sourced protocol fix text', async () => {
  assert.match(STORE_MEANING.registry, /valid remote for the MCP Registry/);
  assert.match(STORE_MEANING.registry, /does not mean the server is published/);
  assert.ok(explainCheck('https').store_meaning['MCP Registry']);
  const url = 'https://mcp.example.com/mcp';
  const f = mockFetch((method, u, body) => {
    if (method === 'GET') return new Response('', { status: 405 });
    if (body.method === 'initialize') return jsonRes({ jsonrpc: '2.0', id: 1, result: { ...initResult, protocolVersion: '2024-11-05' } });
    if (body.method === 'tools/list') return jsonRes({ jsonrpc: '2.0', id: 2, result: { tools: [tool('a_b')] } });
    return jsonRes({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'nf' } });
  });
  const r = await checkServer(url, { fetch: f });
  const pv = byId(r, 'protocol_version');
  assert.doesNotMatch(pv.fix, /not accepted by store clients/);
  assert.match(pv.fix, /Gemini Connected Apps requires 2025-03-26/);
  assert.deepEqual(r.stores.claude.blockers, []);
  const res = await worker.fetch(new Request('https://mcp.zovo.one/stamp/api/checks'), {}, { waitUntil() {} });
  const j = await res.json();
  assert.match(j.store_meaning.registry, /valid remote/);
  assert.ok(j.skip_reasons.not_probed);
});

// ---------- P2-23 badge staleness ----------

test('P2-23: a badge for a result older than 7 days re-checks in the background and refreshes KV', async () => {
  const url = 'https://stale.example.com/mcp';
  const id = await resultId(normalizeUrl(url));
  const store = new Map();
  const old = new Date(Date.now() - STALE_MS - 3600e3).toISOString();
  store.set(`r:${id}`, JSON.stringify({ id, url: normalizeUrl(url), score: 50, grade: 'D', checked_at: old }));
  const puts = [];
  const e = { RESULTS: { get: async (k, t) => (store.has(k) ? (t === 'json' ? JSON.parse(store.get(k)) : store.get(k)) : null), put: async (k, v, o) => { puts.push([k, o]); store.set(k, v); } } };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u, init = {}) => {
    u = String(u);
    if (u.startsWith('https://cloudflare-dns.com/')) return jsonRes({ Status: 0, Answer: [{ type: 1, data: PUBLIC_IP }] });
    if (u !== url) return jsonRes({}, 404);
    if ((init.method || 'GET') === 'GET') return new Response('', { status: 405 });
    const b = JSON.parse(init.body);
    if (b.method === 'initialize') return jsonRes({ jsonrpc: '2.0', id: 1, result: initResult });
    if (b.method === 'tools/list') return jsonRes({ jsonrpc: '2.0', id: 2, result: { tools: [tool('a_b')] } });
    return jsonRes({ jsonrpc: '2.0', id: b.id, error: { code: -32601, message: 'nf' } });
  };
  try {
    const res = await worker.fetch(new Request(`https://mcp.zovo.one/stamp/badge/${id}.svg`, { headers: { 'cf-connecting-ip': '203.0.113.11' } }), e, ctx);
    assert.match(await res.text(), /50 D/); // the old badge is served immediately
    assert.equal(waits.length, 1);
    await Promise.all(waits);
    await Promise.all(waits.slice(1));
    const fresh = JSON.parse(store.get(`r:${id}`));
    assert.notEqual(fresh.checked_at, old);
    assert.ok(fresh.score > 50);
    assert.ok(puts.some(([k, o]) => k === `r:${id}` && o.expirationTtl === 30 * 24 * 3600));
    // a second badge request right after does not re-check again
    const before = waits.length;
    await worker.fetch(new Request(`https://mcp.zovo.one/stamp/badge/${id}.svg`, { headers: { 'cf-connecting-ip': '203.0.113.11' } }), e, ctx);
    assert.equal(waits.length, before);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('P2-23: fresh results and redacted URLs are not re-checked from the badge id', async () => {
  const store = new Map();
  const e = { RESULTS: { get: async (k) => (store.has(k) ? JSON.parse(store.get(k)) : null), put: async () => {} } };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  store.set('r:bbbbbbbbbbbb', JSON.stringify({ id: 'bbbbbbbbbbbb', url: 'https://x.example.com/mcp', score: 90, grade: 'A', checked_at: new Date().toISOString() }));
  store.set('r:cccccccccccc', JSON.stringify({ id: 'cccccccccccc', url: 'https://x.example.com/t/REDACTED', score: 90, grade: 'A', checked_at: new Date(Date.now() - 2 * STALE_MS).toISOString() }));
  await worker.fetch(new Request('https://mcp.zovo.one/stamp/badge/bbbbbbbbbbbb.svg'), e, ctx);
  await worker.fetch(new Request('https://mcp.zovo.one/stamp/badge/cccccccccccc.svg'), e, ctx);
  assert.equal(waits.length, 0);
});

// ---------- P2-28 SSE parsing and wall time ----------

test('P2-28: SSE parser handles boundaries split across chunks', () => {
  const p = new SSEParser();
  const parts = ['event: message\r\ndata: {"jsonrpc":"2.0",', '"id":1,"result":{}}\r', '\n\r', '\ndata: {"id":2,"result":{}}\n', '\n'];
  const seen = [];
  for (const x of parts) seen.push(...p.push(x));
  assert.deepEqual(seen.map((m) => m.id), [1, 2]);
  assert.deepEqual(parseSSE('data: {"a":1}\n\ndata: {"b":2}').map((m) => Object.keys(m)[0]), ['a', 'b']);
});

test('P2-28: a 1.1 MB SSE stream without the wanted id is parsed in linear time', async () => {
  const chunk = new TextEncoder().encode(('data: {"jsonrpc":"2.0","method":"notifications/message","params":{"x":"' + 'a'.repeat(900) + '"}}\n\n').slice(0, 1000).padEnd(1000, ' '));
  const sse = () => { let n = 0; return new ReadableStream({ pull(c) { if (n++ >= 1100) return c.close(); c.enqueue(chunk); } }); };
  const f = async () => new Response(sse(), { status: 200, headers: { 'content-type': 'text/event-stream' } });
  const cpu0 = process.cpuUsage();
  const r = await checkServer('https://mcp.example.com/mcp', { fetch: f });
  const cpu = process.cpuUsage(cpu0);
  const ms = (cpu.user + cpu.system) / 1000;
  assert.ok(ms < 1500, `cpu ${ms} ms`);
  assert.equal(r.reachable, true);
});

test('P2-28: the whole check stops at the wall-time budget', async () => {
  const slow = (url, init) => new Promise((resolve, reject) => {
    const t = setTimeout(() => resolve(jsonRes({ jsonrpc: '2.0', id: 1, result: initResult })), 5000);
    init.signal.addEventListener('abort', () => { clearTimeout(t); reject(Object.assign(new Error('aborted'), { name: 'AbortError' })); });
  });
  const t0 = Date.now();
  const r = await checkServer('https://mcp.example.com/mcp', { fetch: slow, timeoutMs: 8000, deadlineMs: 1500 });
  assert.ok(Date.now() - t0 < 2500, `took ${Date.now() - t0} ms`);
  assert.equal(r.reachable, false);
  assert.match(r.error, /timeout after 1500 ms/);
});

test('engine version is 1.2.0', () => {
  assert.equal(ENGINE_VERSION, '1.2.0');
  assert.equal(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version, '1.2.0');
});
