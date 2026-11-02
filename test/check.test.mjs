import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkServer as rawCheck, CHECKS, gradeFor, parseWwwAuthenticate, STORES, LIMITED_CAP, DEFAULT_MAX_REQUESTS } from '../src/check.mjs';

// Tests never touch the network: DNS answers come from this stub (a public address by default).
export const PUBLIC_IP = '93.184.215.14';
const checkServer = (u, o = {}) => rawCheck(u, { resolve: async () => [PUBLIC_IP], ...o });

const URL0 = 'https://mcp.example.com/mcp';
const goodTool = (name, extra = {}) => ({
  name,
  title: `Title for ${name}`,
  description: `Call ${name} to do a precise thing for the user and return a structured answer with ids.`,
  inputSchema: { type: 'object', properties: {} },
  annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  ...extra,
});
const initResult = (over = {}) => ({
  protocolVersion: '2025-11-25',
  capabilities: { tools: {} },
  serverInfo: { name: 'example', version: '1.2.3' },
  instructions: 'Example server for tests. It covers widgets and gadgets for small teams.',
  ...over,
});

function jsonRes(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

/** Build a mock fetch from a handler(method, url, body) -> Response; records calls. */
function mockFetch(handler) {
  const calls = [];
  const f = async (url, init = {}) => {
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url: String(url), method: init.method || 'GET', body, headers: init.headers });
    return handler(init.method || 'GET', String(url), body, init);
  };
  f.calls = calls;
  return f;
}

function openServer({ tools = [goodTool('list_widgets'), goodTool('get_widget')], init = {}, sse = false } = {}) {
  return mockFetch((method, url, body) => {
    if (url !== URL0) return jsonRes({ error: 'not_found' }, 404);
    if (method === 'GET') return new Response('', { status: 405 });
    if (body.method === 'initialize') {
      const msg = { jsonrpc: '2.0', id: body.id, result: initResult(init) };
      if (sse) return new Response(`event: message\ndata: ${JSON.stringify(msg)}\n\n`, { headers: { 'content-type': 'text/event-stream' } });
      return jsonRes(msg);
    }
    if (body.method === 'tools/list') return jsonRes({ jsonrpc: '2.0', id: body.id, result: { tools } });
    return jsonRes({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'Method not found' } });
  });
}

const byId = (r, id) => r.checks.find((c) => c.id === id);

test('CHECKS table is well formed', () => {
  const ids = new Set();
  for (const c of CHECKS) {
    assert.ok(c.id && !ids.has(c.id)); ids.add(c.id);
    assert.ok(['transport', 'auth', 'tools', 'metadata'].includes(c.group));
    assert.ok(c.weight > 0 && c.title);
    for (const s of [...c.stores, ...c.blocks]) assert.ok(STORES.includes(s));
    for (const s of c.blocks) assert.ok(c.stores.includes(s), `${c.id} blocks ${s} but does not count for it`);
  }
});

test('grades', () => {
  assert.equal(gradeFor(90), 'A'); assert.equal(gradeFor(89), 'B'); assert.equal(gradeFor(80), 'B');
  assert.equal(gradeFor(65), 'C'); assert.equal(gradeFor(50), 'D'); assert.equal(gradeFor(49), 'F');
});

test('good open server scores A and is ready everywhere', async () => {
  const f = openServer();
  const r = await checkServer(URL0, { fetch: f });
  assert.equal(r.reachable, true);
  assert.equal(r.auth, 'none');
  assert.equal(r.grade, 'A');
  assert.equal(r.score, 100);
  for (const s of STORES) { assert.equal(r.stores[s].ready, true, s); assert.equal(r.stores[s].status, 'ready', s); }
  assert.ok(f.calls.length <= 6, `used ${f.calls.length} requests`);
  assert.equal(byId(r, 'jsonrpc_errors').status, 'pass');
  assert.equal(byId(r, 'get_stream').status, 'pass');
  assert.equal(r.tool_count, 2);
  assert.ok(f.calls.every((c) => c.headers['user-agent'].startsWith('McpStampCheck/1.0')));
});

test('SSE initialize body is parsed', async () => {
  const r = await checkServer(URL0, { fetch: openServer({ sse: true }) });
  assert.equal(byId(r, 'initialize').status, 'pass');
  assert.match(byId(r, 'initialize').detail, /SSE/);
});

test('missing annotations and titles block Claude and ChatGPT, not Registry', async () => {
  const bare = { name: 'do_thing', description: 'Does the thing for the user and returns a result object with ids.', inputSchema: { type: 'object' } };
  const r = await checkServer(URL0, { fetch: openServer({ tools: [bare] }) });
  assert.equal(byId(r, 'tool_annotations').status, 'fail');
  assert.equal(byId(r, 'tool_titles').status, 'fail');
  assert.equal(r.stores.claude.ready, false);
  assert.equal(r.stores.claude.status, 'not_ready');
  assert.ok(r.stores.claude.blockers.includes('tool_annotations'));
  assert.ok(r.stores.chatgpt.blockers.includes('tool_open_world'));
  assert.equal(r.stores.registry.ready, true);
  for (const c of r.checks) if (c.status === 'fail' || c.status === 'warn') assert.ok(c.fix && c.fix.length > 10, `${c.id} has a fix`);
});

test('bad schema, names and old protocol', async () => {
  const tools = [goodTool('a.b'), goodTool('9bad'), goodTool('ok', { inputSchema: { type: 'string' } }), goodTool('ok')];
  const r = await checkServer(URL0, { fetch: openServer({ tools, init: { protocolVersion: '2024-11-05', instructions: undefined } }) });
  assert.equal(byId(r, 'tool_schema').status, 'fail');
  assert.equal(byId(r, 'tool_names').status, 'fail'); // duplicate "ok"
  assert.equal(byId(r, 'protocol_version').status, 'fail');
  assert.equal(byId(r, 'instructions').status, 'fail');
  assert.equal(r.stores.gemini.ready, false);
});

test('OAuth-gated server: discovery chain, limited score cap', async () => {
  const f = mockFetch((method, url, body) => {
    if (url === URL0) return jsonRes({ error: 'unauthorized' }, 401, { 'www-authenticate': 'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="read"' });
    if (url === 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp') return jsonRes({ resource: URL0, authorization_servers: ['https://auth.example.com'] });
    if (url === 'https://auth.example.com/.well-known/oauth-authorization-server') return jsonRes({
      issuer: 'https://auth.example.com', authorization_endpoint: 'https://auth.example.com/a', token_endpoint: 'https://auth.example.com/t',
      registration_endpoint: 'https://auth.example.com/r', response_types_supported: ['code'], code_challenge_methods_supported: ['S256'],
      grant_types_supported: ['authorization_code', 'refresh_token'], token_endpoint_auth_methods_supported: ['none'],
    });
    return jsonRes({}, 404);
  });
  const r = await checkServer(URL0, { fetch: f });
  assert.equal(r.auth, 'oauth');
  for (const id of ['initialize', 'auth_method', 'auth_challenge', 'auth_prm', 'auth_resource', 'auth_as_metadata', 'auth_gemini_discovery', 'auth_chatgpt_metadata', 'auth_pkce', 'auth_registration', 'auth_refresh']) assert.equal(byId(r, id).status, 'pass', id);
  assert.equal(byId(r, 'tools_list').status, 'skip');
  assert.equal(r.limited, true);
  assert.ok(r.score <= LIMITED_CAP);
  assert.ok(f.calls.length <= 6);
  // tools behind sign-in: no blocker failed, but tool blockers were skipped -> unverified, not ready
  for (const s of ['claude', 'chatgpt', 'gemini']) {
    assert.equal(r.stores[s].status, 'unverified', s);
    assert.equal(r.stores[s].ready, false, s);
    assert.deepEqual(r.stores[s].blockers, [], s);
    assert.ok(r.stores[s].unverified.includes('tools_list'), s);
    assert.equal(r.stores[s].unverified_reasons.tools_list, 'needs_sign_in', s);
  }
  assert.equal(r.stores.registry.status, 'ready');
  assert.equal(r.stores.registry.ready, true);
});

test('PRM resource that is only the origin fails for Claude', async () => {
  const f = mockFetch((method, url, body) => {
    if (url === URL0) {
      if (method === 'GET') return new Response('', { status: 405 });
      if (body.method === 'initialize') return jsonRes({ jsonrpc: '2.0', id: 1, result: initResult() });
      if (body.method === 'tools/list') return jsonRes({ jsonrpc: '2.0', id: 2, result: { tools: [goodTool('x_y')] } });
      return jsonRes({ error: 'unauthorized' }, 401, { 'www-authenticate': 'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"' });
    }
    if (url === 'https://mcp.example.com/.well-known/oauth-protected-resource') return jsonRes({ resource: 'https://mcp.example.com', authorization_servers: ['https://mcp.example.com'] });
    if (url === 'https://mcp.example.com/.well-known/oauth-authorization-server') return jsonRes({ authorization_endpoint: 'https://mcp.example.com/a', token_endpoint: 'https://mcp.example.com/t', response_types_supported: ['code'] });
    return jsonRes({}, 404);
  });
  const r = await checkServer(URL0, { fetch: f });
  assert.equal(r.auth, 'oauth');
  assert.equal(byId(r, 'jsonrpc_errors').status, 'warn');
  assert.equal(byId(r, 'auth_resource').status, 'fail');
  assert.equal(byId(r, 'auth_pkce').status, 'fail');
  assert.equal(byId(r, 'auth_registration').status, 'warn');
  assert.equal(r.stores.claude.ready, false);
  assert.ok(r.stores.claude.blockers.includes('auth_resource'));
  assert.ok(r.stores.gemini.blockers.includes('auth_pkce'));
  assert.ok(f.calls.length <= 6);
});

test('401 without OAuth discovery: transport not verified, API-key gate blocks ChatGPT and Gemini only', async () => {
  const f = mockFetch(() => jsonRes({ error: 'need api key' }, 401));
  const r = await checkServer(URL0, { fetch: f });
  assert.equal(r.auth, 'other');
  assert.equal(byId(r, 'initialize').status, 'skip');
  assert.equal(byId(r, 'initialize').skip_reason, 'needs_sign_in');
  assert.equal(byId(r, 'auth_method').status, 'fail');
  assert.equal(r.stores.claude.ready, false);
  assert.equal(r.stores.claude.status, 'unverified');
  assert.deepEqual(r.stores.claude.blockers, []);
  for (const s of ['chatgpt', 'gemini']) { assert.equal(r.stores[s].status, 'not_ready', s); assert.ok(r.stores[s].blockers.includes('auth_method'), s); }
  assert.equal(r.stores.registry.status, 'unverified');
  assert.doesNotMatch(byId(r, 'auth_method').fix, /cannot send API keys\.$/);
});

test('unreachable server: score 0, reachable false', async () => {
  const f = async () => { throw new TypeError('fetch failed'); };
  const r = await checkServer(URL0, { fetch: f });
  assert.equal(r.reachable, false);
  assert.equal(r.score, 0);
  assert.equal(r.grade, 'F');
  assert.match(r.error, /unreachable/);
});

test('timeout aborts the request', async () => {
  const f = (url, init) => new Promise((_, rej) => init.signal.addEventListener('abort', () => rej(Object.assign(new Error('aborted'), { name: 'AbortError' }))));
  const t0 = Date.now();
  const r = await checkServer(URL0, { fetch: f, timeoutMs: 50 });
  assert.ok(Date.now() - t0 < 2000);
  assert.equal(r.reachable, false);
  assert.match(r.error, /timeout/);
});

test('redirect to a private host is refused', async () => {
  const f = mockFetch(() => new Response('', { status: 307, headers: { location: 'https://127.0.0.1/mcp' } }));
  const r = await checkServer(URL0, { fetch: f });
  assert.equal(f.calls.length, 1);
  assert.equal(r.reachable, false);
  assert.equal(r.error_code, 'blocked_host');
  assert.match(r.error, /blocked redirect target/);
});

test('redirects are followed (max 3) and re-validated', async () => {
  let n = 0;
  const f = mockFetch(() => { n++; return new Response('', { status: 302, headers: { location: `https://mcp.example.com/r${n}` } }); });
  const r = await checkServer(URL0, { fetch: f, maxRequests: 1 });
  assert.equal(n, 4); // first hop + 3 redirects
  assert.match(byId(r, 'initialize').detail + (r.error || ''), /redirect/);
});

test('body over 1 MB is truncated, not buffered', async () => {
  const big = 'x'.repeat(64 * 1024);
  const f = mockFetch(() => new Response(new ReadableStream({
    start(c) { for (let i = 0; i < 40; i++) c.enqueue(new TextEncoder().encode(big)); c.close(); },
  }), { headers: { 'content-type': 'application/json' } }));
  const r = await checkServer(URL0, { fetch: f, maxBodyBytes: 256 * 1024 });
  assert.equal(byId(r, 'initialize').status, 'fail');
});

test('blocked URL is never fetched', async () => {
  const f = mockFetch(() => jsonRes({}));
  const r = await checkServer('https://localhost/mcp', { fetch: f });
  assert.equal(f.calls.length, 0);
  assert.equal(r.reachable, false);
});

test('request budget is respected for stateful servers', async () => {
  const f = mockFetch((method, url, body) => {
    if (method === 'GET') return new Response('', { status: 405 });
    if (!body.id) return new Response(null, { status: 202 });
    if (body.method === 'initialize') return jsonRes({ jsonrpc: '2.0', id: 1, result: initResult() }, 200, { 'mcp-session-id': 'abc' });
    if (body.method === 'tools/list') return jsonRes({ jsonrpc: '2.0', id: 2, result: { tools: [goodTool('a_b')] } });
    return jsonRes({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'nf' } });
  });
  const r = await checkServer(URL0, { fetch: f });
  assert.ok(f.calls.length <= 6);
  assert.equal(f.calls[1].body.method, 'notifications/initialized');
  assert.equal(f.calls[2].headers['mcp-session-id'], 'abc');
  assert.equal(f.calls[2].headers['mcp-protocol-version'], '2025-11-25');
  assert.equal(r.grade, 'A');
});

test('parseWwwAuthenticate', () => {
  const p = parseWwwAuthenticate('Bearer realm="x", error="invalid_token", resource_metadata="https://a/b"');
  assert.equal(p.scheme, 'bearer');
  assert.equal(p.params.resource_metadata, 'https://a/b');
  assert.equal(p.params.error, 'invalid_token');
});

test('Cloudflare 530 / gateway errors count as unreachable', async () => {
  const f = mockFetch(() => new Response('error code: 1016', { status: 530, headers: { 'content-type': 'text/plain' } }));
  const r = await checkServer(URL0, { fetch: f });
  assert.equal(r.reachable, false);
  assert.match(r.error, /530/);
});

test('default budget (10) reaches AS metadata when PRM is found without a 401', async () => {
  assert.equal(DEFAULT_MAX_REQUESTS, 10);
  const handler = (method, url, body) => {
    if (url.endsWith('/.well-known/oauth-protected-resource/mcp')) return jsonRes({ resource: URL0, authorization_servers: ['https://mcp.example.com'] });
    if (url.endsWith('/.well-known/oauth-authorization-server')) return jsonRes({ issuer: 'https://mcp.example.com', authorization_endpoint: 'https://mcp.example.com/authorize', token_endpoint: 'https://mcp.example.com/token', response_types_supported: ['code'], code_challenge_methods_supported: ['S256'], registration_endpoint: 'https://mcp.example.com/register', grant_types_supported: ['authorization_code', 'refresh_token'] });
    if (method === 'GET') return new Response('', { status: 405 });
    if (body.method === 'initialize') return jsonRes({ jsonrpc: '2.0', id: 1, result: initResult() });
    if (body.method === 'tools/list') return jsonRes({ jsonrpc: '2.0', id: 2, result: { tools: [goodTool('a_b')] } });
    return jsonRes({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'nf' } });
  };
  const f = mockFetch(handler);
  const r = await checkServer(URL0, { fetch: f });
  assert.equal(f.calls.length, 6); // root issuer: the Gemini URL is the RFC 8414 URL, fetched once
  assert.equal(r.requests, 6);
  const st = Object.fromEntries(r.checks.map((c) => [c.id, c.status]));
  assert.equal(st.auth_prm, 'pass');
  assert.equal(st.auth_as_metadata, 'pass');
  assert.equal(st.auth_pkce, 'pass');
  assert.equal(r.auth, 'oauth');
  assert.ok(!r.checks.some((c) => /request budget/.test(c.detail || '')));
  // the budget stays a parameter: with 5 the AS metadata probe is skipped
  const r5 = await checkServer(URL0, { fetch: mockFetch(handler), maxRequests: 5 });
  assert.equal(r5.requests, 5);
  assert.equal(r5.checks.find((c) => c.id === 'auth_as_metadata').status, 'skip');
});
