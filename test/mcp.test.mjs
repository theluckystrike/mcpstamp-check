import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.mjs';
import { checkServer, CHECKS } from '../src/check.mjs';
import { normalizeUrl, resultId } from '../src/ssrf.mjs';
import { AUDIT_LINE, TOOLS } from '../src/mcp.mjs';

function env() {
  const m = new Map();
  return { RESULTS: { get: async (k, t) => (m.has(k) ? (t === 'json' ? JSON.parse(m.get(k)) : m.get(k)) : null), put: async (k, v) => { m.set(k, v); } }, _m: m };
}
const ctx = { waitUntil() {} };
const MCP = 'https://mcp.zovo.one/stamp/mcp';

async function rpc(body, { e = env(), headers = {}, url = MCP } = {}) {
  const res = await worker.fetch(new Request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }), e, ctx);
  const text = await res.text();
  return { res, status: res.status, json: text ? JSON.parse(text) : null };
}

test('initialize negotiates 2025-11-25 and returns serverInfo + instructions', async () => {
  const { status, json, res } = await rpc({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '1' } } });
  assert.equal(status, 200);
  assert.match(res.headers.get('content-type'), /application\/json/);
  assert.equal(json.id, 1);
  assert.equal(json.result.protocolVersion, '2025-11-25');
  assert.ok(json.result.capabilities.tools);
  assert.equal(json.result.serverInfo.name, 'mcpstamp-check');
  assert.equal(json.result.serverInfo.title, 'McpStamp Check');
  assert.ok(json.result.serverInfo.version);
  assert.ok(json.result.instructions.length >= 40);
  assert.equal(res.headers.get('mcp-session-id'), null);
});

test('initialize echoes an older supported version and falls back to latest for unknown', async () => {
  let r = await rpc({ jsonrpc: '2.0', id: 'a', method: 'initialize', params: { protocolVersion: '2025-06-18' } });
  assert.equal(r.json.result.protocolVersion, '2025-06-18');
  r = await rpc({ jsonrpc: '2.0', id: 'b', method: 'initialize', params: { protocolVersion: '2099-01-01' } });
  assert.equal(r.json.result.protocolVersion, '2025-11-25');
});

test('tools/list: two tools with titles, annotations and object schemas', async () => {
  const { json } = await rpc({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  const tools = json.result.tools;
  assert.deepEqual(tools.map((t) => t.name), ['check_mcp_server', 'explain_check']);
  for (const t of tools) {
    assert.ok(t.title);
    assert.ok(t.description.length >= 60 && t.description.length <= 2000);
    assert.equal(t.inputSchema.type, 'object');
    assert.equal(t.outputSchema.type, 'object');
    assert.equal(t.annotations.readOnlyHint, true);
    assert.equal(t.annotations.destructiveHint, false);
    assert.equal(typeof t.annotations.openWorldHint, 'boolean');
  }
  assert.equal(tools[0].annotations.openWorldHint, true);
  assert.deepEqual(tools[0].inputSchema.required, ['url']);
  assert.ok(tools[1].inputSchema.properties.check_id.enum.includes('tool_annotations'));
});

test('JSON-RPC errors: unknown method, parse error, batch, bad request, unknown tool', async () => {
  let r = await rpc({ jsonrpc: '2.0', id: 3, method: 'nope/nope', params: {} });
  assert.equal(r.status, 200);
  assert.equal(r.json.error.code, -32601);
  assert.equal(r.json.id, 3);
  r = await rpc('{not json');
  assert.equal(r.status, 400);
  assert.equal(r.json.error.code, -32700);
  assert.equal(r.json.id, null);
  r = await rpc([{ jsonrpc: '2.0', id: 1, method: 'ping' }]);
  assert.equal(r.json.error.code, -32600);
  r = await rpc({ id: 1, method: 'ping' });
  assert.equal(r.json.error.code, -32600);
  r = await rpc({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'delete_everything', arguments: {} } });
  assert.equal(r.json.error.code, -32602);
  r = await rpc({ jsonrpc: '2.0', id: 5, method: 'ping' }, { headers: { 'mcp-protocol-version': '1999-01-01' } });
  assert.equal(r.status, 400);
});

test('notifications and client responses get 202 with no body', async () => {
  let r = await rpc({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(r.status, 202);
  assert.equal(r.json, null);
  r = await rpc({ jsonrpc: '2.0', id: 9, result: {} });
  assert.equal(r.status, 202);
});

test('GET and DELETE are 405, OPTIONS allows MCP headers, ping works on workers.dev path', async () => {
  const g = await worker.fetch(new Request(MCP, { headers: { accept: 'text/event-stream' } }), env(), ctx);
  assert.equal(g.status, 405);
  assert.match(g.headers.get('allow'), /POST/);
  const d = await worker.fetch(new Request(MCP, { method: 'DELETE' }), env(), ctx);
  assert.equal(d.status, 405);
  const o = await worker.fetch(new Request(MCP, { method: 'OPTIONS' }), env(), ctx);
  assert.equal(o.status, 204);
  assert.match(o.headers.get('access-control-allow-headers'), /mcp-protocol-version/);
  assert.match(o.headers.get('access-control-allow-methods'), /POST/);
  const p = await rpc({ jsonrpc: '2.0', id: 7, method: 'ping' }, { url: 'https://mcpstamp-check.example.workers.dev/mcp' });
  assert.deepEqual(p.json.result, {});
});

test('explain_check returns meaning, blocks and sources; unknown id is a tool error', async () => {
  let r = await rpc({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'explain_check', arguments: { check_id: 'auth_resource' } } });
  const res = r.json.result;
  assert.ok(!res.isError);
  assert.match(res.content[0].text, /Claude Directory/);
  assert.equal(res.structuredContent.id, 'auth_resource');
  assert.ok(res.structuredContent.sources[0].url.startsWith('https://'));
  r = await rpc({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'explain_check', arguments: { check_id: 'zzz' } } });
  assert.equal(r.json.result.isError, true);
});

test('every check id has an explanation', async () => {
  for (const c of CHECKS) {
    const r = await rpc({ jsonrpc: '2.0', id: c.id, method: 'tools/call', params: { name: 'explain_check', arguments: { check_id: c.id } } });
    assert.ok(r.json.result.structuredContent.meaning.length > 20, c.id);
    assert.ok(r.json.result.structuredContent.rule.length > 10, c.id);
  }
});

test('check_mcp_server: cached result -> score, stores, fixes, badge, audit line last', async () => {
  const e = env();
  const url = 'https://mcp.example.com/mcp';
  const id = await resultId(normalizeUrl(url));
  const stored = {
    id, url, checked_at: new Date().toISOString(), score: 72, grade: 'C', auth: 'none', protocol_version: '2025-11-25', tool_count: 3,
    stores: { claude: { ready: false, score: 70, blockers: ['tool_titles'] }, chatgpt: { ready: false, score: 60, blockers: ['tool_open_world', 'tool_titles'] }, gemini: { ready: true, score: 80, blockers: [] }, registry: { ready: true, score: 100, blockers: [] } },
    checks: [
      { id: 'tool_titles', group: 'tools', title: 'Human-readable title on every tool', status: 'fail', weight: 5, detail: '3/3 without title', fix: 'Add a title.' },
      { id: 'tool_descriptions', group: 'tools', title: 'Tool descriptions', status: 'warn', weight: 6, detail: 'short', fix: 'Write more.' },
      { id: 'https', group: 'transport', title: 'Served over HTTPS', status: 'pass', weight: 10, detail: 'ok', fix: null },
    ],
    badge_url: `https://www.mcpstamp.com/badge/${id}.svg`, report_url: `https://www.mcpstamp.com/check/?id=${id}`,
  };
  e._m.set(`r:${id}`, JSON.stringify(stored));
  const r = await rpc({ jsonrpc: '2.0', id: 10, method: 'tools/call', params: { name: 'check_mcp_server', arguments: { url } } }, { e });
  const res = r.json.result;
  assert.ok(!res.isError);
  const text = res.content[0].text;
  assert.match(text, /Score 72\/100, grade C/);
  assert.match(text, /ChatGPT Apps: NOT ready/);
  assert.match(text, /Fix: Add a title\./);
  assert.match(text, /\[!\[McpStamp\]\(https:\/\/www\.mcpstamp\.com\/badge\//);
  assert.equal(text.trim().split('\n').pop(), AUDIT_LINE);
  assert.equal(AUDIT_LINE, 'Need it fixed? Readiness Audit $490: https://www.mcpstamp.com/services/');
  const sc = res.structuredContent;
  assert.equal(sc.score, 72);
  assert.equal(sc.stores.gemini.ready, true);
  assert.deepEqual(sc.issues.map((i) => i.id), ['tool_titles', 'tool_descriptions']);
  assert.equal(sc.cached, true);
  assert.equal(sc.report_url, stored.report_url);
  // output matches the declared outputSchema's required keys
  for (const k of TOOLS[0].outputSchema.required) assert.ok(k in sc, k);
});

test('check_mcp_server: bad and private URLs are tool errors, missing url too', async () => {
  let r = await rpc({ jsonrpc: '2.0', id: 11, method: 'tools/call', params: { name: 'check_mcp_server', arguments: { url: 'https://127.0.0.1/mcp' } } });
  assert.equal(r.json.result.isError, true);
  assert.match(r.json.result.content[0].text, /cannot be checked/);
  r = await rpc({ jsonrpc: '2.0', id: 12, method: 'tools/call', params: { name: 'check_mcp_server', arguments: { url: 'http://example.com/mcp' } } });
  assert.equal(r.json.result.isError, true);
  r = await rpc({ jsonrpc: '2.0', id: 13, method: 'tools/call', params: { name: 'check_mcp_server', arguments: {} } });
  assert.equal(r.json.result.isError, true);
  assert.match(r.json.result.content[0].text, /Missing "url"/);
});

test('check_mcp_server shares the API rate limit (20 live checks per hour per IP)', async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('offline in tests'); };
  try {
    const headers = { 'cf-connecting-ip': '198.51.100.77' };
    const e = env();
    // 20 live checks through the API ...
    for (let i = 0; i < 20; i++) {
      const res = await worker.fetch(new Request(`https://mcp.zovo.one/stamp/api/check?fresh=1&url=${encodeURIComponent(`https://s${i}.example.com/mcp`)}`, { headers }), e, ctx);
      assert.equal(res.status, 502);
    }
    // ... use up the same budget for the MCP tool
    const r = await rpc({ jsonrpc: '2.0', id: 14, method: 'tools/call', params: { name: 'check_mcp_server', arguments: { url: 'https://other.example.com/mcp', fresh: true } } }, { e, headers });
    assert.equal(r.json.result.isError, true);
    assert.match(r.json.result.content[0].text, /Rate limited/);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('self-check: the engine grades this MCP endpoint A and ready for all 4 stores', async () => {
  const e = env();
  const f = (url, init = {}) => {
    const u = new URL(url);
    if (u.pathname.startsWith('/stamp')) return worker.fetch(new Request(url, init), e, ctx);
    return Promise.resolve(new Response(JSON.stringify({ error: 'not_found' }), { status: 404, headers: { 'content-type': 'application/json' } }));
  };
  const r = await checkServer(MCP, { fetch: f });
  const bad = r.checks.filter((c) => c.status === 'fail' || c.status === 'warn').map((c) => `${c.id}: ${c.detail}`);
  assert.deepEqual(bad, []);
  assert.equal(r.grade, 'A');
  assert.equal(r.score, 100);
  assert.equal(r.auth, 'none');
  for (const s of ['claude', 'chatgpt', 'gemini', 'registry']) assert.equal(r.stores[s].ready, true, s);
});

test('check_mcp_server shows unverified stores (tools behind sign-in) as not ready', async () => {
  const e = env();
  const url = 'https://gated.example.com/mcp';
  const id = await resultId(normalizeUrl(url));
  e._m.set(`r:${id}`, JSON.stringify({
    id, url, checked_at: new Date().toISOString(), score: 85, grade: 'B', auth: 'oauth', limited: true,
    stores: { claude: { status: 'unverified', ready: false, score: 85, blockers: [], unverified: ['tools_list', 'tool_schema'] }, chatgpt: { status: 'unverified', ready: false, score: 85, blockers: [], unverified: ['tools_list'] }, gemini: { status: 'unverified', ready: false, score: 85, blockers: [], unverified: ['tools_list'] }, registry: { status: 'ready', ready: true, score: 100, blockers: [], unverified: [] } },
    checks: [], badge_url: 'https://www.mcpstamp.com/badge/x.svg', report_url: 'https://www.mcpstamp.com/check/?id=x',
  }));
  const r = await rpc({ jsonrpc: '2.0', id: 20, method: 'tools/call', params: { name: 'check_mcp_server', arguments: { url } } }, { e });
  const text = r.json.result.content[0].text;
  assert.match(text, /Claude Directory: unverified \(score 85\), could not verify tools_list, tool_schema/);
  assert.match(text, /MCP Registry: ready/);
  assert.equal(r.json.result.structuredContent.stores.claude.status, 'unverified');
  assert.equal(r.json.result.structuredContent.stores.claude.ready, false);
});
