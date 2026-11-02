// McpStamp Check engine. Pure ESM: no Worker-only or Node-only APIs.
// Usage: const result = await checkServer(url, { fetch, timeoutMs, userAgent });
// The caller provides fetch. The engine never sends more than `maxRequests` logical
// HTTP requests per run (default 5; redirect hops are bounded separately, max 3).

import { checkUrlSafety, normalizeUrl, redactUrl } from './ssrf.mjs';

export const ENGINE_VERSION = '1.0.0';
export const LATEST_PROTOCOL = '2025-11-25';
export const KNOWN_PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
export const DEFAULT_UA = 'McpStampCheck/1.0 (+https://www.mcpstamp.com/check/)';
export const STORES = ['claude', 'chatgpt', 'gemini', 'registry'];
export const STORE_TITLES = {
  claude: 'Claude Directory',
  chatgpt: 'ChatGPT Apps',
  gemini: 'Gemini Connected Apps',
  registry: 'MCP Registry',
};

const ALL = ['claude', 'chatgpt', 'gemini', 'registry'];
const AI = ['claude', 'chatgpt', 'gemini'];

// stores: where the check counts toward the store score.
// blocks: stores for which a "fail" on this check means "not ready".
export const CHECKS = [
  // transport
  { id: 'https', group: 'transport', title: 'Served over HTTPS', weight: 10, stores: ALL, blocks: ALL },
  { id: 'initialize', group: 'transport', title: 'initialize over Streamable HTTP', weight: 15, stores: ALL, blocks: ALL },
  { id: 'protocol_version', group: 'transport', title: 'Supported protocol version negotiated', weight: 6, stores: ALL, blocks: ['gemini'] },
  { id: 'content_type', group: 'transport', title: 'JSON or SSE response Content-Type', weight: 3, stores: ALL, blocks: [] },
  { id: 'jsonrpc_errors', group: 'transport', title: 'JSON-RPC error for unknown method', weight: 4, stores: ALL, blocks: [] },
  { id: 'get_stream', group: 'transport', title: 'GET answers SSE or 405', weight: 3, stores: ALL, blocks: [] },
  { id: 'latency', group: 'transport', title: 'initialize latency', weight: 5, stores: ALL, blocks: [] },
  // metadata
  { id: 'server_info', group: 'metadata', title: 'serverInfo name and version', weight: 6, stores: ALL, blocks: [] },
  { id: 'instructions', group: 'metadata', title: 'Server instructions', weight: 4, stores: AI, blocks: [] },
  { id: 'capabilities_tools', group: 'metadata', title: 'tools capability declared', weight: 3, stores: ALL, blocks: [] },
  // auth (skipped when no auth is detected)
  { id: 'auth_challenge', group: 'auth', title: '401 carries WWW-Authenticate resource_metadata', weight: 6, stores: AI, blocks: [] },
  { id: 'auth_prm', group: 'auth', title: 'Protected resource metadata (RFC 9728)', weight: 8, stores: AI, blocks: ['claude', 'chatgpt'] },
  { id: 'auth_resource', group: 'auth', title: 'Resource metadata "resource" equals the server URL', weight: 4, stores: AI, blocks: ['claude'] },
  { id: 'auth_as_metadata', group: 'auth', title: 'Authorization server metadata (RFC 8414 / OIDC)', weight: 8, stores: AI, blocks: AI },
  { id: 'auth_pkce', group: 'auth', title: 'PKCE S256 advertised', weight: 6, stores: AI, blocks: AI },
  { id: 'auth_registration', group: 'auth', title: 'Client registration (DCR or Client ID Metadata Documents)', weight: 6, stores: AI, blocks: [] },
  { id: 'auth_refresh', group: 'auth', title: 'refresh_token grant advertised', weight: 3, stores: AI, blocks: [] },
  // tools
  { id: 'tools_list', group: 'tools', title: 'tools/list returns tools', weight: 10, stores: ALL, blocks: AI },
  { id: 'tool_schema', group: 'tools', title: 'inputSchema is an object schema', weight: 6, stores: ALL, blocks: AI },
  { id: 'tool_names', group: 'tools', title: 'Tool names are valid and portable', weight: 5, stores: ALL, blocks: [] },
  { id: 'tool_annotations', group: 'tools', title: 'readOnlyHint and destructiveHint on every tool', weight: 10, stores: AI, blocks: ['claude', 'chatgpt'] },
  { id: 'tool_open_world', group: 'tools', title: 'Explicit readOnlyHint, destructiveHint and openWorldHint (ChatGPT)', weight: 5, stores: ['chatgpt'], blocks: ['chatgpt'] },
  { id: 'tool_titles', group: 'tools', title: 'Human-readable title on every tool', weight: 5, stores: AI, blocks: ['claude', 'chatgpt'] },
  { id: 'tool_descriptions', group: 'tools', title: 'Tool descriptions', weight: 6, stores: AI, blocks: [] },
];

const CHECK_BY_ID = Object.fromEntries(CHECKS.map((c) => [c.id, c]));
const STATUS_VALUE = { pass: 1, warn: 0.5, fail: 0 };
/** Score cap when tools sit behind authorization and could not be inspected. */
export const LIMITED_CAP = 85;

export function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

// ---------- HTTP helpers ----------

function parseSSE(text) {
  const msgs = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data = block.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, '')).join('\n');
    if (!data) continue;
    try { msgs.push(JSON.parse(data)); } catch { /* partial or non-JSON event */ }
  }
  return msgs;
}

function findById(msgs, id) {
  for (const m of msgs) {
    if (Array.isArray(m)) { const f = findById(m, id); if (f) return f; continue; }
    if (m && typeof m === 'object' && m.id === id && ('result' in m || 'error' in m)) return m;
  }
  return null;
}

async function readBody(res, { maxBytes, isSSE, wantId, stopAfterBytes }) {
  if (!res.body) return { text: '', truncated: false };
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let text = '';
  let bytes = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      text += dec.decode(value, { stream: true });
      if (bytes > maxBytes) { truncated = true; break; }
      if (stopAfterBytes && bytes >= stopAfterBytes) break;
      if (isSSE && wantId !== undefined && findById(parseSSE(text), wantId)) break;
    }
  } finally {
    try { await reader.cancel(); } catch { /* ignore */ }
  }
  return { text, truncated };
}

function headerObj(h) {
  const o = {};
  if (h && typeof h.forEach === 'function') h.forEach((v, k) => { o[k.toLowerCase()] = v; });
  return o;
}

class Ctx {
  constructor(opts) {
    this.fetch = opts.fetch;
    this.timeoutMs = opts.timeoutMs;
    this.ua = opts.userAgent;
    this.max = opts.maxRequests;
    this.maxBytes = opts.maxBodyBytes;
    this.extraHeaders = opts.headers || {};
    this.validate = opts.validateUrl;
    this.used = 0;
    this.log = [];
  }

  hasBudget(n = 1) { return this.used + n <= this.max; }

  /**
   * One logical request (redirects followed manually, max 3, each hop re-validated).
   * Returns {status, headers, contentType, text, json, messages, ms, finalUrl, redirects}
   * or {error, ms} / {budget:true}.
   */
  async request(url, { method = 'GET', headers = {}, body, wantId, sseStopBytes, sseNoRead } = {}) {
    if (!this.hasBudget()) return { budget: true, error: 'request budget exhausted' };
    this.used++;
    const t0 = Date.now();
    let cur = url;
    const redirects = [];
    for (let hop = 0; hop <= 3; hop++) {
      const v = this.validate(cur);
      if (!v.ok) return { error: `blocked redirect target: ${v.reason}`, blocked: true, ms: Date.now() - t0, redirects };
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), this.timeoutMs);
      let res;
      try {
        res = await this.fetch(cur, {
          method,
          headers: { 'user-agent': this.ua, ...this.extraHeaders, ...headers },
          body,
          redirect: 'manual',
          signal: ac.signal,
        });
      } catch (e) {
        clearTimeout(timer);
        const msg = e && e.name === 'AbortError' ? `timeout after ${this.timeoutMs} ms` : String((e && e.message) || e);
        this.log.push({ method, url: cur, error: msg });
        return { error: msg, ms: Date.now() - t0, redirects };
      }
      const loc = res.headers.get('location');
      if ([301, 302, 303, 307, 308].includes(res.status) && loc) {
        clearTimeout(timer);
        try { res.body && (await res.body.cancel()); } catch { /* ignore */ }
        if (hop === 3) return { error: 'more than 3 redirects', ms: Date.now() - t0, redirects };
        let next;
        try { next = new URL(loc, cur).href; } catch { return { error: 'invalid redirect Location', ms: Date.now() - t0, redirects }; }
        redirects.push({ status: res.status, to: next });
        cur = next;
        continue;
      }
      const contentType = (res.headers.get('content-type') || '').toLowerCase();
      const isSSE = contentType.includes('text/event-stream');
      let text = '';
      let truncated = false;
      try {
        if (isSSE && sseNoRead) {
          try { res.body && (await res.body.cancel()); } catch { /* ignore */ }
        } else {
          ({ text, truncated } = await readBody(res, { maxBytes: this.maxBytes, isSSE, wantId, stopAfterBytes: isSSE ? sseStopBytes : 0 }));
        }
      } catch (e) {
        const aborted = e && e.name === 'AbortError';
        if (!(isSSE && aborted && text)) {
          clearTimeout(timer);
          const msg = aborted ? `timeout after ${this.timeoutMs} ms while reading body` : String((e && e.message) || e);
          this.log.push({ method, url: cur, status: res.status, error: msg });
          return { status: res.status, headers: headerObj(res.headers), contentType, error: msg, ms: Date.now() - t0, redirects, finalUrl: cur };
        }
      }
      clearTimeout(timer);
      const out = {
        status: res.status,
        headers: headerObj(res.headers),
        contentType,
        text,
        truncated,
        ms: Date.now() - t0,
        finalUrl: cur,
        redirects,
        isSSE,
      };
      if (isSSE) out.messages = parseSSE(text);
      else if (text) { try { out.json = JSON.parse(text); } catch { /* not JSON */ } }
      this.log.push({ method, url: cur, status: res.status, ms: out.ms });
      return out;
    }
    return { error: 'redirect loop', ms: Date.now() - t0, redirects };
  }
}

function rpcMessage(r, id) {
  if (!r || r.error && r.status === undefined) return null;
  if (r.isSSE) return findById(r.messages || [], id);
  if (r.json !== undefined) {
    if (Array.isArray(r.json)) return findById(r.json, id);
    if (r.json && typeof r.json === 'object' && 'jsonrpc' in r.json) return r.json;
  }
  return null;
}

/** Parse a WWW-Authenticate header into {scheme, params}. */
export function parseWwwAuthenticate(value) {
  if (!value) return null;
  const m = value.match(/^\s*([A-Za-z][\w-]*)\s*(.*)$/s);
  if (!m) return null;
  const params = {};
  const re = /([\w-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))/g;
  let p;
  while ((p = re.exec(m[2]))) params[p[1].toLowerCase()] = p[2] !== undefined ? p[2].replace(/\\(.)/g, '$1') : p[3];
  return { scheme: m[1].toLowerCase(), params };
}

function isAuthStatus(r) { return r && (r.status === 401 || r.status === 403); }

function asMetadataUrls(issuer) {
  let u;
  try { u = new URL(issuer); } catch { return []; }
  const path = u.pathname.replace(/\/$/, '');
  if (!path) return [`${u.origin}/.well-known/oauth-authorization-server`, `${u.origin}/.well-known/openid-configuration`];
  return [
    `${u.origin}/.well-known/oauth-authorization-server${path}`,
    `${u.origin}/.well-known/openid-configuration${path}`,
    `${u.origin}${path}/.well-known/openid-configuration`,
  ];
}

function prmUrls(serverUrl) {
  const u = new URL(serverUrl);
  const path = u.pathname.replace(/\/$/, '');
  const root = `${u.origin}/.well-known/oauth-protected-resource`;
  return path ? [`${root}${path}`, root] : [root];
}

// ---------- main ----------

/**
 * Check a remote MCP server.
 * @param {string} url
 * @param {{fetch:Function,timeoutMs?:number,userAgent?:string,maxRequests?:number,maxBodyBytes?:number,headers?:object,validateUrl?:Function}} opts
 */
export async function checkServer(url, opts = {}) {
  const {
    fetch,
    timeoutMs = 8000,
    userAgent = DEFAULT_UA,
    maxRequests = 5,
    maxBodyBytes = 1024 * 1024,
    headers = {},
    validateUrl = checkUrlSafety,
  } = opts;
  if (typeof fetch !== 'function') throw new TypeError('checkServer: opts.fetch is required');
  const started = Date.now();
  const ctx = new Ctx({ fetch, timeoutMs, userAgent, maxRequests, maxBodyBytes, headers, validateUrl });
  const s = { url: String(url) }; // collected state

  let normalized;
  try { normalized = normalizeUrl(url); } catch { normalized = String(url); }
  s.isHttps = /^https:\/\//i.test(normalized);
  const safety = validateUrl(normalized);

  const finish = (extra = {}) => buildResult(s, ctx, { normalized, started, ...extra });

  if (!safety.ok) {
    s.blocked = safety.reason;
    return finish({ reachable: false, error: `${safety.error}: ${safety.reason}` });
  }

  const postHeaders = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
  const rpc = (method, params, id, extraH = {}) =>
    ctx.request(normalized, {
      method: 'POST',
      headers: { ...postHeaders, ...extraH },
      body: JSON.stringify(id === undefined ? { jsonrpc: '2.0', method, ...(params ? { params } : {}) } : { jsonrpc: '2.0', id, method, ...(params ? { params } : {}) }),
      wantId: id,
    });

  // 1. initialize
  const init = await rpc('initialize', {
    protocolVersion: LATEST_PROTOCOL,
    capabilities: {},
    clientInfo: { name: 'McpStampCheck', title: 'McpStamp Check', version: ENGINE_VERSION },
  }, 1);
  s.init = init;
  if (init.error && init.status === undefined) {
    return finish({ reachable: false, error: `unreachable: ${init.error}` });
  }
  s.initMsg = rpcMessage(init, 1);
  s.initResult = s.initMsg && s.initMsg.result && typeof s.initMsg.result === 'object' ? s.initMsg.result : null;
  s.sessionId = init.headers && init.headers['mcp-session-id'];
  const sessionH = {};
  if (s.sessionId) sessionH['mcp-session-id'] = s.sessionId;
  const negotiated = s.initResult && typeof s.initResult.protocolVersion === 'string' ? s.initResult.protocolVersion : null;
  if (negotiated) sessionH['mcp-protocol-version'] = negotiated;

  const challenges = [];
  const noteAuth = (r, where) => {
    if (isAuthStatus(r)) challenges.push({ where, status: r.status, www: r.headers && r.headers['www-authenticate'] || null });
  };
  noteAuth(init, 'initialize');

  if (s.initResult) {
    // 2. initialized notification (only for stateful servers, which may require it)
    if (s.sessionId) {
      s.notified = await rpc('notifications/initialized', null, undefined, sessionH);
    }
    // 3. tools/list
    s.tools = await rpc('tools/list', {}, 2, sessionH);
    noteAuth(s.tools, 'tools/list');
    s.toolsMsg = rpcMessage(s.tools, 2);
    // 4. unknown method
    s.unknown = await rpc('mcpstamp/unknown-method-probe', {}, 3, sessionH);
    noteAuth(s.unknown, 'unknown method');
    s.unknownMsg = rpcMessage(s.unknown, 3);
  }

  // GET behaviour (lowest priority when auth discovery still needs requests)
  const doGet = async () => {
    s.get = await ctx.request(normalized, {
      method: 'GET',
      headers: { accept: 'text/event-stream', ...sessionH },
      sseNoRead: !!s.initResult,
      sseStopBytes: 4096,
    });
    noteAuth(s.get, 'GET');
  };

  // Auth discovery
  const discover = async (probeOnly) => {
    const ch = challenges.find((c) => c.www) || null;
    const parsed = ch ? parseWwwAuthenticate(ch.www) : null;
    s.challenge = ch ? { ...ch, parsed } : (challenges[0] || null);
    const candidates = [];
    if (parsed && parsed.params.resource_metadata) candidates.push(parsed.params.resource_metadata);
    for (const u of prmUrls(normalized)) if (!candidates.includes(u)) candidates.push(u);
    s.prmTried = [];
    const limit = probeOnly ? 1 : candidates.length;
    for (const cand of candidates.slice(0, limit)) {
      if (!ctx.hasBudget()) { s.prmBudget = true; break; }
      const r = await ctx.request(cand, { headers: { accept: 'application/json' } });
      s.prmTried.push({ url: cand, status: r.status, error: r.error });
      if (r.status === 200 && r.json && typeof r.json === 'object' && !Array.isArray(r.json) && (r.json.resource || r.json.authorization_servers)) {
        s.prm = r.json;
        s.prmUrl = cand;
        break;
      }
    }
    if (probeOnly && !s.prm) return;
    let issuers = [];
    if (s.prm && Array.isArray(s.prm.authorization_servers)) issuers = s.prm.authorization_servers.filter((x) => typeof x === 'string');
    else if (challenges.length) issuers = [new URL(normalized).origin]; // 2025-03-26 fallback
    s.asTried = [];
    if (issuers.length) {
      for (const cand of asMetadataUrls(issuers[0])) {
        if (!ctx.hasBudget()) { s.asBudget = true; break; }
        const r = await ctx.request(cand, { headers: { accept: 'application/json' } });
        s.asTried.push({ url: cand, status: r.status, error: r.error });
        if (r.status === 200 && r.json && typeof r.json === 'object' && (r.json.authorization_endpoint || r.json.token_endpoint)) {
          s.asMeta = r.json;
          s.asUrl = cand;
          break;
        }
      }
    }
  };

  if (!s.initResult) {
    if (challenges.length) await discover(false);
    if (ctx.hasBudget()) await doGet();
    if (!challenges.length && s.get && isAuthStatus(s.get) && ctx.hasBudget()) await discover(false);
  } else if (challenges.length) {
    await discover(false);
    if (ctx.hasBudget()) await doGet();
  } else {
    if (ctx.hasBudget()) await doGet();
    if (s.get && isAuthStatus(s.get)) { if (ctx.hasBudget()) await discover(false); }
    else if (ctx.hasBudget()) await discover(true); // look for OAuth on servers that gate only tool calls
  }
  s.challenges = challenges;

  // Gateway errors without a JSON-RPC body (502-504, Cloudflare 520-530) mean the server is down.
  if (!s.initResult && !isAuthStatus(init) && ((init.status >= 502 && init.status <= 504) || (init.status >= 520 && init.status <= 530)) && !rpcMessage(init, 1)) {
    return finish({ reachable: false, error: `unreachable: HTTP ${init.status} from the gateway` });
  }
  return finish({ reachable: true });
}

// ---------- evaluation ----------

const r1 = (n) => Math.round(n * 10) / 10;
function listNames(arr, n = 5) {
  const head = arr.slice(0, n).join(', ');
  return arr.length > n ? `${head} and ${arr.length - n} more` : head;
}

function evaluate(s, ctx) {
  const out = {};
  const set = (id, status, detail, fix = null) => { out[id] = { status, detail, fix: status === 'pass' || status === 'skip' ? null : fix }; };
  const init = s.init || {};
  const authGated = isAuthStatus(init);

  // https
  if (s.isHttps) set('https', 'pass', 'URL uses https://');
  else set('https', 'fail', 'URL is not https://', 'Serve the MCP endpoint over HTTPS with a valid public certificate.');

  if (s.blocked) {
    for (const c of CHECKS) if (!out[c.id]) set(c.id, 'skip', 'URL was not checked: ' + s.blocked);
    return out;
  }

  // initialize
  if (s.initResult) {
    set('initialize', 'pass', `HTTP ${init.status}, ${init.isSSE ? 'SSE' : 'JSON'} body, ${init.ms} ms` + (s.sessionId ? ', session id issued' : ''));
  } else if (authGated) {
    if (s.prm || s.asMeta) set('initialize', 'pass', `HTTP ${init.status} with an OAuth challenge: initialize needs a signed-in user`);
    else set('initialize', 'fail', `HTTP ${init.status} and no OAuth discovery: store clients cannot sign in`, 'Use MCP OAuth (protected resource metadata + authorization server metadata) or answer initialize without auth; store clients cannot send API keys.');
  } else if (init.error && init.status === undefined) {
    set('initialize', 'fail', 'No HTTP response: ' + init.error, 'Make the endpoint publicly reachable over HTTPS and answer POST initialize within 8 s.');
  } else {
    const legacy = s.get && s.get.isSSE && /event:\s*endpoint/.test(s.get.text || '');
    const msg = rpcMessage(init, 1);
    let detail = `HTTP ${init.status}`;
    if (msg && msg.error) detail += `, JSON-RPC error ${msg.error.code}: ${String(msg.error.message || '').slice(0, 120)}`;
    else if (init.contentType) detail += `, ${init.contentType.split(';')[0]} body without a JSON-RPC result`;
    if (init.error) detail += ` (${init.error})`;
    if (legacy) {
      detail += '; GET opens a legacy HTTP+SSE (2024-11-05) stream';
      set('initialize', 'fail', detail, 'Move from the legacy HTTP+SSE transport to Streamable HTTP: answer JSON-RPC POSTs on one endpoint.');
    } else {
      set('initialize', 'fail', detail, 'Answer POST {"method":"initialize"} with a JSON-RPC result (application/json or text/event-stream) on this exact URL.');
    }
  }

  const ir = s.initResult;
  // protocol version
  if (!ir) set('protocol_version', 'skip', 'initialize did not complete');
  else {
    const v = ir.protocolVersion;
    if (v === '2025-11-25' || v === '2025-06-18') set('protocol_version', 'pass', `Negotiated ${v}`);
    else if (v === '2025-03-26') set('protocol_version', 'warn', 'Negotiated 2025-03-26', 'Support protocol version 2025-11-25 (or 2025-06-18) and echo it back in initialize.');
    else if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && v > LATEST_PROTOCOL) set('protocol_version', 'fail', `Negotiated ${v}, newer than the ${LATEST_PROTOCOL} the client asked for`, `When the client asks for ${LATEST_PROTOCOL}, answer with ${LATEST_PROTOCOL}.`);
    else set('protocol_version', 'fail', v ? `Negotiated ${v}` : 'No protocolVersion in the initialize result', `Return protocolVersion "${LATEST_PROTOCOL}" (or "2025-06-18") in the initialize result; 2024-11-05 is not accepted by store clients.`);
  }

  // content type
  if (!ir) set('content_type', 'skip', 'initialize did not complete');
  else {
    const ct = init.contentType || '';
    if (ct.includes('application/json') || ct.includes('text/event-stream')) set('content_type', 'pass', ct.split(';')[0]);
    else set('content_type', 'fail', `Content-Type "${ct || 'missing'}"`, 'Send Content-Type: application/json (or text/event-stream) on JSON-RPC responses.');
  }

  // unknown method
  const un = s.unknown;
  if (!un) set('jsonrpc_errors', 'skip', ir ? 'Not probed (request budget)' : 'initialize did not complete');
  else if (un.budget) set('jsonrpc_errors', 'skip', 'Not probed (request budget)');
  else {
    const m = s.unknownMsg;
    if (m && m.error && m.error.code === -32601) set('jsonrpc_errors', 'pass', `-32601 Method not found (HTTP ${un.status})`);
    else if (m && m.error && Number.isInteger(m.error.code)) set('jsonrpc_errors', 'warn', `JSON-RPC error ${m.error.code} instead of -32601`, 'Return JSON-RPC error code -32601 (Method not found) for unknown methods.');
    else if (isAuthStatus(un)) set('jsonrpc_errors', 'warn', `HTTP ${un.status} instead of a JSON-RPC error`, 'Route the method first and answer unknown methods with JSON-RPC error -32601 before the auth check, or return a JSON-RPC error body with the 401.');
    else if (m && 'result' in m) set('jsonrpc_errors', 'fail', 'Unknown method returned a result', 'Return JSON-RPC error -32601 (Method not found) for unknown methods instead of a result.');
    else set('jsonrpc_errors', 'fail', `HTTP ${un.status ?? 'error'} without a JSON-RPC error body${un.error ? ' (' + un.error + ')' : ''}`, 'Answer unknown methods with {"jsonrpc":"2.0","id":<id>,"error":{"code":-32601,"message":"Method not found"}}.');
  }

  // GET behaviour
  const g = s.get;
  if (!g || g.budget) set('get_stream', 'skip', 'Not probed (request budget)');
  else if (g.status === 405) set('get_stream', 'pass', 'HTTP 405 (no server-initiated stream)');
  else if (g.isSSE && g.status === 200) set('get_stream', 'pass', 'HTTP 200 text/event-stream');
  else if (isAuthStatus(g)) set('get_stream', 'pass', `HTTP ${g.status} (auth required)`);
  else if (g.status === 400) set('get_stream', 'warn', 'HTTP 400 on GET', 'Return HTTP 405 Method Not Allowed on GET when you do not offer a server-to-client SSE stream.');
  else set('get_stream', 'fail', g.status ? `HTTP ${g.status} ${(g.contentType || '').split(';')[0]}` : `No response: ${g.error}`, 'Return HTTP 405 Method Not Allowed on GET (or a text/event-stream), not a page or 404.');

  // latency
  if (init.status === undefined || init.ms === undefined) set('latency', 'skip', 'No response');
  else if (!s.initResult && !authGated) set('latency', 'skip', 'initialize did not complete');
  else if (init.ms < 1500) set('latency', 'pass', `${init.ms} ms`);
  else if (init.ms < 4000) set('latency', 'warn', `${init.ms} ms`, 'Bring initialize under 1.5 s: avoid cold starts and upstream calls in the handshake.');
  else set('latency', 'fail', `${init.ms} ms`, 'Bring initialize under 1.5 s: avoid cold starts and upstream calls in the handshake.');

  // metadata
  if (!ir) {
    for (const id of ['server_info', 'instructions', 'capabilities_tools']) set(id, 'skip', 'initialize did not complete');
  } else {
    const si = ir.serverInfo || {};
    if (si.name && si.version) set('server_info', 'pass', `${si.name} ${si.version}`);
    else set('server_info', si.name ? 'warn' : 'fail', `serverInfo ${JSON.stringify(si).slice(0, 120)}`, 'Return serverInfo with both name and version (and a title) in the initialize result.');
    const ins = typeof ir.instructions === 'string' ? ir.instructions.trim() : '';
    if (ins.length >= 40) set('instructions', 'pass', `${ins.length} characters`);
    else if (ins.length) set('instructions', 'warn', `Only ${ins.length} characters`, 'Expand initialize.instructions to 1-3 sentences on what the server covers and its limits.');
    else set('instructions', 'fail', 'No instructions in the initialize result', 'Add an "instructions" string to the initialize result: what the server covers, for whom, and its limits.');
    if (ir.capabilities && ir.capabilities.tools) set('capabilities_tools', 'pass', 'capabilities.tools present');
    else set('capabilities_tools', 'fail', 'capabilities.tools missing', 'Declare "tools": {} in the initialize capabilities.');
  }

  // auth
  evaluateAuth(s, set);

  // tools
  evaluateTools(s, set);

  return out;
}

function evaluateAuth(s, set) {
  const challenges = s.challenges || [];
  const authSeen = challenges.length > 0;
  const ids = ['auth_challenge', 'auth_prm', 'auth_resource', 'auth_as_metadata', 'auth_pkce', 'auth_registration', 'auth_refresh'];
  if (!authSeen && !s.prm) {
    s.auth = s.initResult ? 'none' : 'unknown';
    for (const id of ids) set(id, 'skip', s.initResult ? 'No authorization detected (open server)' : 'Auth not determined');
    return;
  }
  s.auth = s.prm || s.asMeta ? 'oauth' : 'other';

  // challenge
  const ch = s.challenge;
  if (!authSeen) set('auth_challenge', 'skip', 'No 401 seen on the probed requests (OAuth found via well-known metadata)');
  else if (ch && ch.parsed && ch.parsed.scheme === 'bearer' && ch.parsed.params.resource_metadata) set('auth_challenge', 'pass', `${ch.where}: HTTP ${ch.status} Bearer resource_metadata=${ch.parsed.params.resource_metadata}`);
  else if (ch && ch.parsed) set('auth_challenge', 'warn', `${ch.where}: WWW-Authenticate ${ch.parsed.scheme} without resource_metadata`, 'Add resource_metadata="https://<host>/.well-known/oauth-protected-resource<path>" to the WWW-Authenticate: Bearer header on 401.');
  else set('auth_challenge', 'fail', `${challenges[0].where}: HTTP ${challenges[0].status} without WWW-Authenticate`, 'On 401, send WWW-Authenticate: Bearer resource_metadata="<protected resource metadata URL>".');

  // PRM
  if (s.prm) {
    const as = Array.isArray(s.prm.authorization_servers) ? s.prm.authorization_servers : [];
    if (as.length) set('auth_prm', 'pass', `${s.prmUrl} lists ${as.length} authorization server(s)`);
    else set('auth_prm', 'fail', `${s.prmUrl} has no authorization_servers`, 'List your issuer URL in "authorization_servers" in the protected resource metadata.');
  } else {
    const tried = (s.prmTried || []).map((t) => `${t.url} -> ${t.status ?? t.error}`).join('; ');
    set('auth_prm', 'fail', tried ? `Not found: ${tried}` : 'Not probed', 'Serve RFC 9728 metadata at /.well-known/oauth-protected-resource (plus the path-suffixed form) with "resource" and "authorization_servers".');
  }

  // resource match
  if (!s.prm) set('auth_resource', 'skip', 'No protected resource metadata');
  else {
    const res = s.prm.resource;
    let exact = false; let same = false;
    try {
      const a = new URL(res); const b = new URL(s.url);
      same = a.origin === b.origin;
      exact = same && a.pathname.replace(/\/$/, '') === b.pathname.replace(/\/$/, '') && a.search === b.search;
    } catch { /* invalid */ }
    if (exact) set('auth_resource', 'pass', `resource ${res}`);
    else set('auth_resource', 'fail', `resource ${res ?? 'missing'} is not the server URL ${s.url}`, `Serve metadata whose "resource" is exactly ${s.url} (Claude requires an exact match, path included), e.g. at /.well-known/oauth-protected-resource${(() => { try { return new URL(s.url).pathname.replace(/\/$/, ''); } catch { return ''; } })()}.`);
  }

  // AS metadata
  const am = s.asMeta;
  if (am) {
    const missing = ['authorization_endpoint', 'token_endpoint'].filter((k) => typeof am[k] !== 'string');
    const rts = am.response_types_supported;
    if (!Array.isArray(rts) || !rts.includes('code')) missing.push('response_types_supported:["code"]');
    if (!missing.length) set('auth_as_metadata', 'pass', `${s.asUrl}`);
    else set('auth_as_metadata', 'fail', `${s.asUrl} lacks ${missing.join(', ')}`, `Add ${missing.join(', ')} to the authorization server metadata.`);
  } else {
    const tried = (s.asTried || []).map((t) => `${t.url} -> ${t.status ?? t.error}`).join('; ');
    if (s.asBudget && !tried) set('auth_as_metadata', 'skip', 'Not probed (request budget)');
    else set('auth_as_metadata', s.asBudget ? 'warn' : 'fail', tried ? `Not found: ${tried}${s.asBudget ? ' (budget stopped further locations)' : ''}` : 'No authorization server to probe', 'Serve RFC 8414 metadata at <issuer>/.well-known/oauth-authorization-server with authorization_endpoint, token_endpoint and response_types_supported ["code"].');
  }
  if (!am) {
    for (const id of ['auth_pkce', 'auth_registration', 'auth_refresh']) set(id, 'skip', 'No authorization server metadata');
    return;
  }
  const pk = am.code_challenge_methods_supported;
  if (Array.isArray(pk) && pk.includes('S256')) set('auth_pkce', 'pass', `code_challenge_methods_supported: ${pk.join(', ')}`);
  else set('auth_pkce', 'fail', pk ? `code_challenge_methods_supported: ${JSON.stringify(pk)}` : 'code_challenge_methods_supported missing', 'Support PKCE and advertise "code_challenge_methods_supported": ["S256"] (MCP clients refuse to proceed without it).');
  const dcr = typeof am.registration_endpoint === 'string';
  const cimd = am.client_id_metadata_document_supported === true;
  if (dcr || cimd) set('auth_registration', 'pass', [dcr && 'Dynamic Client Registration', cimd && 'Client ID Metadata Documents'].filter(Boolean).join(' + '));
  else set('auth_registration', 'warn', 'No registration_endpoint and no client_id_metadata_document_supported', 'Add a Dynamic Client Registration endpoint (RFC 7591) or set client_id_metadata_document_supported: true; otherwise every store needs a manually issued client id.');
  const gt = am.grant_types_supported;
  if (Array.isArray(gt) && gt.includes('refresh_token')) set('auth_refresh', 'pass', 'refresh_token in grant_types_supported');
  else set('auth_refresh', 'warn', gt ? `grant_types_supported: ${JSON.stringify(gt)}` : 'grant_types_supported missing', 'Issue refresh tokens and list "refresh_token" in grant_types_supported so users are not logged out hourly.');
}

const SPEC_NAME = /^[A-Za-z0-9_.-]{1,128}$/;
const PORTABLE_NAME = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/;

function evaluateTools(s, set) {
  const ids = ['tools_list', 'tool_schema', 'tool_names', 'tool_annotations', 'tool_open_world', 'tool_titles', 'tool_descriptions'];
  const t = s.tools;
  if (!s.initResult) { for (const id of ids) set(id, 'skip', isAuthStatus(s.init) ? 'Tools are behind authorization' : 'initialize did not complete'); return; }
  if (!t || t.budget) { for (const id of ids) set(id, 'skip', 'Not probed (request budget)'); return; }
  if (isAuthStatus(t)) { for (const id of ids) set(id, 'skip', `tools/list needs authorization (HTTP ${t.status})`); return; }
  const m = s.toolsMsg;
  const tools = m && m.result && Array.isArray(m.result.tools) ? m.result.tools : null;
  if (!tools) {
    set('tools_list', 'fail', m && m.error ? `JSON-RPC error ${m.error.code}: ${String(m.error.message || '').slice(0, 120)}` : `HTTP ${t.status ?? t.error} without a tools array`, 'Answer tools/list with {"result":{"tools":[...]}}.');
    for (const id of ids.slice(1)) set(id, 'skip', 'No tools to inspect');
    return;
  }
  s.toolCount = tools.length;
  s.toolsPaged = !!(m.result && m.result.nextCursor);
  if (!tools.length) {
    set('tools_list', 'fail', 'tools/list returned 0 tools', 'Expose at least one tool in tools/list (store reviewers test tools).');
    for (const id of ids.slice(1)) set(id, 'skip', 'No tools to inspect');
    return;
  }
  set('tools_list', 'pass', `${tools.length} tool(s)${s.toolsPaged ? ' on the first page' : ''}`);
  const nm = (x, i) => (x && typeof x.name === 'string' ? x.name : `#${i + 1}`);
  const ann = (x) => (x && x.annotations && typeof x.annotations === 'object' ? x.annotations : {});

  const badSchema = tools.filter((x) => !(x && x.inputSchema && typeof x.inputSchema === 'object' && x.inputSchema.type === 'object')
    || (x.outputSchema !== undefined && !(x.outputSchema && x.outputSchema.type === 'object'))).map(nm);
  if (!badSchema.length) set('tool_schema', 'pass', `All ${tools.length} inputSchema are type "object"`);
  else set('tool_schema', 'fail', `${badSchema.length}/${tools.length} invalid: ${listNames(badSchema)}`, 'Give every tool an inputSchema with "type": "object" (use {"type":"object","properties":{}} for no arguments).');

  const names = tools.map(nm);
  const dup = names.filter((n, i) => names.indexOf(n) !== i);
  const invalid = names.filter((n) => !SPEC_NAME.test(n));
  const nonPortable = names.filter((n) => SPEC_NAME.test(n) && !PORTABLE_NAME.test(n));
  if (dup.length || invalid.length) set('tool_names', 'fail', [dup.length && `duplicates: ${listNames([...new Set(dup)])}`, invalid.length && `invalid: ${listNames(invalid)}`].filter(Boolean).join('; '), 'Use unique tool names of 1-64 characters from A-Z a-z 0-9 _ - (start with a letter).');
  else if (nonPortable.length) set('tool_names', 'warn', `Not portable (dots, over 64 chars or leading digit/dash): ${listNames(nonPortable)}`, 'Rename tools to ^[A-Za-z_][A-Za-z0-9_-]{0,63}$ so every client and model API accepts them.');
  else set('tool_names', 'pass', `All ${tools.length} names match ^[A-Za-z_][A-Za-z0-9_-]{0,63}$`);

  const noRD = tools.filter((x) => typeof ann(x).readOnlyHint !== 'boolean' || (ann(x).readOnlyHint === false && typeof ann(x).destructiveHint !== 'boolean')).map(nm);
  if (!noRD.length) set('tool_annotations', 'pass', `All ${tools.length} tools set readOnlyHint${tools.some((x) => ann(x).readOnlyHint === false) ? ' (and destructiveHint on write tools)' : ''}`);
  else set('tool_annotations', 'fail', `${noRD.length}/${tools.length} tools lack them: ${listNames(noRD)}`, 'Set annotations.readOnlyHint on every tool, and destructiveHint on every tool where readOnlyHint is false.');

  const noOW = tools.filter((x) => ['readOnlyHint', 'destructiveHint', 'openWorldHint'].some((k) => typeof ann(x)[k] !== 'boolean')).map(nm);
  if (!noOW.length) set('tool_open_world', 'pass', `All ${tools.length} tools set all three hints explicitly`);
  else set('tool_open_world', 'fail', `${noOW.length}/${tools.length} tools miss an explicit hint: ${listNames(noOW)}`, 'Set readOnlyHint, destructiveHint and openWorldHint to explicit true/false on every tool (OpenAI app review requires all three).');

  const noTitle = tools.filter((x) => !(typeof x.title === 'string' && x.title.trim()) && !(typeof ann(x).title === 'string' && ann(x).title.trim())).map(nm);
  if (!noTitle.length) set('tool_titles', 'pass', `All ${tools.length} tools have a title`);
  else set('tool_titles', 'fail', `${noTitle.length}/${tools.length} without title: ${listNames(noTitle)}`, 'Add a short human-readable "title" to every tool (shown in store UIs and consent screens).');

  const desc = (x) => (typeof x.description === 'string' ? x.description.trim() : '');
  const noDesc = tools.filter((x) => desc(x).length < 20).map(nm);
  const short = tools.filter((x) => desc(x).length >= 20 && desc(x).length < 60).map(nm);
  const long = tools.filter((x) => desc(x).length > 2000).map(nm);
  if (noDesc.length) set('tool_descriptions', 'fail', `${noDesc.length}/${tools.length} missing or under 20 chars: ${listNames(noDesc)}`, 'Write a 1-3 sentence description for every tool: when to use it and what it returns.');
  else if (short.length || long.length) set('tool_descriptions', 'warn', [short.length && `${short.length} under 60 chars: ${listNames(short)}`, long.length && `${long.length} over 2000 chars: ${listNames(long)}`].filter(Boolean).join('; '), 'Keep each tool description between 60 and 2000 characters: when to use it, what it returns, key limits.');
  else set('tool_descriptions', 'pass', `All ${tools.length} descriptions 60-2000 chars`);
}

function scoreOf(checks) {
  let num = 0; let den = 0;
  for (const c of checks) {
    if (c.status === 'skip') continue;
    num += c.weight * STATUS_VALUE[c.status];
    den += c.weight;
  }
  return den ? Math.round((num / den) * 100) : 0;
}

function buildResult(s, ctx, { normalized, started, reachable, error }) {
  const ev = evaluate(s, ctx);
  const checks = CHECKS.map((c) => ({
    id: c.id,
    group: c.group,
    title: c.title,
    status: ev[c.id] ? ev[c.id].status : 'skip',
    weight: c.weight,
    detail: ev[c.id] ? ev[c.id].detail : '',
    fix: ev[c.id] ? ev[c.id].fix : null,
  }));
  let score = scoreOf(checks);
  // Coverage: share of applicable weight that could actually be verified.
  const authSkipped = checks.filter((c) => c.status === 'skip' && /behind authorization|needs authorization/.test(c.detail || ''));
  const verifiedW = checks.filter((c) => c.status !== 'skip').reduce((a, c) => a + c.weight, 0);
  const coverage = Math.round((verifiedW / (verifiedW + authSkipped.reduce((a, c) => a + c.weight, 0) || 1)) * 100);
  // A server whose tools could not be seen cannot earn an A: cap at 85.
  const limited = authSkipped.length > 0;
  if (limited) score = Math.min(score, LIMITED_CAP);
  if (reachable === false) score = 0;
  const stores = {};
  for (const st of STORES) {
    const mine = checks.filter((c) => CHECK_BY_ID[c.id].stores.includes(st));
    const blockers = mine.filter((c) => c.status === 'fail' && CHECK_BY_ID[c.id].blocks.includes(st)).map((c) => c.id);
    const unverified = mine.filter((c) => c.status === 'skip' && CHECK_BY_ID[c.id].blocks.includes(st) && !/No authorization detected|No tools to inspect|No authorization server metadata|No protected resource metadata|OAuth found via/.test(c.detail || '')).map((c) => c.id);
    const ok = reachable !== false && blockers.length === 0;
    const stScore = reachable === false ? 0 : limited ? Math.min(scoreOf(mine), LIMITED_CAP) : scoreOf(mine);
    stores[st] = { ready: ok, score: stScore, blockers: reachable === false ? ['initialize'] : blockers, unverified };
  }
  const ir = s.initResult || {};
  const si = ir.serverInfo || {};
  let displayUrl = normalized;
  try { displayUrl = redactUrl(normalized); } catch { /* keep */ }
  const res = {
    url: displayUrl,
    checked_at: new Date().toISOString(),
    duration_ms: Date.now() - started,
    score,
    grade: gradeFor(score),
    auth: s.auth || (reachable === false ? 'unknown' : 'unknown'),
    reachable: reachable !== false,
    protocol_version: typeof ir.protocolVersion === 'string' ? ir.protocolVersion : null,
    server: s.initResult ? { name: si.name ?? null, version: si.version ?? null, title: si.title ?? null } : null,
    tool_count: s.toolCount ?? null,
    coverage,
    limited,
    stores,
    checks,
    requests: ctx.used,
    engine: ENGINE_VERSION,
  };
  if (error) res.error = error;
  return res;
}
