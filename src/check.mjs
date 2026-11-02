// McpStamp Check engine. Pure ESM: no Worker-only or Node-only APIs.
// Usage: const result = await checkServer(url, { fetch, timeoutMs, userAgent, resolve });
// The caller provides fetch. The engine never sends more than `maxRequests` logical HTTP
// requests per run (default 10; redirect hops are bounded separately, max 3) and stops
// starting new requests after `deadlineMs` (default 25 s). Every URL it fetches (first URL,
// each redirect hop, each discovery URL) passes the same host guard (syntax + DNS).

import { normalizeUrl, redactUrl, makeHostGuard, secretParts, scrubSecrets } from './ssrf.mjs';

export const ENGINE_VERSION = '1.2.0';
export const LATEST_PROTOCOL = '2025-11-25';
export const KNOWN_PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
/** Default cap on logical HTTP requests per check (room for PRM, AS metadata and the Gemini discovery URL). */
export const DEFAULT_MAX_REQUESTS = 10;
/** Wall-time budget per check: no new request starts after this, running ones are cut at it. */
export const DEFAULT_DEADLINE_MS = 25000;
export const DEFAULT_UA = 'McpStampCheck/1.0 (+https://www.mcpstamp.com/check/)';
export const STORES = ['claude', 'chatgpt', 'gemini', 'registry'];
export const STORE_TITLES = {
  claude: 'Claude Directory',
  chatgpt: 'ChatGPT Apps',
  gemini: 'Gemini Connected Apps',
  registry: 'MCP Registry',
};
/** What "ready" means per store key (the key "registry" is kept for API compatibility). */
export const STORE_MEANING = {
  claude: 'Every Claude Connectors Directory rule that can be checked from outside passes. Listing assets, policy review and test accounts are not checked.',
  chatgpt: 'Every ChatGPT app (plugin) rule that can be checked from outside passes. Domain verification, test cases and review are not checked.',
  gemini: 'Every Google Connected Apps (Gemini) rule that can be checked from outside passes. Access still needs Google\'s developer waitlist and console steps.',
  registry: 'A valid remote for the MCP Registry: a public https URL that answers as a Streamable HTTP (or legacy SSE) MCP server. It does not mean the server is published in the Registry; server.json and namespace auth are not checked.',
};
/** Why a check was skipped. Only "not_applicable" skips never make a store "unverified". */
export const SKIP_REASONS = {
  not_applicable: 'Does not apply to this server',
  needs_sign_in: 'Not verified: needs a signed-in user or a credential',
  not_probed: 'Not probed: the check stopped at its request or time budget',
  not_reached: 'Not verified: the MCP handshake did not complete',
  blocked: 'Not verified: a firewall or the URL guard blocked the request',
};

const ALL = ['claude', 'chatgpt', 'gemini', 'registry'];
const AI = ['claude', 'chatgpt', 'gemini'];

// stores: where the check counts toward the store score.
// blocks: stores for which a "fail" on this check means "not ready".
// A check result may soften its status for single stores (per-store status), e.g. a missing
// protected resource metadata document is only a warning for Claude when 2025-03-26 discovery works.
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
  { id: 'auth_method', group: 'auth', title: 'Sign-in method the store supports (OAuth or none)', weight: 6, stores: AI, blocks: ['chatgpt', 'gemini'] },
  { id: 'auth_challenge', group: 'auth', title: '401 carries WWW-Authenticate resource_metadata', weight: 6, stores: AI, blocks: [] },
  { id: 'auth_prm', group: 'auth', title: 'Protected resource metadata (RFC 9728)', weight: 8, stores: AI, blocks: ['claude', 'chatgpt'] },
  { id: 'auth_resource', group: 'auth', title: 'Resource metadata "resource" equals the server URL', weight: 4, stores: AI, blocks: ['claude'] },
  { id: 'auth_as_metadata', group: 'auth', title: 'Authorization server metadata (RFC 8414 / OIDC)', weight: 8, stores: AI, blocks: AI },
  { id: 'auth_gemini_discovery', group: 'auth', title: 'First metadata URL Gemini tries answers 200 with the required fields', weight: 4, stores: ['gemini'], blocks: ['gemini'] },
  { id: 'auth_chatgpt_metadata', group: 'auth', title: 'issuer equals the authorization_servers entry; token_endpoint_auth_methods_supported (ChatGPT)', weight: 4, stores: ['chatgpt'], blocks: ['chatgpt'] },
  { id: 'auth_pkce', group: 'auth', title: 'PKCE S256 advertised', weight: 6, stores: AI, blocks: AI },
  { id: 'auth_registration', group: 'auth', title: 'Client registration (DCR or Client ID Metadata Documents)', weight: 6, stores: AI, blocks: [] },
  { id: 'auth_refresh', group: 'auth', title: 'refresh_token grant advertised', weight: 3, stores: AI, blocks: [] },
  // tools
  { id: 'tools_list', group: 'tools', title: 'tools/list returns tools', weight: 10, stores: ALL, blocks: AI },
  { id: 'tool_schema', group: 'tools', title: 'inputSchema is an object schema', weight: 6, stores: ALL, blocks: AI },
  { id: 'tool_names', group: 'tools', title: 'Tool names are valid and portable', weight: 5, stores: ALL, blocks: [] },
  { id: 'tool_annotations', group: 'tools', title: 'readOnlyHint or destructiveHint on every tool', weight: 10, stores: AI, blocks: ['claude', 'chatgpt'] },
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

/**
 * Incremental SSE parser: each push() scans only the new text (plus a 3-character overlap for a
 * boundary split across chunks), so a long stream costs O(n), not O(n^2).
 */
export class SSEParser {
  constructor() {
    this.buf = '';
    this.from = 0;
    this.messages = [];
    this.events = [];
    this.blocks = 0;
  }

  /** Feed decoded text; returns the JSON messages completed by this chunk. */
  push(text) {
    this.buf += text;
    const re = /\r?\n\r?\n/g;
    re.lastIndex = this.from;
    const fresh = [];
    let start = 0;
    let m;
    while ((m = re.exec(this.buf))) {
      this.block(this.buf.slice(start, m.index), fresh);
      start = m.index + m[0].length;
    }
    if (start) this.buf = this.buf.slice(start);
    this.from = Math.max(0, this.buf.length - 3);
    return fresh;
  }

  /** End of stream: parse a last event that had no blank line after it. */
  flush() {
    const fresh = [];
    if (this.buf.trim()) this.block(this.buf, fresh);
    this.buf = '';
    this.from = 0;
    return fresh;
  }

  block(text, fresh) {
    let event = '';
    const data = [];
    for (const line of text.split(/\r?\n/)) {
      if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
      else if (line.startsWith('event:')) event = line.slice(6).trim();
    }
    if (!data.length && !event) return;
    this.blocks++;
    const d = data.join('\n');
    if (this.events.length < 20) this.events.push({ event: event || 'message', data: d.slice(0, 500) });
    if (!d) return;
    try {
      const msg = JSON.parse(d);
      this.messages.push(msg);
      fresh.push(msg);
    } catch { /* partial or non-JSON event */ }
  }
}

/** Parse a complete SSE text (tests and callers that already hold the body). */
export function parseSSE(text) {
  const p = new SSEParser();
  p.push(text);
  p.flush();
  return p.messages;
}

function findById(msgs, id) {
  for (const m of msgs) {
    if (Array.isArray(m)) { const f = findById(m, id); if (f) return f; continue; }
    if (m && typeof m === 'object' && m.id === id && ('result' in m || 'error' in m)) return m;
  }
  return null;
}

async function readBody(res, { maxBytes, isSSE, wantId, stopAfterBytes, stopAfterEvents }) {
  const parser = isSSE ? new SSEParser() : null;
  if (!res.body) return { text: '', truncated: false, parser };
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let text = '';
  let bytes = 0;
  let truncated = false;
  let found = null;
  let aborted = false;
  let error = null;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      const chunk = dec.decode(value, { stream: true });
      text += chunk;
      if (parser) {
        const fresh = parser.push(chunk);
        if (wantId !== undefined && !found && fresh.length) found = findById(fresh, wantId);
      }
      if (bytes > maxBytes) { truncated = true; break; }
      if (found) break;
      if (stopAfterBytes && bytes >= stopAfterBytes) break;
      if (parser && stopAfterEvents && parser.blocks >= stopAfterEvents) break;
    }
  } catch (e) {
    if (e && e.name === 'AbortError') aborted = true;
    else error = e;
  } finally {
    try { await reader.cancel(); } catch { /* ignore */ }
  }
  if (parser) parser.flush();
  return { text, truncated, parser, found, aborted, error };
}

function headerObj(h) {
  const o = {};
  if (h && typeof h.forEach === 'function') h.forEach((v, k) => { o[k.toLowerCase()] = v; });
  return o;
}

/**
 * True when a response is a firewall, WAF, bot-protection or access-rule block page rather than an
 * MCP or sign-in answer: Cloudflare's cf-mitigated header, or a 403 without WWW-Authenticate whose
 * body is not JSON (HTML or plain-text "Forbidden" pages). A 403 with a JSON body stays a
 * credential gate (API gateways answer {"message":"Forbidden"} for a missing key).
 */
export function isFirewall(r) {
  if (!r || r.status === undefined) return false;
  const h = r.headers || {};
  if (h['cf-mitigated']) return true;
  if (r.status !== 403 || h['www-authenticate']) return false;
  const ct = r.contentType || '';
  if (ct.includes('json')) return false;
  const body = String(r.text || '').trim();
  return !(body.startsWith('{') || body.startsWith('['));
}

function firewallLabel(r) {
  const h = r.headers || {};
  const who = h['cf-mitigated'] || /cloudflare/i.test(h.server || '') ? 'Cloudflare ' : '';
  if (h['cf-mitigated']) return `HTTP ${r.status} ${who}${h['cf-mitigated']} page`;
  const ct = (r.contentType || '').split(';')[0] || 'no content type';
  return `HTTP ${r.status} ${who}${ct.includes('html') ? 'HTML' : ct} block page`;
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
    this.deadlineMs = opts.deadlineMs;
    this.deadline = opts.started + opts.deadlineMs;
    this.used = 0;
    this.budgetHit = null;
    this.log = [];
  }

  remaining() { return this.deadline - Date.now(); }

  hasBudget(n = 1) {
    if (this.used + n > this.max) { this.budgetHit = this.budgetHit || 'request budget'; return false; }
    if (this.remaining() < 1000) { this.budgetHit = this.budgetHit || `${Math.round(this.deadlineMs / 1000)} s time budget`; return false; }
    return true;
  }

  /**
   * One logical request (redirects followed manually, max 3; every hop passes the host guard).
   * Returns {status, headers, contentType, text, json, messages, events, ms, finalUrl, redirects}
   * or {error, ms} / {budget:true} / {blocked:true}.
   */
  async request(url, { method = 'GET', headers = {}, body, wantId, sseStopBytes, sseStopEvents, sseNoRead } = {}) {
    if (!this.hasBudget()) return { budget: true, error: `${this.budgetHit} exhausted` };
    this.used++;
    const t0 = Date.now();
    let cur = url;
    const redirects = [];
    for (let hop = 0; hop <= 3; hop++) {
      const v = await this.validate(cur);
      if (!v.ok) {
        const what = hop ? 'redirect target' : 'URL';
        return { error: `blocked ${what}: ${v.reason}`, blocked: v.error === 'blocked_host' || v.error === 'bad_url', ms: Date.now() - t0, redirects };
      }
      const left = this.remaining();
      if (left <= 0) return { error: `${Math.round(this.deadlineMs / 1000)} s time budget exhausted`, ms: Date.now() - t0, redirects };
      const limit = Math.min(this.timeoutMs, left);
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), limit);
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
        const msg = e && e.name === 'AbortError' ? `timeout after ${limit} ms` : String((e && e.message) || e);
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
      let rb = { text: '', truncated: false, parser: null };
      try {
        if (isSSE && sseNoRead) {
          try { res.body && (await res.body.cancel()); } catch { /* ignore */ }
        } else {
          rb = await readBody(res, { maxBytes: this.maxBytes, isSSE, wantId, stopAfterBytes: isSSE ? sseStopBytes : 0, stopAfterEvents: isSSE ? sseStopEvents : 0 });
        }
      } catch (e) {
        rb = { text: '', truncated: false, parser: null, error: e };
      }
      clearTimeout(timer);
      const base = { status: res.status, headers: headerObj(res.headers), contentType, ms: Date.now() - t0, redirects, finalUrl: cur, isSSE };
      const partialOk = isSSE && rb.parser && (rb.found || (wantId === undefined && rb.parser.blocks > 0));
      if ((rb.aborted || rb.error) && !partialOk) {
        const msg = rb.aborted ? `timeout after ${limit} ms while reading body` : String((rb.error && rb.error.message) || rb.error);
        this.log.push({ method, url: cur, status: res.status, error: msg });
        return { ...base, text: rb.text, error: msg };
      }
      const out = { ...base, text: rb.text, truncated: rb.truncated };
      if (isSSE) {
        out.messages = rb.parser ? rb.parser.messages : [];
        out.events = rb.parser ? rb.parser.events : [];
      } else if (rb.text) { try { out.json = JSON.parse(rb.text); } catch { /* not JSON */ } }
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

/** 401/403 from the server itself (a firewall block page is not a sign-in request). */
function isAuthStatus(r) { return !!r && (r.status === 401 || r.status === 403) && !isFirewall(r); }

/** RFC 8414 / OIDC discovery URLs in MCP spec order (path issuers: path inserted after .well-known). */
export function asMetadataUrls(issuer) {
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

/**
 * The URLs the Gemini console tries, in its order (Google Connected Apps OAuth guide): the
 * well-known suffixes appended to the issuer, path included. Gemini uses the first URL that
 * returns a response, even an error.
 */
export function geminiMetadataUrls(issuer) {
  let u;
  try { u = new URL(issuer); } catch { return []; }
  const base = u.origin + u.pathname.replace(/\/$/, '');
  return [`${base}/.well-known/oauth-authorization-server`, `${base}/.well-known/openid-configuration`];
}

function prmUrls(serverUrl) {
  const u = new URL(serverUrl);
  const path = u.pathname.replace(/\/$/, '');
  const root = `${u.origin}/.well-known/oauth-protected-resource`;
  return path ? [`${root}${path}`, root] : [root];
}

function hasAsFields(j) {
  return !!(j && typeof j === 'object' && !Array.isArray(j) && (j.authorization_endpoint || j.token_endpoint));
}

// ---------- main ----------

/**
 * Check a remote MCP server.
 * @param {string} url
 * @param {{fetch:Function,timeoutMs?:number,userAgent?:string,maxRequests?:number,maxBodyBytes?:number,
 *   headers?:object,validateUrl?:Function,resolve?:Function,deadlineMs?:number,dnsFailClosed?:boolean}} opts
 * validateUrl(url) -> {ok}|Promise<{ok}> guards every fetched URL. Default: makeHostGuard with
 * opts.resolve (runtime DNS) or DNS-over-HTTPS through globalThis.fetch.
 */
export async function checkServer(url, opts = {}) {
  const {
    fetch,
    timeoutMs = 8000,
    userAgent = DEFAULT_UA,
    maxRequests = DEFAULT_MAX_REQUESTS,
    maxBodyBytes = 1024 * 1024,
    headers = {},
    deadlineMs = DEFAULT_DEADLINE_MS,
  } = opts;
  if (typeof fetch !== 'function') throw new TypeError('checkServer: opts.fetch is required');
  const validateUrl = opts.validateUrl || makeHostGuard({ resolve: opts.resolve, fetch: opts.dnsFetch, failClosed: opts.dnsFailClosed !== false });
  const started = Date.now();
  const ctx = new Ctx({ fetch, timeoutMs, userAgent, maxRequests, maxBodyBytes, headers, validateUrl, deadlineMs, started });
  const s = {}; // collected state

  let normalized;
  try { normalized = normalizeUrl(url); } catch { normalized = String(url); }
  s.url = normalized;
  try { s.displayUrl = redactUrl(normalized); } catch { s.displayUrl = normalized; }
  s.isHttps = /^https:\/\//i.test(normalized);

  const finish = (extra = {}) => buildResult(s, ctx, { normalized, started, ...extra });

  const safety = await validateUrl(normalized);
  if (!safety.ok) {
    s.blocked = safety.reason;
    return finish({ reachable: false, error: `${safety.error}: ${safety.reason}`, code: safety.error === 'unreachable' ? 'unreachable' : 'blocked_host' });
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
  if (init.blocked) {
    s.blocked = init.error;
    return finish({ reachable: false, error: `blocked_host: ${init.error}`, code: 'blocked_host' });
  }
  if (init.error && init.status === undefined) {
    return finish({ reachable: false, error: `unreachable: ${init.error}`, code: 'unreachable' });
  }
  if (isFirewall(init)) {
    s.firewall = firewallLabel(init);
    return finish({
      reachable: false,
      code: 'blocked_by_firewall',
      error: `blocked_by_firewall: ${s.firewall} from a firewall, bot protection or access rule instead of an MCP response. The request never reached the MCP server, so nothing could be scored. Store clients connect from their own IP ranges and can hit the same block: allow Anthropic (160.79.104.0/21), OpenAI and Google egress ranges on the MCP and OAuth paths, or exempt those paths from bot challenges.`,
    });
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
      sseStopEvents: 1,
    });
    noteAuth(s.get, 'GET');
  };

  // Metadata fetches are shared between the spec, Claude/ChatGPT and Gemini orders.
  const meta = new Map();
  const fetchMeta = async (u) => {
    if (meta.has(u)) return meta.get(u);
    if (!ctx.hasBudget()) return { budget: true };
    const r = await ctx.request(u, { headers: { accept: 'application/json' } });
    const out = { url: u, status: r.status, error: r.error, json: r.json, firewall: isFirewall(r) };
    meta.set(u, out);
    return out;
  };
  const triedLine = (r) => ({ url: r.url, status: r.status, error: r.error && !r.status ? r.error : undefined, firewall: r.firewall || undefined });

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
      const r = await fetchMeta(cand);
      if (r.budget) { s.prmBudget = true; break; }
      s.prmTried.push(triedLine(r));
      if (r.status === 200 && r.json && typeof r.json === 'object' && !Array.isArray(r.json) && (r.json.resource || r.json.authorization_servers)) {
        s.prm = r.json;
        s.prmUrl = cand;
        break;
      }
    }
    if (probeOnly && !s.prm) return;
    let issuers = [];
    if (s.prm && Array.isArray(s.prm.authorization_servers)) issuers = s.prm.authorization_servers.filter((x) => typeof x === 'string');
    else if (challenges.length) { issuers = [new URL(normalized).origin]; s.issuerFromOrigin = true; } // 2025-03-26 fallback
    s.issuer = issuers[0] || null;
    s.asTried = [];
    if (!s.issuer) return;
    for (const cand of asMetadataUrls(s.issuer)) {
      const r = await fetchMeta(cand);
      if (r.budget) { s.asBudget = true; break; }
      s.asTried.push(triedLine(r));
      if (r.status === 200 && hasAsFields(r.json)) {
        s.asMeta = r.json;
        s.asUrl = cand;
        break;
      }
    }
    // Gemini: the first of its URLs that answers at all decides.
    const g = { tried: [] };
    for (const cand of geminiMetadataUrls(s.issuer)) {
      const r = await fetchMeta(cand);
      if (r.budget) { g.budget = true; break; }
      g.tried.push(triedLine(r));
      if (r.status !== undefined) { g.url = cand; g.status = r.status; g.json = r.json; g.firewall = r.firewall; break; }
    }
    s.gemini = g;
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
    return finish({ reachable: false, error: `unreachable: HTTP ${init.status} from the gateway`, code: 'unreachable' });
  }
  return finish({ reachable: true });
}

// ---------- evaluation ----------

const NA = 'not_applicable';
const AUTH = 'needs_sign_in';
const BUDGET = 'not_probed';
const NOINIT = 'not_reached';
const BLOCKED = 'blocked';

function listNames(arr, n = 5) {
  const head = arr.slice(0, n).join(', ');
  return arr.length > n ? `${head} and ${arr.length - n} more` : head;
}

function triedText(list) {
  return (list || []).map((t) => `${t.url} -> ${t.status ?? t.error}${t.firewall ? ' (firewall page)' : ''}`).join('; ');
}

function evaluate(s, ctx) {
  const out = {};
  // set(id, status, detail, fix, {per: {store: status}, reason})
  const set = (id, status, detail, fix = null, extra = {}) => {
    out[id] = {
      status,
      detail,
      fix: status === 'pass' || status === 'skip' ? null : fix,
      reason: status === 'skip' ? extra.reason || NA : undefined,
      per: extra.per || null,
    };
  };
  const nb = `Not probed (${ctx.budgetHit || 'request budget'})`;
  s.nb = nb;
  const init = s.init || {};
  const authGated = isAuthStatus(init);

  // https
  if (s.isHttps) set('https', 'pass', 'URL uses https://');
  else set('https', 'fail', 'URL is not https://', 'Serve the MCP endpoint over HTTPS with a valid public certificate.');

  if (s.blocked) {
    for (const c of CHECKS) if (!out[c.id]) set(c.id, 'skip', 'URL was not checked: ' + s.blocked, null, { reason: BLOCKED });
    return out;
  }
  if (s.firewall) {
    for (const c of CHECKS) if (!out[c.id]) set(c.id, 'skip', `Not checked: ${s.firewall} from a firewall, bot protection or access rule`, null, { reason: BLOCKED });
    return out;
  }

  // initialize
  const legacy = !!(s.get && s.get.isSSE && ((s.get.events || []).some((e) => e.event === 'endpoint') || /event:\s*endpoint/.test(s.get.text || '')));
  if (s.initResult) {
    set('initialize', 'pass', `HTTP ${init.status}, ${init.isSSE ? 'SSE' : 'JSON'} body, ${init.ms} ms` + (s.sessionId ? ', session id issued' : ''));
  } else if (authGated) {
    if (s.prm || s.asMeta) set('initialize', 'pass', `HTTP ${init.status} with an OAuth challenge: initialize needs a signed-in user`);
    else set('initialize', 'skip', `HTTP ${init.status} without OAuth discovery: initialize needs a credential, so the transport could not be verified`, null, { reason: AUTH });
  } else if (init.error && init.status === undefined) {
    set('initialize', 'fail', 'No HTTP response: ' + init.error, 'Make the endpoint publicly reachable over HTTPS and answer POST initialize within 8 s.');
  } else {
    const msg = rpcMessage(init, 1);
    let detail = `HTTP ${init.status}`;
    if (msg && msg.error) detail += `, JSON-RPC error ${msg.error.code}: ${String(msg.error.message || '').slice(0, 120)}`;
    else if (init.contentType) detail += `, ${init.contentType.split(';')[0]} body without a JSON-RPC result`;
    if (init.error) detail += ` (${init.error})`;
    if (legacy) {
      detail += '; GET opens a legacy HTTP+SSE (2024-11-05) stream';
      set('initialize', 'fail', detail, 'Move from the legacy HTTP+SSE transport to Streamable HTTP: answer JSON-RPC POSTs on one endpoint. Gemini supports Streamable HTTP only and ChatGPT requires it for submission; Claude and the MCP Registry still accept legacy SSE, which is deprecated.', { per: { claude: 'warn', registry: 'warn' } });
    } else {
      set('initialize', 'fail', detail, 'Answer POST {"method":"initialize"} with a JSON-RPC result (application/json or text/event-stream) on this exact URL.');
    }
  }
  const noInit = authGated ? AUTH : NOINIT;
  const noInitText = authGated ? 'initialize needs authorization' : 'initialize did not complete';

  const ir = s.initResult;
  // protocol version
  if (!ir) set('protocol_version', 'skip', noInitText, null, { reason: noInit });
  else {
    const v = ir.protocolVersion;
    if (v === '2025-11-25' || v === '2025-06-18') set('protocol_version', 'pass', `Negotiated ${v}`);
    else if (v === '2025-03-26') set('protocol_version', 'warn', 'Negotiated 2025-03-26', 'Support protocol version 2025-11-25 (or 2025-06-18) and echo it back in initialize.');
    else if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && v > LATEST_PROTOCOL) set('protocol_version', 'fail', `Negotiated ${v}, newer than the ${LATEST_PROTOCOL} the client asked for`, `When the client asks for ${LATEST_PROTOCOL}, answer with ${LATEST_PROTOCOL}. Gemini Connected Apps supports versions up to ${LATEST_PROTOCOL} only.`);
    else set('protocol_version', 'fail', v ? `Negotiated ${v}` : 'No protocolVersion in the initialize result', `Return protocolVersion "${LATEST_PROTOCOL}" (or "2025-06-18") in the initialize result. Gemini Connected Apps requires 2025-03-26 to ${LATEST_PROTOCOL}.`);
  }

  // content type
  if (!ir) set('content_type', 'skip', noInitText, null, { reason: noInit });
  else {
    const ct = init.contentType || '';
    if (ct.includes('application/json') || ct.includes('text/event-stream')) set('content_type', 'pass', ct.split(';')[0]);
    else set('content_type', 'fail', `Content-Type "${ct || 'missing'}"`, 'Send Content-Type: application/json (or text/event-stream) on JSON-RPC responses.');
  }

  // unknown method
  const un = s.unknown;
  if (!ir) set('jsonrpc_errors', 'skip', noInitText, null, { reason: noInit });
  else if (!un || un.budget) set('jsonrpc_errors', 'skip', nb, null, { reason: BUDGET });
  else if (isFirewall(un)) set('jsonrpc_errors', 'skip', `${firewallLabel(un)} from a firewall`, null, { reason: BLOCKED });
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
  if (!g || g.budget) set('get_stream', 'skip', nb, null, { reason: BUDGET });
  else if (g.blocked) set('get_stream', 'skip', g.error, null, { reason: BLOCKED });
  else if (isFirewall(g)) set('get_stream', 'skip', `${firewallLabel(g)} from a firewall`, null, { reason: BLOCKED });
  else if (g.status === 405) set('get_stream', 'pass', 'HTTP 405 (no server-initiated stream)');
  else if (legacy) set('get_stream', 'warn', 'HTTP 200 legacy HTTP+SSE endpoint stream (event: endpoint)', 'Serve Streamable HTTP on this URL: GET returns 405 or a server-to-client stream, POST answers JSON-RPC.');
  else if (g.isSSE && g.status === 200) set('get_stream', 'pass', 'HTTP 200 text/event-stream');
  else if (isAuthStatus(g)) set('get_stream', 'pass', `HTTP ${g.status} (auth required)`);
  else if (g.status === 400) set('get_stream', 'warn', 'HTTP 400 on GET', 'Return HTTP 405 Method Not Allowed on GET when you do not offer a server-to-client SSE stream.');
  else set('get_stream', 'fail', g.status ? `HTTP ${g.status} ${(g.contentType || '').split(';')[0]}` : `No response: ${g.error}`, 'Return HTTP 405 Method Not Allowed on GET (or a text/event-stream), not a page or 404.');

  // latency
  if (init.status === undefined || init.ms === undefined) set('latency', 'skip', 'No response', null, { reason: NOINIT });
  else if (!s.initResult && !authGated) set('latency', 'skip', 'initialize did not complete', null, { reason: NOINIT });
  else if (init.ms < 1500) set('latency', 'pass', `${init.ms} ms`);
  else if (init.ms < 4000) set('latency', 'warn', `${init.ms} ms`, 'Bring initialize under 1.5 s: avoid cold starts and upstream calls in the handshake.');
  else set('latency', 'fail', `${init.ms} ms`, 'Bring initialize under 1.5 s: avoid cold starts and upstream calls in the handshake.');

  // metadata
  if (!ir) {
    for (const id of ['server_info', 'instructions', 'capabilities_tools']) set(id, 'skip', noInitText, null, { reason: noInit });
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
  evaluateAuth(s, set, nb);

  // tools
  evaluateTools(s, set, nb);

  return out;
}

function evaluateAuth(s, set, nb) {
  const challenges = s.challenges || [];
  const authSeen = challenges.length > 0;
  const ids = ['auth_method', 'auth_challenge', 'auth_prm', 'auth_resource', 'auth_as_metadata', 'auth_gemini_discovery', 'auth_chatgpt_metadata', 'auth_pkce', 'auth_registration', 'auth_refresh'];
  if (!authSeen && !s.prm) {
    s.auth = s.initResult ? 'none' : 'unknown';
    for (const id of ids) set(id, 'skip', s.initResult ? 'No authorization detected (open server)' : 'Auth not determined', null, { reason: s.initResult ? NA : NOINIT });
    return;
  }
  s.auth = s.prm || s.asMeta ? 'oauth' : 'other';
  const other = s.auth === 'other';
  // Claude accepts a static credential in a request header (beta), so OAuth gaps on a key-gated server only warn for Claude.
  const claudeSoft = other ? { per: { claude: 'warn' } } : {};
  const ch = s.challenge;
  const first = challenges[0];

  // sign-in method
  if (!other) set('auth_method', 'pass', `OAuth discovery found (${s.prm ? 'protected resource metadata' : 'authorization server metadata on the server origin'})`);
  else {
    const oauthHint = ch && ch.parsed && (ch.parsed.scheme === 'bearer' || ch.parsed.params.resource_metadata);
    set('auth_method', 'fail',
      `${first.where}: HTTP ${first.status} and no working OAuth discovery: ${oauthHint ? 'the server asks for a Bearer token but its OAuth metadata could not be found' : 'the server expects a credential such as an API key or static token'}`,
      'ChatGPT and Gemini cannot send a static API key or token: add MCP OAuth (protected resource metadata and authorization server metadata), or serve the tools without auth. Claude accepts a static credential in a request header only in a beta for a limited set of organizations.',
      claudeSoft);
  }

  // challenge
  if (!authSeen) set('auth_challenge', 'skip', 'No 401 seen on the probed requests (OAuth found via well-known metadata)');
  else if (ch && ch.parsed && ch.parsed.scheme === 'bearer' && ch.parsed.params.resource_metadata) set('auth_challenge', 'pass', `${ch.where}: HTTP ${ch.status} Bearer resource_metadata=${ch.parsed.params.resource_metadata}`);
  else if (ch && ch.parsed) set('auth_challenge', 'warn', `${ch.where}: WWW-Authenticate ${ch.parsed.scheme} without resource_metadata`, 'Add resource_metadata="https://<host>/.well-known/oauth-protected-resource<path>" to the WWW-Authenticate: Bearer header on 401.');
  else set('auth_challenge', 'fail', `${first.where}: HTTP ${first.status} without WWW-Authenticate`, 'On 401, send WWW-Authenticate: Bearer resource_metadata="<protected resource metadata URL>".');

  // PRM
  const prmFix = 'Serve RFC 9728 metadata at /.well-known/oauth-protected-resource (plus the path-suffixed form) with "resource" and "authorization_servers".';
  if (s.prm) {
    const as = Array.isArray(s.prm.authorization_servers) ? s.prm.authorization_servers : [];
    if (as.length) set('auth_prm', 'pass', `${s.prmUrl} lists ${as.length} authorization server(s)`);
    else set('auth_prm', 'fail', `${s.prmUrl} has no authorization_servers`, 'List your issuer URL in "authorization_servers" in the protected resource metadata.');
  } else if (s.prmBudget && !(s.prmTried || []).length) {
    set('auth_prm', 'skip', nb, null, { reason: BUDGET });
  } else {
    const tried = triedText(s.prmTried);
    if (s.asMeta) {
      set('auth_prm', 'fail', `Not found${tried ? ': ' + tried : ''}. Authorization server metadata on the server origin works (2025-03-26 discovery): Claude accepts that, ChatGPT needs protected resource metadata`, prmFix, { per: { claude: 'warn' } });
    } else {
      set('auth_prm', 'fail', tried ? `Not found: ${tried}` : 'No protected resource metadata', prmFix, claudeSoft);
    }
  }

  // resource match
  if (!s.prm) set('auth_resource', 'skip', 'No protected resource metadata');
  else {
    const res = s.prm.resource;
    let exact = false;
    try {
      const a = new URL(res); const b = new URL(s.url);
      exact = a.origin === b.origin && a.pathname.replace(/\/$/, '') === b.pathname.replace(/\/$/, '') && a.search === b.search;
    } catch { /* invalid */ }
    const shown = s.displayUrl;
    let path = '';
    try { path = new URL(shown).pathname.replace(/\/$/, ''); } catch { /* keep */ }
    if (exact) set('auth_resource', 'pass', `resource equals ${shown}`);
    else set('auth_resource', 'fail', `resource ${typeof res === 'string' ? res : 'missing'} is not the server URL ${shown}`, `Serve metadata whose "resource" is exactly ${shown} (Claude requires an exact match, path included), e.g. at /.well-known/oauth-protected-resource${path}.`);
  }

  // AS metadata
  const am = s.asMeta;
  const asFix = 'Serve RFC 8414 metadata at <issuer>/.well-known/oauth-authorization-server with authorization_endpoint, token_endpoint and response_types_supported ["code"].';
  if (am) {
    const missing = ['authorization_endpoint', 'token_endpoint'].filter((k) => typeof am[k] !== 'string');
    const rts = am.response_types_supported;
    if (!Array.isArray(rts) || !rts.includes('code')) missing.push('response_types_supported:["code"]');
    if (!missing.length) set('auth_as_metadata', 'pass', `${s.asUrl}`);
    else set('auth_as_metadata', 'fail', `${s.asUrl} lacks ${missing.join(', ')}`, `Add ${missing.join(', ')} to the authorization server metadata.`, claudeSoft);
  } else if (s.asBudget) {
    const tried = triedText(s.asTried);
    set('auth_as_metadata', 'skip', `${nb}${tried ? '; tried ' + tried : ''}`, null, { reason: BUDGET });
  } else {
    const tried = triedText(s.asTried);
    set('auth_as_metadata', 'fail', tried ? `Not found: ${tried}` : 'No authorization server to probe', asFix, claudeSoft);
  }

  // Gemini: first URL that answers decides
  const gm = s.gemini;
  if (other || !s.issuer || !gm) set('auth_gemini_discovery', 'skip', other ? 'No OAuth discovery to check' : 'No authorization server to probe');
  else if (gm.budget && !gm.url) set('auth_gemini_discovery', 'skip', nb, null, { reason: BUDGET });
  else {
    const order = geminiMetadataUrls(s.issuer);
    const geminiFix = `Make ${order[0]} answer HTTP 200 with the authorization server metadata (authorization_endpoint, token_endpoint, response_types_supported ["code"], registration_endpoint). Gemini tries ${order.join(' then ')} and stops at the first URL that answers, even with an error.`;
    if (!gm.url) set('auth_gemini_discovery', 'fail', `No answer from ${triedText(gm.tried)}`, geminiFix);
    else if (gm.status === 200 && hasAsFields(gm.json)) {
      const j = gm.json;
      const miss = ['authorization_endpoint', 'token_endpoint'].filter((k) => typeof j[k] !== 'string');
      if (!(Array.isArray(j.response_types_supported) && j.response_types_supported.includes('code'))) miss.push('response_types_supported:["code"]');
      if (!miss.length) set('auth_gemini_discovery', 'pass', `${gm.url} (first URL Gemini tries) answers 200 with the required fields${typeof j.registration_endpoint === 'string' ? '' : '; no registration_endpoint, so the client id and secret must be entered by hand'}`);
      else set('auth_gemini_discovery', 'fail', `${gm.url} (first URL Gemini tries) lacks ${miss.join(', ')}`, geminiFix);
    } else {
      const shown = gm.status === 200 ? 'HTTP 200 without authorization server metadata' : `HTTP ${gm.status}${gm.firewall ? ' (firewall page)' : ''}`;
      set('auth_gemini_discovery', 'fail', `Gemini tries ${gm.url} first and gets ${shown}; it uses that answer and does not try ${s.asUrl && s.asUrl !== gm.url ? s.asUrl : 'other locations'}`, geminiFix);
    }
  }

  // ChatGPT: issuer equality and token endpoint auth methods
  if (!s.prm || !am) set('auth_chatgpt_metadata', 'skip', !s.prm ? 'No protected resource metadata' : 'No authorization server metadata');
  else {
    const problems = [];
    if (am.issuer !== s.issuer) problems.push(`issuer ${typeof am.issuer === 'string' ? JSON.stringify(am.issuer) : 'missing'} is not exactly the authorization_servers entry ${JSON.stringify(s.issuer)}`);
    const tam = am.token_endpoint_auth_methods_supported;
    if (!Array.isArray(tam) || !tam.length) problems.push('token_endpoint_auth_methods_supported missing');
    if (!problems.length) set('auth_chatgpt_metadata', 'pass', `issuer ${am.issuer}; token_endpoint_auth_methods_supported: ${tam.join(', ')}`);
    else set('auth_chatgpt_metadata', 'fail', problems.join('; '), 'Use the exact metadata "issuer" string in the protected resource metadata authorization_servers list (no trailing-slash or case differences), and list token_endpoint_auth_methods_supported (for example ["none"] for public clients) in the authorization server metadata. OpenAI lists both as fields that must be correct.');
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

function evaluateTools(s, set, nb) {
  const ids = ['tools_list', 'tool_schema', 'tool_names', 'tool_annotations', 'tool_open_world', 'tool_titles', 'tool_descriptions'];
  const t = s.tools;
  const skipAll = (detail, reason) => { for (const id of ids) set(id, 'skip', detail, null, { reason }); };
  if (!s.initResult) return skipAll(isAuthStatus(s.init) ? 'Tools are behind authorization' : 'initialize did not complete', isAuthStatus(s.init) ? AUTH : NOINIT);
  if (!t || t.budget) return skipAll(nb, BUDGET);
  if (isFirewall(t)) return skipAll(`tools/list got ${firewallLabel(t)} from a firewall`, BLOCKED);
  if (isAuthStatus(t)) return skipAll(`tools/list needs authorization (HTTP ${t.status})`, AUTH);
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

  // Claude: every tool has readOnlyHint or destructiveHint (Anthropic: "the applicable readOnlyHint or destructiveHint").
  const noHint = tools.filter((x) => typeof ann(x).readOnlyHint !== 'boolean' && typeof ann(x).destructiveHint !== 'boolean').map(nm);
  if (!noHint.length) set('tool_annotations', 'pass', `All ${tools.length} tools set readOnlyHint or destructiveHint`);
  else set('tool_annotations', 'fail', `${noHint.length}/${tools.length} tools set neither readOnlyHint nor destructiveHint: ${listNames(noHint)}`, 'Set annotations.readOnlyHint: true on read-only tools and destructiveHint: true on tools that modify or delete data (Claude needs one of them on every tool; ChatGPT needs all three hints, see tool_open_world).');

  // ChatGPT: all three hints as explicit booleans.
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

function scoreOf(items) {
  let num = 0; let den = 0;
  for (const c of items) {
    if (c.status === 'skip') continue;
    num += c.weight * STATUS_VALUE[c.status];
    den += c.weight;
  }
  return den ? Math.round((num / den) * 100) : 0;
}

function buildResult(s, ctx, { normalized, started, reachable, error, code }) {
  const ev = evaluate(s, ctx);
  const checks = CHECKS.map((c) => {
    const e = ev[c.id] || { status: 'skip', detail: '', fix: null, reason: NA, per: null };
    const row = { id: c.id, group: c.group, title: c.title, status: e.status, weight: c.weight, detail: e.detail, fix: e.fix };
    if (e.status === 'skip') row.skip_reason = e.reason || NA;
    if (e.per) row.store_status = e.per;
    return row;
  });
  let score = scoreOf(checks);
  // Coverage: share of applicable weight that could actually be verified.
  const authSkipped = checks.filter((c) => c.status === 'skip' && c.skip_reason === AUTH);
  const verifiedW = checks.filter((c) => c.status !== 'skip').reduce((a, c) => a + c.weight, 0);
  const coverage = Math.round((verifiedW / (verifiedW + authSkipped.reduce((a, c) => a + c.weight, 0) || 1)) * 100);
  // A server whose tools could not be seen cannot earn an A: cap at 85.
  const limited = authSkipped.length > 0;
  if (limited) score = Math.min(score, LIMITED_CAP);
  if (reachable === false) score = 0;
  const stores = {};
  for (const st of STORES) {
    const mine = checks.filter((c) => CHECK_BY_ID[c.id].stores.includes(st)).map((c) => ({ ...c, status: (c.store_status && c.store_status[st]) || c.status }));
    const blocking = (c) => CHECK_BY_ID[c.id].blocks.includes(st);
    const blockers = mine.filter((c) => c.status === 'fail' && blocking(c)).map((c) => c.id);
    const unv = mine.filter((c) => c.status === 'skip' && blocking(c) && c.skip_reason !== NA);
    // not_ready: a blocking check failed (or unreachable). unverified: none failed, but a blocking
    // check for this store was skipped (tools behind sign-in, request/time budget). ready: neither.
    const status = reachable === false || blockers.length ? 'not_ready' : unv.length ? 'unverified' : 'ready';
    const stScore = reachable === false ? 0 : limited ? Math.min(scoreOf(mine), LIMITED_CAP) : scoreOf(mine);
    stores[st] = {
      status,
      ready: status === 'ready',
      score: stScore,
      blockers: reachable === false ? ['initialize'] : blockers,
      unverified: unv.map((c) => c.id),
      unverified_reasons: Object.fromEntries(unv.map((c) => [c.id, c.skip_reason])),
    };
  }
  const ir = s.initResult || {};
  const si = ir.serverInfo || {};
  let res = {
    url: s.displayUrl || normalized,
    checked_at: new Date().toISOString(),
    duration_ms: Date.now() - started,
    score,
    grade: gradeFor(score),
    auth: s.auth || 'unknown',
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
  if (s.displayUrl && s.displayUrl !== normalized) res.redacted = true;
  if (ctx.budgetHit) res.budget_hit = ctx.budgetHit;
  if (error) res.error = error;
  if (reachable === false && code) res.error_code = code;
  // Never let a credential from the URL reach the result: scrub every string.
  res = scrubSecrets(res, secretParts(normalized));
  return res;
}
