// mcpstamp-check Worker: HTTP API, KV result store, rate limit, badges.
import { checkServer, CHECKS, STORES, STORE_TITLES, STORE_MEANING, SKIP_REASONS, ENGINE_VERSION, LIMITED_CAP, DEFAULT_UA, DEFAULT_DEADLINE_MS } from './check.mjs';
import { checkUrlSafety, normalizeUrl, resultId, sha256Hex, makeHostGuard, scrubSecrets, secretParts } from './ssrf.mjs';
import { badgeSvg } from './badge.mjs';
import { handleMcp, MCP_INFO } from './mcp.mjs';

const FRESH_MS = 10 * 60 * 1000;
/** Badges older than this trigger one background re-check (when the rate budget allows). */
export const STALE_MS = 7 * 24 * 3600 * 1000;
const REFRESH_RETRY_MS = 3600 * 1000;
const RESULT_TTL_S = 30 * 24 * 3600;
const LIMIT_PER_HOUR = 20;
const BADGE_MAX_AGE = 21600;
const UNCHECKED_MAX_AGE = 600;
const PUBLIC_SITE = 'https://www.mcpstamp.com';

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, OPTIONS',
  'access-control-allow-headers': 'content-type',
  'access-control-max-age': '86400',
};

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body, null, status === 200 ? 0 : 0), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...CORS, ...extra },
  });
}

function svg(body, maxAge) {
  return new Response(body, {
    headers: { 'content-type': 'image/svg+xml; charset=utf-8', 'cache-control': `public, max-age=${maxAge}`, ...CORS },
  });
}

function decorate(result, id) {
  return { id, ...result, badge_url: `${PUBLIC_SITE}/badge/${id}.svg`, report_url: `${PUBLIC_SITE}/check/?id=${id}` };
}

// ---------- rate limit: per-isolate memory + Cache API hourly counter + burst binding ----------
const mem = new Map();

export function clientIp(req, env) {
  const key = env.PROXY_KEY;
  if (key && req.headers.get('x-mcpstamp-proxy-key') === key) {
    const fwd = (req.headers.get('x-mcpstamp-client-ip') || '').trim();
    if (fwd) return fwd;
  }
  return req.headers.get('cf-connecting-ip') || 'unknown';
}

async function takeToken(req, env) {
  const ip = clientIp(req, env);
  const now = Date.now();
  const hour = Math.floor(now / 3600000);
  const retry = Math.max(1, Math.ceil(((hour + 1) * 3600000 - now) / 1000));
  if (env.BURST) {
    try {
      const { success } = await env.BURST.limit({ key: ip });
      if (!success) return { ok: false, retry_after: 60 };
    } catch { /* binding unavailable: fall through */ }
  }
  const mkey = `${ip}|${hour}`;
  let count = mem.get(mkey) || 0;
  let cache = null;
  const ck = new Request(`https://mcp.zovo.one/stamp/__rl/${encodeURIComponent(ip)}/${hour}`);
  try {
    cache = globalThis.caches && caches.default;
    if (cache) {
      const hit = await cache.match(ck);
      if (hit) count = Math.max(count, parseInt(await hit.text(), 10) || 0);
    }
  } catch { cache = null; }
  if (count >= LIMIT_PER_HOUR) return { ok: false, retry_after: retry };
  count += 1;
  mem.set(mkey, count);
  if (mem.size > 5000) for (const k of mem.keys()) { if (!k.endsWith(`|${hour}`)) mem.delete(k); }
  if (cache) {
    try {
      await cache.put(ck, new Response(String(count), { headers: { 'cache-control': `public, max-age=${retry}` } }));
    } catch { /* ignore */ }
  }
  return { ok: true, remaining: LIMIT_PER_HOUR - count };
}

// ---------- live check ----------
// Every URL the engine fetches (first URL, each redirect hop, each discovery URL) passes the host
// guard: syntax rules plus DNS-over-HTTPS (1.1.1.1), refusing names that resolve to private or
// reserved addresses. If DoH itself fails, global_fetch_strictly_public still keeps egress public.
async function runCheck(normalized, id, env, ctx, hadPrevious) {
  const guard = makeHostGuard({ fetch: (u, i) => fetch(u, i), failClosed: false });
  const result = await checkServer(normalized, {
    fetch: (u, init) => fetch(u, init),
    timeoutMs: 8000,
    deadlineMs: DEFAULT_DEADLINE_MS,
    userAgent: DEFAULT_UA,
    validateUrl: guard,
  });
  if (!result.reachable) {
    const detail = String(result.error || 'no response').replace(/^(unreachable|blocked_host|blocked_by_firewall|bad_url): /, '');
    if (result.error_code === 'blocked_host') return { http: 400, body: { error: 'blocked_host', detail } };
    if (result.error_code === 'blocked_by_firewall') return { http: 502, body: { error: 'blocked_by_firewall', detail } };
    return { http: 502, body: { error: 'unreachable', detail } };
  }
  const full = scrubSecrets(decorate(result, id), secretParts(normalized));
  const writes = [env.RESULTS.put(`r:${id}`, JSON.stringify(full), { expirationTtl: RESULT_TTL_S })];
  if (!hadPrevious) {
    writes.push(sha256Hex(normalized).then((sha) => env.RESULTS.put(`u:${sha}`, id, { expirationTtl: RESULT_TTL_S })));
  }
  ctx.waitUntil(Promise.all(writes).catch(() => {}));
  return { http: 200, body: full };
}

// ---------- badge staleness: one background re-check per stale result ----------
const refreshing = new Map(); // id -> last attempt (per isolate)

/**
 * When a stored result is older than STALE_MS, re-check it in the background (ctx.waitUntil) if the
 * caller's rate budget allows. The re-check rewrites r:<id> with a fresh 30-day TTL.
 * rawUrl is the URL from the request; without it, the stored url is used only when it is the
 * full URL (its hash is the id, i.e. nothing was redacted).
 */
async function maybeRefresh(req, env, ctx, prev, id, rawUrl) {
  if (!prev || !prev.checked_at) return false;
  const age = Date.now() - Date.parse(prev.checked_at);
  if (!(age > STALE_MS)) return false;
  const last = refreshing.get(id);
  if (last && Date.now() - last < REFRESH_RETRY_MS) return false;
  let normalized = null;
  try {
    const cand = rawUrl || prev.url;
    const safe = checkUrlSafety(cand);
    if (safe.ok) {
      const n = normalizeUrl(safe.url);
      if ((await resultId(n)) === id) normalized = n;
    }
  } catch { /* not checkable */ }
  if (!normalized) return false;
  const tok = await takeToken(req, env);
  if (!tok.ok) return false;
  refreshing.set(id, Date.now());
  if (refreshing.size > 2000) for (const [k, t] of refreshing) { if (Date.now() - t > REFRESH_RETRY_MS) refreshing.delete(k); }
  ctx.waitUntil(runCheck(normalized, id, env, ctx, true).catch(() => {}));
  return true;
}

async function readResult(env, id) {
  let r = null;
  try { r = await env.RESULTS.get(`r:${id}`, 'json'); } catch { return null; }
  // Results stored by engine <= 1.1.0 may hold a path token in url and details: scrub on read.
  if (r && typeof r.url === 'string') { try { r = scrubSecrets(r, secretParts(r.url)); } catch { /* keep */ } }
  return r;
}

/**
 * Shared check path for GET /api/check and the MCP tool check_mcp_server:
 * URL safety, 10-minute cache, rate limit, live check, KV store.
 * Returns {http, body, headers}.
 */
export async function checkTarget(req, env, ctx, raw, fresh) {
  if (!raw) return { http: 400, body: { error: 'bad_url', detail: 'missing url parameter' } };
  const safe = checkUrlSafety(raw);
  if (!safe.ok) return { http: 400, body: { error: safe.error, detail: safe.reason } };
  const normalized = normalizeUrl(safe.url);
  const id = await resultId(normalized);
  const prev = await readResult(env, id);
  const age = prev ? Date.now() - Date.parse(prev.checked_at) : Infinity;
  if (prev && !fresh && age < FRESH_MS) return { http: 200, body: { ...prev, cached: true } };
  const tok = await takeToken(req, env);
  if (!tok.ok) {
    if (prev && !fresh) return { http: 200, body: { ...prev, cached: true, stale: true, rate_limited: true } };
    return { http: 429, body: { error: 'rate_limited', retry_after: tok.retry_after }, headers: { 'retry-after': String(tok.retry_after) } };
  }
  const out = await runCheck(normalized, id, env, ctx, !!prev);
  return { ...out, headers: { 'x-ratelimit-remaining': String(tok.remaining) } };
}

async function handleCheck(req, env, ctx, params) {
  const out = await checkTarget(req, env, ctx, params.get('url'), params.get('fresh') === '1');
  return json(out.body, out.http, out.headers || {});
}

async function handleBadgeByUrl(req, env, ctx, params) {
  const safe = checkUrlSafety(params.get('url') || '');
  if (!safe.ok) return svg(badgeSvg(null), UNCHECKED_MAX_AGE);
  const normalized = normalizeUrl(safe.url);
  const id = await resultId(normalized);
  const prev = await readResult(env, id);
  if (prev) {
    await maybeRefresh(req, env, ctx, prev, id, normalized);
    return svg(badgeSvg(prev), BADGE_MAX_AGE);
  }
  const tok = await takeToken(req, env);
  if (!tok.ok) return svg(badgeSvg(null), UNCHECKED_MAX_AGE);
  const out = await runCheck(normalized, id, env, ctx, false);
  return out.http === 200 ? svg(badgeSvg(out.body), BADGE_MAX_AGE) : svg(badgeSvg(null), UNCHECKED_MAX_AGE);
}

function index() {
  return {
    service: 'McpStamp Check',
    engine: ENGINE_VERSION,
    docs: `${PUBLIC_SITE}/check/`,
    endpoints: {
      check: 'GET /stamp/api/check?url=<https MCP URL>[&fresh=1]',
      result: 'GET /stamp/api/result/<id>',
      checks: 'GET /stamp/api/checks',
      badge_by_url: 'GET /stamp/badge?url=<url>',
      badge_by_id: 'GET /stamp/badge/<id>.svg',
      mcp: 'POST /stamp/mcp (MCP Streamable HTTP, authless)',
    },
    mcp: MCP_INFO,
    limits: { checks_per_hour_per_ip: LIMIT_PER_HOUR, result_cache_minutes: FRESH_MS / 60000, result_ttl_days: RESULT_TTL_S / 86400, badge_recheck_after_days: STALE_MS / 86400000, check_time_budget_s: DEFAULT_DEADLINE_MS / 1000 },
  };
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (/^(?:\/stamp)?\/mcp\/?$/.test(url.pathname)) {
      try {
        return await handleMcp(req, { checkTarget: (raw, fresh) => checkTarget(req, env, ctx, raw, fresh) });
      } catch (e) {
        return json({ jsonrpc: '2.0', id: null, error: { code: -32603, message: 'Internal error' } }, 500);
      }
    }
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (req.method !== 'GET') return json({ error: 'method_not_allowed' }, 405, { allow: 'GET, OPTIONS' });
    let path = url.pathname.replace(/^\/stamp(?=\/|$)/, '') || '/';
    if (path.length > 1) path = path.replace(/\/+$/, '');
    try {
      if (path === '/' || path === '/api') return json(index());
      if (path === '/api/check') return await handleCheck(req, env, ctx, url.searchParams);
      if (path === '/api/checks') {
        return json({ checks: CHECKS, stores: STORE_TITLES, store_meaning: STORE_MEANING, skip_reasons: SKIP_REASONS, store_ids: STORES, grades: { A: 90, B: 80, C: 65, D: 50, F: 0 }, status_values: { pass: 1, warn: 0.5, fail: 0, skip: null }, limited_cap: LIMITED_CAP }, 200, { 'cache-control': 'public, max-age=3600' });
      }
      let m = path.match(/^\/api\/result\/([0-9a-f]{12})$/);
      if (m) {
        const r = await readResult(env, m[1]);
        return r ? json(r) : json({ error: 'not_found' }, 404);
      }
      if (path === '/badge' || path === '/badge.svg') return await handleBadgeByUrl(req, env, ctx, url.searchParams);
      m = path.match(/^\/badge\/([0-9a-f]{12})(?:\.svg)?$/);
      if (m) {
        const r = await readResult(env, m[1]);
        if (r) await maybeRefresh(req, env, ctx, r, m[1], null);
        return svg(badgeSvg(r), r ? BADGE_MAX_AGE : UNCHECKED_MAX_AGE);
      }
      return json({ error: 'not_found' }, 404);
    } catch (e) {
      return json({ error: 'internal', detail: String((e && e.message) || e).slice(0, 200) }, 500);
    }
  },
};
