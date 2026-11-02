// mcpstamp-check Worker: HTTP API, KV result store, rate limit, badges.
import { checkServer, CHECKS, STORES, STORE_TITLES, ENGINE_VERSION, LIMITED_CAP, DEFAULT_UA } from './check.mjs';
import { checkUrlSafety, normalizeUrl, resultId, sha256Hex, isPrivateIp } from './ssrf.mjs';
import { badgeSvg } from './badge.mjs';

const FRESH_MS = 10 * 60 * 1000;
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

// ---------- DNS guard (DoH): refuse names that resolve to private addresses ----------
async function dnsGuard(host) {
  const ips = [];
  let anyAnswer = false;
  let answered = 0;
  for (const type of ['A', 'AAAA']) {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, {
        headers: { accept: 'application/dns-json' },
      });
      if (!r.ok) continue;
      const j = await r.json();
      if (j.Status === 0 || j.Status === 3) answered++;
      for (const a of j.Answer || []) {
        if (a.type === 1 || a.type === 28) { ips.push(a.data); anyAnswer = true; }
      }
    } catch { /* DoH failure: rely on Cloudflare's own egress guard */ }
  }
  if (ips.some((ip) => isPrivateIp(ip))) return { ok: false, error: 'blocked_host', detail: 'host resolves to a private or reserved address' };
  if (answered === 2 && !anyAnswer) return { ok: false, error: 'unreachable', detail: 'DNS name has no A or AAAA record' };
  return { ok: true };
}

async function runCheck(normalized, id, env, ctx, hadPrevious) {
  const dns = await dnsGuard(new URL(normalized).hostname);
  if (!dns.ok) return { http: dns.error === 'blocked_host' ? 400 : 502, body: { error: dns.error, detail: dns.detail } };
  const result = await checkServer(normalized, {
    fetch: (u, init) => fetch(u, init),
    timeoutMs: 8000,
    userAgent: DEFAULT_UA,
  });
  if (!result.reachable) return { http: 502, body: { error: 'unreachable', detail: result.error || 'no response' } };
  const full = decorate(result, id);
  const writes = [env.RESULTS.put(`r:${id}`, JSON.stringify(full), { expirationTtl: RESULT_TTL_S })];
  if (!hadPrevious) {
    writes.push(sha256Hex(normalized).then((sha) => env.RESULTS.put(`u:${sha}`, id, { expirationTtl: RESULT_TTL_S })));
  }
  ctx.waitUntil(Promise.all(writes).catch(() => {}));
  return { http: 200, body: full };
}

async function readResult(env, id) {
  try { return await env.RESULTS.get(`r:${id}`, 'json'); } catch { return null; }
}

async function handleCheck(req, env, ctx, params) {
  const raw = params.get('url');
  if (!raw) return json({ error: 'bad_url', detail: 'missing url parameter' }, 400);
  const safe = checkUrlSafety(raw);
  if (!safe.ok) return json({ error: safe.error, detail: safe.reason }, 400);
  const normalized = normalizeUrl(safe.url);
  const id = await resultId(normalized);
  const fresh = params.get('fresh') === '1';
  const prev = await readResult(env, id);
  const age = prev ? Date.now() - Date.parse(prev.checked_at) : Infinity;
  if (prev && !fresh && age < FRESH_MS) return json({ ...prev, cached: true });
  const tok = await takeToken(req, env);
  if (!tok.ok) {
    if (prev && !fresh) return json({ ...prev, cached: true, stale: true, rate_limited: true });
    return json({ error: 'rate_limited', retry_after: tok.retry_after }, 429, { 'retry-after': String(tok.retry_after) });
  }
  const out = await runCheck(normalized, id, env, ctx, !!prev);
  return json(out.body, out.http, { 'x-ratelimit-remaining': String(tok.remaining) });
}

async function handleBadgeByUrl(req, env, ctx, params) {
  const safe = checkUrlSafety(params.get('url') || '');
  if (!safe.ok) return svg(badgeSvg(null), UNCHECKED_MAX_AGE);
  const normalized = normalizeUrl(safe.url);
  const id = await resultId(normalized);
  const prev = await readResult(env, id);
  if (prev) return svg(badgeSvg(prev), BADGE_MAX_AGE);
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
    },
    limits: { checks_per_hour_per_ip: LIMIT_PER_HOUR, result_cache_minutes: FRESH_MS / 60000 },
  };
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (req.method !== 'GET') return json({ error: 'method_not_allowed' }, 405, { allow: 'GET, OPTIONS' });
    let path = url.pathname.replace(/^\/stamp(?=\/|$)/, '') || '/';
    if (path.length > 1) path = path.replace(/\/+$/, '');
    try {
      if (path === '/' || path === '/api') return json(index());
      if (path === '/api/check') return await handleCheck(req, env, ctx, url.searchParams);
      if (path === '/api/checks') {
        return json({ checks: CHECKS, stores: STORE_TITLES, store_ids: STORES, grades: { A: 90, B: 80, C: 65, D: 50, F: 0 }, status_values: { pass: 1, warn: 0.5, fail: 0, skip: null }, limited_cap: LIMITED_CAP }, 200, { 'cache-control': 'public, max-age=3600' });
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
        return svg(badgeSvg(r), r ? BADGE_MAX_AGE : UNCHECKED_MAX_AGE);
      }
      return json({ error: 'not_found' }, 404);
    } catch (e) {
      return json({ error: 'internal', detail: String((e && e.message) || e).slice(0, 200) }, 500);
    }
  },
};
