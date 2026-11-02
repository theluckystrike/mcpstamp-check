// URL safety guard for McpStamp Check. Pure ESM, no runtime-specific APIs.
// checkUrlSafety is syntactic; makeHostGuard adds a DNS check (runtime resolver or DNS-over-HTTPS).

const BLOCKED_SUFFIXES = [
  '.localhost', '.local', '.internal', '.intranet', '.lan', '.home', '.corp',
  '.private', '.localdomain', '.home.arpa', '.arpa', '.test', '.invalid', '.example',
  '.onion', '.alt',
];
// Public wildcard DNS services that map names to arbitrary (often private) IPs.
const BLOCKED_DNS_SERVICES = [
  'nip.io', 'sslip.io', 'xip.io', 'localtest.me', 'lvh.me', 'vcap.me', 'lacolhost.com',
  'localhost.run', 'traefik.me', 'nip.direct', 'backname.io', 'fbi.com', 'localho.st',
  'localtest.dev', 'readme.localtest.me', '1u.ms', 'rbndr.us',
];
const ALLOWED_PORTS = new Set(['', '443', '8443']);

function hostIsIpLiteral(host) {
  if (host.startsWith('[') || host.includes(':')) return true; // IPv6 literal
  // The WHATWG URL parser already turns decimal/octal/hex IPv4 forms into dotted quads.
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

/**
 * Validate a URL for outbound checking.
 * @returns {{ok:true,url:URL}|{ok:false,error:'bad_url'|'blocked_host',reason:string}}
 */
export function checkUrlSafety(input) {
  let u;
  try {
    u = input instanceof URL ? new URL(input.href) : new URL(String(input || '').trim());
  } catch {
    return { ok: false, error: 'bad_url', reason: 'not a valid absolute URL' };
  }
  if (u.protocol !== 'https:') return { ok: false, error: 'bad_url', reason: 'only https:// URLs are checked' };
  if (u.username || u.password) return { ok: false, error: 'bad_url', reason: 'credentials in the URL are not allowed' };
  if (String(input).length > 2048) return { ok: false, error: 'bad_url', reason: 'URL longer than 2048 characters' };
  if (!ALLOWED_PORTS.has(u.port)) return { ok: false, error: 'blocked_host', reason: `port ${u.port} is not allowed (443 or 8443 only)` };
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!host) return { ok: false, error: 'bad_url', reason: 'missing host' };
  if (hostIsIpLiteral(host)) return { ok: false, error: 'blocked_host', reason: 'IP address literals are not allowed; use a DNS name' };
  if (host === 'localhost' || !host.includes('.')) return { ok: false, error: 'blocked_host', reason: 'local or single-label host names are not allowed' };
  for (const s of BLOCKED_SUFFIXES) if (host.endsWith(s)) return { ok: false, error: 'blocked_host', reason: `${s} hosts are not allowed` };
  for (const s of BLOCKED_DNS_SERVICES) if (host === s || host.endsWith('.' + s)) return { ok: false, error: 'blocked_host', reason: `${s} wildcard DNS names are not allowed` };
  if (!/^[a-z0-9.-]+$/.test(host)) return { ok: false, error: 'bad_url', reason: 'host contains invalid characters' };
  return { ok: true, url: u };
}

/** Canonical form used for ids: lowercase host, no default port, no fragment, no trailing "?". */
export function normalizeUrl(input) {
  const u = input instanceof URL ? new URL(input.href) : new URL(String(input).trim());
  u.hash = '';
  u.hostname = u.hostname.toLowerCase().replace(/\.$/, '');
  if (u.port === '443') u.port = '';
  if (!u.pathname) u.pathname = '/';
  let s = u.href;
  if (s.endsWith('?')) s = s.slice(0, -1);
  return s;
}

const SECRET_KEY_RE = /(token|key|secret|auth|password|passwd|pwd|session|sig|signature|credential|access|jwt|bearer)/i;
// Path segments that carry a credential by convention: /t/<token>, /token/<token>, /key/<key> ...
const SECRET_PATH_PREFIX = new Set(['t', 'token', 'key', 'apikey', 'api-key', 'api_key', 'secret']);
export const REDACTED = 'REDACTED';

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

/**
 * True when a string looks like a random credential: at least 24 characters of hex, a UUID,
 * or base64url-style text with mixed classes (letters and digits jumping back and forth).
 * Human slugs such as "mcp-server-2025-11-25-v1" stay visible.
 */
export function looksSecret(value) {
  const s = safeDecode(String(value || ''));
  if (s.length < 24) return false;
  if (!/^[A-Za-z0-9_\-.~+=/]+$/.test(s)) return false;
  const hex = s.replace(/-/g, '');
  if (/^[0-9a-f]+$/i.test(hex) && hex.length >= 24 && /\d/.test(hex) && /[a-f]/i.test(hex)) return true;
  if (/^\d+$/.test(hex)) return hex.length >= 24;
  const cls = (c) => (c >= '0' && c <= '9' ? 'd' : c >= 'a' && c <= 'z' ? 'l' : c >= 'A' && c <= 'Z' ? 'u' : 's');
  let changes = 0;
  for (let i = 1; i < s.length; i++) {
    const a = cls(s[i - 1]); const b = cls(s[i]);
    if (a !== 's' && b !== 's' && a !== b) changes++;
  }
  const digits = (s.match(/\d/g) || []).length;
  const upper = /[A-Z]/.test(s); const lower = /[a-z]/.test(s);
  if (upper && lower && digits >= 1) return true;
  return digits >= 1 && changes >= 6;
}

function splitUrl(input) {
  return new URL(String(input));
}

/** Raw secret substrings of a URL (path tokens and secret query values), decoded and encoded forms. */
export function secretParts(input) {
  let u;
  try { u = splitUrl(input); } catch { return []; }
  const out = new Set();
  const add = (v) => {
    if (!v) return;
    out.add(v);
    const d = safeDecode(v); out.add(d);
    try { out.add(encodeURIComponent(d)); } catch { /* ignore */ }
  };
  const segs = u.pathname.split('/');
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];
    if (!seg) continue;
    const prev = i > 0 ? segs[i - 1].toLowerCase() : '';
    if ((SECRET_PATH_PREFIX.has(prev) && seg.length >= 6) || looksSecret(seg)) add(seg);
  }
  for (const [k, v] of u.searchParams) {
    if (v && (SECRET_KEY_RE.test(k) || looksSecret(v))) add(v);
  }
  return [...out].filter((x) => x && x.length >= 6).sort((a, b) => b.length - a.length);
}

/**
 * Same URL with credentials replaced by REDACTED, for public display and storage:
 * the segment after /t/ (and /token/, /key/ ...), random-looking path segments of 24+ characters,
 * and query values whose name looks secret or whose value looks random.
 */
export function redactUrl(input) {
  const u = splitUrl(input);
  let changed = false;
  const segs = u.pathname.split('/');
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];
    if (!seg) continue;
    const prev = i > 0 ? segs[i - 1].toLowerCase() : '';
    if ((SECRET_PATH_PREFIX.has(prev) && seg !== REDACTED) || looksSecret(seg)) { segs[i] = REDACTED; changed = true; }
  }
  if (changed) u.pathname = segs.join('/');
  for (const [k, v] of [...u.searchParams]) {
    if (v !== REDACTED && (SECRET_KEY_RE.test(k) || looksSecret(v))) { u.searchParams.set(k, REDACTED); changed = true; }
  }
  return changed ? u.href : String(input);
}

/** Replace every secret part of `url` inside `text` with REDACTED. */
export function scrubText(text, secrets) {
  let t = String(text);
  for (const s of secrets) if (s && t.includes(s)) t = t.split(s).join(REDACTED);
  return t;
}

/** Deep-scrub a JSON-able value: every string has the URL's secrets replaced. */
export function scrubSecrets(value, url) {
  const secrets = Array.isArray(url) ? url : secretParts(url);
  if (!secrets.length) return value;
  const walk = (v) => {
    if (typeof v === 'string') return scrubText(v, secrets);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const o = {};
      for (const [k, x] of Object.entries(v)) o[scrubText(k, secrets)] = walk(x);
      return o;
    }
    return v;
  };
  return walk(value);
}

function parseV4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((x) => x > 255)) return null;
  return p;
}
function ipv4ToInt(ip) {
  const p = parseV4(ip) || [0, 0, 0, 0];
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
const V4_BLOCKS = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([b, m]) => [ipv4ToInt(b), m]);

function v4IntIsPrivate(n) {
  return V4_BLOCKS.some(([b, m]) => (n >>> (32 - m)) === (b >>> (32 - m)));
}

/** Parse an IPv6 string (with :: and an optional dotted IPv4 tail) into 8 16-bit groups, or null. */
export function parseIPv6(ip) {
  let s = String(ip).toLowerCase();
  const pct = s.indexOf('%');
  if (pct >= 0) s = s.slice(0, pct); // zone id
  let tail = [];
  const v4m = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (v4m) {
    const p = parseV4(v4m[2]);
    if (!p) return null;
    tail = [(p[0] << 8) | p[1], (p[2] << 8) | p[3]];
    s = v4m[1];
    if (s.endsWith(':') && !s.endsWith('::')) s = s.slice(0, -1);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parse = (h) => (h === '' ? [] : h.split(':').map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN)));
  const head = parse(halves[0]);
  const rest = halves.length === 2 ? parse(halves[1]) : [];
  if ([...head, ...rest].some((x) => Number.isNaN(x))) return null;
  const known = head.length + rest.length + tail.length;
  if (halves.length === 1) {
    if (known !== 8) return null;
    return [...head, ...tail];
  }
  if (known > 7) return null;
  return [...head, ...new Array(8 - known).fill(0), ...rest, ...tail];
}

/** True when an IP address (v4 or v6 string) is private, loopback, link-local or otherwise not public. */
export function isPrivateIp(ip) {
  ip = String(ip).trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    if (!parseV4(ip)) return true;
    return v4IntIsPrivate(ipv4ToInt(ip));
  }
  if (!ip.includes(':')) return true; // not an IP: treat as unsafe
  const g = parseIPv6(ip);
  if (!g) return true; // unparseable: unsafe
  const v4At = (hi, lo) => (((g[hi] << 16) >>> 0) + g[lo]) >>> 0;
  const zero = (from, to) => g.slice(from, to).every((x) => x === 0);
  // ::/96 (unspecified, loopback, deprecated IPv4-compatible) and ::ffff:0:0/96 (IPv4-mapped)
  if (zero(0, 5) && (g[5] === 0 || g[5] === 0xffff)) {
    if (g[5] === 0xffff) return v4IntIsPrivate(v4At(6, 7));
    return true;
  }
  // ::ffff:0:0:0/96 (SIIT IPv4-translated)
  if (zero(0, 4) && g[4] === 0xffff && g[5] === 0) return true;
  // 64:ff9b::/96 NAT64 well-known prefix: judge the embedded IPv4
  if (g[0] === 0x64 && g[1] === 0xff9b && zero(2, 6)) return v4IntIsPrivate(v4At(6, 7));
  // 64:ff9b:1::/48 local-use NAT64
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return true;
  // 2002::/16 6to4: judge the embedded IPv4
  if (g[0] === 0x2002) return v4IntIsPrivate(v4At(1, 2));
  // 2001::/32 Teredo (client address hidden), 2001:db8::/32 documentation, 2001:10::/28 ORCHID
  if (g[0] === 0x2001 && (g[1] === 0 || g[1] === 0xdb8 || (g[1] & 0xfff0) === 0x10 || (g[1] & 0xfff0) === 0x20)) return true;
  // 3fff::/20 documentation
  if (g[0] === 0x3fff && (g[1] & 0xf000) === 0) return true;
  // Everything outside 2000::/3 global unicast: fc00::/7, fe80::/10, fec0::/10, ff00::/8, 100::/64 ...
  if ((g[0] & 0xe000) !== 0x2000) return true;
  return false;
}

/** Resolve A and AAAA records through Cloudflare's DNS-over-HTTPS JSON API. */
export async function dohResolve(host, fetchFn = globalThis.fetch) {
  const ips = [];
  let answered = 0;
  let failed = 0;
  for (const type of ['A', 'AAAA']) {
    try {
      const r = await fetchFn(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, {
        headers: { accept: 'application/dns-json' },
      });
      if (!r.ok) { failed++; continue; }
      const j = await r.json();
      if (j.Status === 0 || j.Status === 3) answered++;
      else failed++;
      for (const a of j.Answer || []) if (a.type === 1 || a.type === 28) ips.push(String(a.data));
    } catch { failed++; }
  }
  return { ips, answered, failed };
}

/**
 * Host guard: the syntactic URL check plus a DNS check that refuses names resolving to a private
 * or reserved address. Use it for the first URL, every redirect hop and every discovery URL.
 * opts.resolve(host) -> string[] uses the runtime resolver; without it, DNS-over-HTTPS (1.1.1.1) is used.
 * opts.failClosed: refuse when DNS cannot be read (default true). Results are cached per host.
 * Returns a function url -> Promise<{ok:true,url}|{ok:false,error,reason}> with .dns(host).
 */
export function makeHostGuard(opts = {}) {
  const { resolve, fetch: fetchFn = globalThis.fetch, failClosed = true } = opts;
  const cache = new Map();
  const dns = (host) => {
    if (!cache.has(host)) {
      cache.set(host, (async () => {
        let ips = []; let answered = 0; let failed = 0;
        if (resolve) {
          try { ips = (await resolve(host)) || []; answered = 2; } catch (e) {
            const code = e && e.code;
            if (code === 'ENOTFOUND' || code === 'ENODATA') answered = 2; else failed = 2;
          }
        } else {
          ({ ips, answered, failed } = await dohResolve(host, fetchFn));
        }
        const bad = ips.find((ip) => isPrivateIp(ip));
        if (bad) return { ok: false, error: 'blocked_host', reason: `${host} resolves to a private or reserved address` };
        if (answered === 2 && !ips.length) return { ok: false, error: 'unreachable', reason: `${host} has no A or AAAA record` };
        if (!ips.length && failed && failClosed) return { ok: false, error: 'blocked_host', reason: `DNS for ${host} could not be checked` };
        return { ok: true, ips };
      })());
    }
    return cache.get(host);
  };
  const guard = async (input) => {
    const v = checkUrlSafety(input);
    if (!v.ok) return v;
    const host = v.url.hostname.toLowerCase().replace(/\.$/, '');
    const d = await dns(host);
    if (!d.ok) return { ok: false, error: d.error, reason: d.reason };
    return v;
  };
  guard.dns = dns;
  return guard;
}

/** sha256 hex of a string (WebCrypto, works in Workers and Node 20+). */
export async function sha256Hex(s) {
  const buf = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Result id: first 12 hex chars of sha256(normalized url). */
export async function resultId(url) {
  return (await sha256Hex(normalizeUrl(url))).slice(0, 12);
}
