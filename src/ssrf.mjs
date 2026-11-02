// URL safety guard for McpStamp Check. Pure ESM, no runtime-specific APIs.
// Syntactic checks only: the worker adds a DNS (DoH) check on top.

const BLOCKED_SUFFIXES = [
  '.localhost', '.local', '.internal', '.intranet', '.lan', '.home', '.corp',
  '.private', '.localdomain', '.home.arpa', '.arpa', '.test', '.invalid', '.example',
  '.onion', '.alt',
];
// Public wildcard DNS services that map names to arbitrary (often private) IPs.
const BLOCKED_DNS_SERVICES = [
  'nip.io', 'sslip.io', 'xip.io', 'localtest.me', 'lvh.me', 'vcap.me', 'lacolhost.com',
  'localhost.run', 'traefik.me', 'nip.direct', 'backname.io', 'fbi.com',
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

const SECRET_KEY_RE = /(token|key|secret|auth|password|passwd|pwd|session|sig|signature|credential|access)/i;
/** Same URL with secret-looking query values replaced, for public display. */
export function redactUrl(input) {
  const u = new URL(String(input));
  let changed = false;
  for (const [k] of [...u.searchParams]) {
    if (SECRET_KEY_RE.test(k)) { u.searchParams.set(k, 'REDACTED'); changed = true; }
  }
  return changed ? u.href : String(input);
}

function ipv4ToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
const V4_BLOCKS = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([b, m]) => [ipv4ToInt(b), m]);

/** True when an IP address (v4 or v6 string) is private, loopback, link-local or otherwise reserved. */
export function isPrivateIp(ip) {
  ip = String(ip).trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    const n = ipv4ToInt(ip);
    return V4_BLOCKS.some(([b, m]) => (n >>> (32 - m)) === (b >>> (32 - m)));
  }
  if (!ip.includes(':')) return true; // not an IP: treat as unsafe
  if (ip === '::' || ip === '::1') return true;
  const mapped = ip.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return isPrivateIp(mapped[1]);
  const first = parseInt(ip.split(':')[0] || '0', 16);
  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link local
  if ((first & 0xff00) === 0xff00) return true; // multicast
  if (ip.startsWith('2001:db8') || ip.startsWith('64:ff9b') || ip.startsWith('100::')) return true;
  return false;
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
