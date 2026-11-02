import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkUrlSafety, normalizeUrl, isPrivateIp, resultId, redactUrl } from '../src/ssrf.mjs';
import { badgeSvg } from '../src/badge.mjs';

test('accepts normal https URLs', () => {
  for (const u of ['https://mcp.zovo.one/mcp/invoice/v1', 'https://example.com:8443/mcp', 'https://a.b.example.org/x?y=1']) {
    assert.equal(checkUrlSafety(u).ok, true, u);
  }
});

test('rejects unsafe URLs', () => {
  const cases = {
    'http://example.com/mcp': 'bad_url',
    'ftp://example.com/': 'bad_url',
    'not a url': 'bad_url',
    'https://user:pw@example.com/mcp': 'bad_url',
    'https://127.0.0.1/mcp': 'blocked_host',
    'https://2130706433/': 'blocked_host',
    'https://0x7f.1/': 'blocked_host',
    'https://[::1]/': 'blocked_host',
    'https://[::ffff:10.0.0.1]/': 'blocked_host',
    'https://10.0.0.5/': 'blocked_host',
    'https://169.254.169.254/latest/meta-data': 'blocked_host',
    'https://localhost/mcp': 'blocked_host',
    'https://foo.localhost/': 'blocked_host',
    'https://printer.local/': 'blocked_host',
    'https://svc.internal/': 'blocked_host',
    'https://intranet/': 'blocked_host',
    'https://127.0.0.1.nip.io/': 'blocked_host',
    'https://10-0-0-1.sslip.io/': 'blocked_host',
    'https://example.com:8080/': 'blocked_host',
    'https://example.com:22/': 'blocked_host',
  };
  for (const [u, err] of Object.entries(cases)) {
    const r = checkUrlSafety(u);
    assert.equal(r.ok, false, u);
    assert.equal(r.error, err, u);
  }
  assert.equal(checkUrlSafety('http://127.0.0.1').ok, false);
});

test('normalizeUrl', () => {
  assert.equal(normalizeUrl('https://MCP.Example.COM:443/mcp#frag'), 'https://mcp.example.com/mcp');
  assert.equal(normalizeUrl('https://example.com'), 'https://example.com/');
  assert.equal(normalizeUrl('https://example.com/mcp?'), 'https://example.com/mcp');
});

test('isPrivateIp', () => {
  for (const ip of ['10.1.2.3', '127.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fc00::1', 'fd12::3', 'fe80::1', '::ffff:192.168.0.1', '224.0.0.1']) assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ['1.1.1.1', '8.8.8.8', '172.32.0.1', '104.21.3.4', '2606:4700::1111']) assert.equal(isPrivateIp(ip), false, ip);
});

test('resultId is 12 hex chars and stable across equivalent URLs', async () => {
  const a = await resultId('https://MCP.example.com:443/mcp#x');
  const b = await resultId('https://mcp.example.com/mcp');
  assert.match(a, /^[0-9a-f]{12}$/);
  assert.equal(a, b);
  assert.notEqual(a, await resultId('https://mcp.example.com/mcp/v1'));
});

test('redactUrl hides secret query values', () => {
  assert.equal(redactUrl('https://x.com/mcp?token=abc&lang=en'), 'https://x.com/mcp?token=REDACTED&lang=en');
  assert.equal(redactUrl('https://x.com/mcp'), 'https://x.com/mcp');
});

test('badge svg', () => {
  const s = badgeSvg({ score: 87, grade: 'B' });
  assert.match(s, /^<svg /);
  assert.match(s, /87 B/);
  assert.match(s, /#97ca00/);
  const u = badgeSvg(null);
  assert.match(u, /unchecked/);
  assert.match(u, /#9f9f9f/);
});
