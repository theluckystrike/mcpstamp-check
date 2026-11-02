import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.mjs';

function env() {
  const m = new Map();
  return { RESULTS: { get: async (k, t) => (m.has(k) ? (t === 'json' ? JSON.parse(m.get(k)) : m.get(k)) : null), put: async (k, v) => { m.set(k, v); } }, _m: m };
}
const ctx = { waitUntil() {} };
const get = (path, init) => worker.fetch(new Request('https://mcp.zovo.one' + path, init), env(), ctx);

test('400 on http://127.0.0.1 and private hosts', async () => {
  let r = await get('/stamp/api/check?url=' + encodeURIComponent('http://127.0.0.1'));
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, 'bad_url');
  r = await get('/stamp/api/check?url=' + encodeURIComponent('https://127.0.0.1/mcp'));
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, 'blocked_host');
  assert.equal(r.headers.get('access-control-allow-origin'), '*');
});

test('405 on POST, 204 on OPTIONS', async () => {
  assert.equal((await get('/stamp/api/check', { method: 'POST', body: '{}' })).status, 405);
  const o = await get('/stamp/api/check', { method: 'OPTIONS' });
  assert.equal(o.status, 204);
  assert.equal(o.headers.get('access-control-allow-origin'), '*');
});

test('unknown result 404, unchecked badge grey', async () => {
  assert.equal((await get('/stamp/api/result/000000000000')).status, 404);
  const b = await get('/stamp/badge/000000000000.svg');
  assert.equal(b.status, 200);
  assert.match(b.headers.get('content-type'), /image\/svg\+xml/);
  assert.match(await b.text(), /unchecked/);
});

test('stored result is served as badge and cached result', async () => {
  const e = env();
  e._m.set('r:abcdefabcdef', JSON.stringify({ id: 'abcdefabcdef', score: 93, grade: 'A', checked_at: new Date().toISOString() }));
  const b = await worker.fetch(new Request('https://mcp.zovo.one/stamp/badge/abcdefabcdef.svg'), e, ctx);
  assert.match(await b.text(), /93 A/);
  assert.match(b.headers.get('cache-control'), /max-age=21600/);
  const r = await worker.fetch(new Request('https://x.workers.dev/api/result/abcdefabcdef'), e, ctx);
  assert.equal((await r.json()).score, 93);
});
