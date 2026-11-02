import { test } from 'node:test';
import assert from 'node:assert/strict';
import { run, parseStores, evaluateGate } from '../action/run.mjs';

const RESULT = {
  id: 'abcdefabcdef', url: 'https://mcp.example.com/mcp', score: 74, grade: 'C', auth: 'none', protocol_version: '2025-11-25', tool_count: 3,
  stores: {
    claude: { status: 'not_ready', ready: false, score: 77, blockers: ['tool_titles'], unverified: [] },
    chatgpt: { status: 'not_ready', ready: false, score: 74, blockers: ['tool_open_world'], unverified: [] },
    gemini: { status: 'ready', ready: true, score: 77, blockers: [], unverified: [] },
    registry: { status: 'ready', ready: true, score: 93, blockers: [], unverified: [] },
  },
  checks: [
    { id: 'tool_titles', status: 'fail', weight: 5, detail: '3/3 without title', fix: 'Add a title | now.' },
    { id: 'https', status: 'pass', weight: 10, detail: 'ok', fix: null },
  ],
  badge_url: 'https://www.mcpstamp.com/badge/abcdefabcdef.svg', report_url: 'https://www.mcpstamp.com/check/?id=abcdefabcdef',
};

function io(env, responses) {
  const files = {}; const errors = []; const warns = []; const urls = [];
  let i = 0;
  return {
    env: { GITHUB_OUTPUT: 'out', GITHUB_STEP_SUMMARY: 'sum', ...env },
    fetch: async (u) => { urls.push(u); const [status, body] = responses[Math.min(i++, responses.length - 1)]; return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }); },
    log() {}, error: (m) => errors.push(m), warn: (m) => warns.push(m),
    append: (f, t) => { files[f] = (files[f] || '') + t; },
    files, errors, warns, urls,
  };
}

test('passes with defaults, writes outputs and summary', async () => {
  const x = io({ INPUT_URL: 'https://mcp.example.com/mcp' }, [[200, RESULT]]);
  assert.equal(await run(x), 0);
  assert.match(x.urls[0], /^https:\/\/mcp\.zovo\.one\/stamp\/api\/check\?url=https%3A%2F%2Fmcp\.example\.com%2Fmcp&fresh=1$/);
  assert.match(x.files.out, /^score=74$/m);
  assert.match(x.files.out, /^grade=C$/m);
  assert.match(x.files.out, /^report-url=https:\/\/www\.mcpstamp\.com\/check\/\?id=abcdefabcdef$/m);
  assert.match(x.files.out, /^ready-stores=gemini,registry$/m);
  assert.match(x.files.sum, /\| Claude Directory \| not ready \| 77 \| tool_titles \|/);
  assert.match(x.files.sum, /Add a title \\\| now\./);
  assert.match(x.files.sum, /Gate passed/);
});

test('fails below min-score and on a listed store that is not ready', async () => {
  let x = io({ INPUT_URL: 'https://mcp.example.com/mcp', INPUT_MIN_SCORE: '80' }, [[200, RESULT]]);
  assert.equal(await run(x), 1);
  assert.match(x.errors[0], /Score 74 is below min-score 80/);
  x = io({ INPUT_URL: 'https://mcp.example.com/mcp', INPUT_FAIL_ON_STORE: 'gemini, registry' }, [[200, RESULT]]);
  assert.equal(await run(x), 0);
  x = io({ INPUT_URL: 'https://mcp.example.com/mcp', INPUT_FAIL_ON_STORE: 'claude,gemini' }, [[200, RESULT]]);
  assert.equal(await run(x), 1);
  assert.match(x.errors.join(' '), /Claude Directory is not ready: blocked by tool_titles/);
  assert.match(x.files.sum, /Gate failed/);
});

test('unverified store fails the store gate', async () => {
  const r = { ...RESULT, stores: { ...RESULT.stores, claude: { status: 'unverified', ready: false, score: 85, blockers: [], unverified: ['tools_list'] } } };
  const g = evaluateGate(r, 0, ['claude']);
  assert.match(g.failures[0], /unverified \(tools_list\)/);
});

test('input validation and API errors', async () => {
  assert.deepEqual(parseStores('Claude, chatgpt,,claude'), { list: ['claude', 'chatgpt'], bad: [] });
  let x = io({ INPUT_URL: 'https://mcp.example.com/mcp', INPUT_FAIL_ON_STORE: 'claud' }, [[200, RESULT]]);
  assert.equal(await run(x), 1);
  assert.match(x.errors[0], /Unknown store/);
  x = io({ INPUT_URL: '' }, [[200, RESULT]]);
  assert.equal(await run(x), 1);
  x = io({ INPUT_URL: 'https://down.example.com/mcp' }, [[502, { error: 'unreachable', detail: 'timeout' }]]);
  assert.equal(await run(x), 1);
  assert.match(x.errors[0], /unreachable: timeout/);
});

test('429 on a fresh check falls back to the cached result', async () => {
  const x = io({ INPUT_URL: 'https://mcp.example.com/mcp' }, [[429, { error: 'rate_limited', retry_after: 60 }], [200, { ...RESULT, cached: true }]]);
  assert.equal(await run(x), 0);
  assert.equal(x.urls.length, 2);
  assert.ok(!x.urls[1].includes('fresh=1'));
  assert.equal(x.warns.length, 1);
});
