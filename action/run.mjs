// GitHub Action runner for McpStamp Check. No dependencies: Node 18+ (fetch).
// Reads INPUT_* env vars, calls the public API, writes outputs + job summary, exits 1 on a failed gate.
import { appendFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const STORE_NAMES = {
  claude: 'Claude Directory',
  chatgpt: 'ChatGPT Apps',
  gemini: 'Gemini Connected Apps',
  registry: 'MCP Registry',
};
const UA = 'mcpstamp-check-action/1 (+https://github.com/theluckystrike/mcpstamp-check)';

export function parseStores(input) {
  const list = String(input || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const bad = list.filter((s) => !STORE_NAMES[s]);
  return { list: [...new Set(list)], bad };
}

const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

const REASON_TEXT = { needs_sign_in: 'needs sign-in', not_probed: 'not probed', not_reached: 'handshake did not complete', blocked: 'blocked' };
export function unverifiedList(st) {
  const why = (st && st.unverified_reasons) || {};
  return ((st && st.unverified) || []).map((id) => (REASON_TEXT[why[id]] ? `${id} (${REASON_TEXT[why[id]]})` : id)).join(', ');
}

function storeStatus(st) {
  if (!st) return 'not_ready';
  return st.status || (st.ready ? 'ready' : 'not_ready');
}

export function summaryMarkdown(r, gate) {
  const lines = [];
  lines.push(`## McpStamp Check: ${r.score}/100 (${r.grade})`, '');
  lines.push(`Server: \`${esc(r.url)}\` - auth ${r.auth || 'unknown'}${r.protocol_version ? `, protocol ${r.protocol_version}` : ''}${typeof r.tool_count === 'number' ? `, ${r.tool_count} tools` : ''}${r.cached ? ' (cached result)' : ''}`, '');
  lines.push('| Store | Status | Score | Blockers |', '|---|---|---|---|');
  for (const [id, name] of Object.entries(STORE_NAMES)) {
    const st = (r.stores || {})[id] || {};
    const s = storeStatus(st);
    const label = s === 'ready' ? 'ready' : s === 'unverified' ? 'unverified' : 'not ready';
    const extra = s === 'unverified' && st.unverified && st.unverified.length ? `could not verify: ${unverifiedList(st)}` : (st.blockers || []).join(', ');
    lines.push(`| ${name} | ${label} | ${st.score ?? '-'} | ${esc(extra) || '-'} |`);
  }
  const issues = (r.checks || []).filter((c) => c.status === 'fail' || c.status === 'warn')
    .sort((a, b) => (a.status === b.status ? b.weight - a.weight : a.status === 'fail' ? -1 : 1));
  lines.push('');
  if (issues.length) {
    lines.push(`### Fixes (${issues.length})`, '', '| Check | Status | Detail | Fix |', '|---|---|---|---|');
    for (const c of issues) lines.push(`| \`${c.id}\` | ${c.status} | ${esc(c.detail)} | ${esc(c.fix)} |`);
  } else {
    lines.push('All checks pass or do not apply.');
  }
  lines.push('');
  if (gate.failures.length) {
    lines.push('### Gate failed', '');
    for (const f of gate.failures) lines.push(`- ${f}`);
  } else {
    lines.push(`Gate passed (min-score ${gate.minScore}${gate.stores.length ? `, stores ${gate.stores.join(', ')}` : ''}).`);
  }
  lines.push('', `Report: ${r.report_url}`, '', 'Badge for your README:', '', '```markdown', `[![McpStamp](${r.badge_url})](${r.report_url})`, '```', '');
  lines.push('Need it fixed? Readiness Audit $490: https://www.mcpstamp.com/services/', '');
  return lines.join('\n');
}

export function evaluateGate(r, minScore, stores) {
  const failures = [];
  if (r.score < minScore) failures.push(`Score ${r.score} is below min-score ${minScore}.`);
  for (const s of stores) {
    const st = (r.stores || {})[s];
    if (!st || !st.ready) {
      const status = storeStatus(st);
      const why = status === 'unverified' ? `unverified (${unverifiedList(st)})` : `blocked by ${((st && st.blockers) || []).join(', ') || 'unknown'}`;
      failures.push(`${STORE_NAMES[s]} is not ready: ${why}.`);
    }
  }
  return { failures, minScore, stores };
}

async function callApi(fetchFn, base, url, fresh) {
  const q = `${base.replace(/\/+$/, '')}/api/check?url=${encodeURIComponent(url)}${fresh ? '&fresh=1' : ''}`;
  const res = await fetchFn(q, { headers: { accept: 'application/json', 'user-agent': UA } });
  let body = null;
  try { body = await res.json(); } catch { /* not JSON */ }
  return { status: res.status, body };
}

/** Returns the process exit code. io: {env, fetch, log, error, warn, append(file, text)} */
export async function run(io) {
  const { env } = io;
  const url = (env.INPUT_URL || '').trim();
  if (!url) { io.error('Input "url" is required.'); return 1; }
  const minScore = Number(env.INPUT_MIN_SCORE || 0);
  if (!Number.isFinite(minScore) || minScore < 0 || minScore > 100) { io.error(`min-score must be a number 0-100, got "${env.INPUT_MIN_SCORE}".`); return 1; }
  const { list: stores, bad } = parseStores(env.INPUT_FAIL_ON_STORE);
  if (bad.length) { io.error(`Unknown store in fail-on-store: ${bad.join(', ')}. Use: ${Object.keys(STORE_NAMES).join(', ')}.`); return 1; }
  const fresh = String(env.INPUT_FRESH || 'true').toLowerCase() !== 'false';
  const base = env.INPUT_API_BASE || 'https://mcp.zovo.one/stamp';

  let out;
  try {
    out = await callApi(io.fetch, base, url, fresh);
    if (out.status === 429 && fresh) {
      io.warn('Rate limited for a fresh check; using the latest cached result if there is one.');
      out = await callApi(io.fetch, base, url, false);
    }
  } catch (e) {
    io.error(`McpStamp Check API request failed: ${(e && e.message) || e}`);
    return 1;
  }
  const r = out.body;
  if (out.status !== 200 || !r || typeof r.score !== 'number') {
    const err = r && r.error ? `${r.error}${r.detail ? ': ' + r.detail : ''}${r.retry_after ? ` (retry after ${r.retry_after} s)` : ''}` : `HTTP ${out.status}`;
    io.error(`McpStamp Check could not check ${url}: ${err}`);
    if (env.GITHUB_STEP_SUMMARY) io.append(env.GITHUB_STEP_SUMMARY, `## McpStamp Check: error\n\n\`${esc(url)}\`: ${esc(err)}\n`);
    return 1;
  }

  const ready = Object.keys(STORE_NAMES).filter((s) => r.stores && r.stores[s] && r.stores[s].ready);
  if (env.GITHUB_OUTPUT) {
    io.append(env.GITHUB_OUTPUT, [`score=${r.score}`, `grade=${r.grade}`, `report-url=${r.report_url}`, `badge-url=${r.badge_url}`, `ready-stores=${ready.join(',')}`].join('\n') + '\n');
  }
  const gate = evaluateGate(r, minScore, stores);
  if (env.GITHUB_STEP_SUMMARY) io.append(env.GITHUB_STEP_SUMMARY, summaryMarkdown(r, gate));
  io.log(`McpStamp Check: ${r.url} scored ${r.score}/100 (${r.grade}). Ready: ${ready.join(', ') || 'none'}. Report: ${r.report_url}`);
  for (const f of gate.failures) io.error(f);
  return gate.failures.length ? 1 : 0;
}

const cmd = (m) => String(m).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  const code = await run({
    env: process.env,
    fetch: globalThis.fetch,
    log: (m) => console.log(m),
    error: (m) => console.log(`::error title=McpStamp Check::${cmd(m)}`),
    warn: (m) => console.log(`::warning title=McpStamp Check::${cmd(m)}`),
    append: (file, text) => appendFileSync(file, text),
  });
  process.exitCode = code;
}
