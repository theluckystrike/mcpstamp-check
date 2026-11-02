// Self-scan: run the engine over every hosted endpoint listed by https://mcp.zovo.one/mcp/token.
// Usage: node scripts/self-scan.mjs [out.json]   (concurrency 4)
import { writeFileSync } from 'node:fs';
import { checkServer } from '../src/check.mjs';
import { resultId } from '../src/ssrf.mjs';

const out = process.argv[2] || 'self-scan.json';
const tok = await (await fetch('https://mcp.zovo.one/mcp/token', { method: 'POST', headers: { 'user-agent': 'curl/8.7.1' } })).json();
const urls = [...new Set([...(tok.endpoints || []), 'https://mcp.zovo.one/mcp/invoice/v1'])];
const results = [];
let i = 0;
async function worker() {
  while (i < urls.length) {
    const url = urls[i++];
    const r = await checkServer(url, { fetch: globalThis.fetch });
    results.push({ id: await resultId(url), ...r });
  }
}
await Promise.all([worker(), worker(), worker(), worker()]);
results.sort((a, b) => a.url.localeCompare(b.url));
const scores = results.map((r) => r.score);
const avg = Math.round((scores.reduce((a, b) => a + b, 0) / scores.length) * 10) / 10;
const grades = {};
for (const r of results) grades[r.grade] = (grades[r.grade] || 0) + 1;
const ready = {};
for (const r of results) for (const [k, v] of Object.entries(r.stores)) ready[k] = (ready[k] || 0) + (v.ready ? 1 : 0);
const failCounts = {};
for (const r of results) for (const c of r.checks) if (c.status === 'fail' || c.status === 'warn') failCounts[`${c.id}:${c.status}`] = (failCounts[`${c.id}:${c.status}`] || 0) + 1;
const summary = { scanned_at: new Date().toISOString(), servers: results.length, average_score: avg, min: Math.min(...scores), max: Math.max(...scores), grades, store_ready: ready, issues: failCounts };
writeFileSync(out, JSON.stringify({ summary, results }, null, 2));
console.log(JSON.stringify(summary));
