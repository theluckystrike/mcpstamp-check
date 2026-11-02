// Usage: node scripts/check-cli.mjs <url> [--json]
import { checkServer } from '../src/check.mjs';
import { nodeResolve } from '../src/resolve-node.mjs';
const url = process.argv[2];
const r = await checkServer(url, { fetch: globalThis.fetch, resolve: nodeResolve });
if (process.argv.includes('--json')) { console.log(JSON.stringify(r, null, 2)); process.exit(0); }
console.log(`${r.url}  score ${r.score} ${r.grade}  auth=${r.auth} proto=${r.protocol_version} tools=${r.tool_count} req=${r.requests} ${r.duration_ms}ms ${r.error || ''}`);
for (const [k, v] of Object.entries(r.stores)) console.log(`  ${k}: ready=${v.ready} score=${v.score} blockers=${v.blockers.join(',')} unverified=${v.unverified.join(',')}`);
for (const c of r.checks) console.log(`  [${c.status}] ${c.id} (${c.weight}) ${c.detail}${c.fix ? '  FIX: ' + c.fix : ''}`);
