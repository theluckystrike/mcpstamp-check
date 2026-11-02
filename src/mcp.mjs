// Remote MCP server (Streamable HTTP, stateless, authless) at /stamp/mcp.
// Tools call the same check code and rate limit as GET /stamp/api/check.
import { STORES, STORE_TITLES, STORE_MEANING, ENGINE_VERSION } from './check.mjs';
import { explainCheck, CHECK_IDS, SOURCES_URL } from './explain.mjs';

export const MCP_PROTOCOL = '2025-11-25';
export const MCP_PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
export const SERVER_VERSION = '1.2.0';
export const AUDIT_LINE = 'Need it fixed? Readiness Audit $490: https://www.mcpstamp.com/services/';
const MAX_BODY = 64 * 1024;

const MCP_CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS',
  'access-control-allow-headers': 'content-type, accept, authorization, mcp-session-id, mcp-protocol-version, last-event-id',
  'access-control-expose-headers': 'mcp-session-id, mcp-protocol-version',
  'access-control-max-age': '86400',
};

export const INSTRUCTIONS = 'McpStamp Check scores any public remote MCP server (Streamable HTTP URL) for readiness for the Claude Directory, ChatGPT Apps, Gemini Connected Apps and the MCP Registry. Use check_mcp_server with the server URL to get a 0-100 score, an A-F grade, per-store readiness and a fix for each failing check; use explain_check to learn what a check means and which store rule it comes from. Only https URLs on public hosts can be checked. Results are cached for 10 minutes and live checks are limited to 20 per hour per client.';

const ANN = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };

export const TOOLS = [
  {
    name: 'check_mcp_server',
    title: 'Check MCP server readiness',
    description: 'Check a public remote MCP server URL (Streamable HTTP) for readiness for the Claude Directory, ChatGPT Apps, Gemini Connected Apps and the MCP Registry. Returns the 0-100 score, A-F grade, readiness per store, every failing or warning check with its fix, the report URL and README badge markdown. Results are cached for 10 minutes; set fresh to true to force a new check.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'The https URL of the MCP endpoint, for example https://example.com/mcp' },
        fresh: { type: 'boolean', description: 'Run a new check even when a result from the last 10 minutes exists. Default false.' },
      },
      required: ['url'],
      additionalProperties: false,
    },
    outputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string' },
        score: { type: 'number' },
        grade: { type: 'string' },
        auth: { type: 'string' },
        stores: { type: 'object' },
        issues: { type: 'array', items: { type: 'object' } },
        report_url: { type: 'string' },
        badge_url: { type: 'string' },
        badge_markdown: { type: 'string' },
        checked_at: { type: 'string' },
        cached: { type: 'boolean' },
      },
      required: ['url', 'score', 'grade', 'stores', 'issues', 'report_url', 'badge_markdown'],
    },
    annotations: { title: 'Check MCP server readiness', ...ANN },
  },
  {
    name: 'explain_check',
    title: 'Explain a McpStamp check',
    description: 'Explain one McpStamp Check rule by its id (for example tool_annotations or auth_prm): what it tests, why stores need it, which stores it blocks, its weight and the store or spec documents it comes from. Use it after check_mcp_server to understand a failing check.',
    inputSchema: {
      type: 'object',
      properties: {
        check_id: { type: 'string', enum: CHECK_IDS, description: 'Check id from a check_mcp_server result.' },
      },
      required: ['check_id'],
      additionalProperties: false,
    },
    outputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        title: { type: 'string' },
        group: { type: 'string' },
        weight: { type: 'number' },
        meaning: { type: 'string' },
        rule: { type: 'string' },
        counts_for: { type: 'array', items: { type: 'string' } },
        blocks: { type: 'array', items: { type: 'string' } },
        sources: { type: 'array', items: { type: 'object' } },
        sources_file: { type: 'string' },
      },
      required: ['id', 'title', 'meaning', 'rule', 'sources'],
    },
    annotations: { title: 'Explain a McpStamp check', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
];

function rpcResult(id, result) { return { jsonrpc: '2.0', id, result }; }
function rpcError(id, code, message, data) {
  return { jsonrpc: '2.0', id: id ?? null, error: data === undefined ? { code, message } : { code, message, data } };
}

function reply(body, status = 200, extra = {}) {
  return new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: {
      ...(body === null ? {} : { 'content-type': 'application/json; charset=utf-8' }),
      'cache-control': 'no-store',
      ...MCP_CORS,
      ...extra,
    },
  });
}

function textResult(text, structured, isError = false) {
  const r = { content: [{ type: 'text', text }] };
  if (structured) r.structuredContent = structured;
  if (isError) r.isError = true;
  return r;
}

const REASON_TEXT = { needs_sign_in: 'needs sign-in', not_probed: 'not probed, request or time budget', not_reached: 'handshake did not complete', blocked: 'blocked' };

/** "tools_list, tool_schema (needs sign-in); auth_as_metadata (not probed, request or time budget)" */
export function unverifiedText(st) {
  const reasons = st.unverified_reasons || {};
  const groups = new Map();
  for (const id of st.unverified || []) {
    const k = REASON_TEXT[reasons[id]] || '';
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(id);
  }
  return [...groups].map(([k, ids]) => (k ? `${ids.join(', ')} (${k})` : ids.join(', '))).join('; ');
}

export function badgeMarkdown(r) {
  return `[![McpStamp](${r.badge_url})](${r.report_url})`;
}

/** Turn an API result into the tool's text and structured output. */
export function formatCheck(r) {
  const issues = (r.checks || [])
    .filter((c) => c.status === 'fail' || c.status === 'warn')
    .sort((a, b) => (a.status === b.status ? b.weight - a.weight : a.status === 'fail' ? -1 : 1))
    .map((c) => ({ id: c.id, status: c.status, title: c.title, detail: c.detail, fix: c.fix }));
  const stores = {};
  for (const s of STORES) {
    const st = (r.stores || {})[s] || {};
    const status = st.status || (st.ready ? 'ready' : 'not_ready');
    stores[s] = { name: STORE_TITLES[s], meaning: STORE_MEANING[s], status, ready: status === 'ready', score: st.score ?? 0, blockers: st.blockers || [], unverified: st.unverified || [], unverified_reasons: st.unverified_reasons || {} };
  }
  const md = badgeMarkdown(r);
  const lines = [];
  lines.push(`McpStamp Check: ${r.url}`);
  const meta = [`auth ${r.auth || 'unknown'}`];
  if (r.protocol_version) meta.push(`protocol ${r.protocol_version}`);
  if (typeof r.tool_count === 'number') meta.push(`${r.tool_count} tools`);
  meta.push(`checked ${r.checked_at}${r.cached ? ' (cached)' : ''}`);
  lines.push(`Score ${r.score}/100, grade ${r.grade}. ${meta.join(', ')}.`);
  if (r.limited) lines.push(`Parts of the server sit behind sign-in and could not be inspected, so the score is capped at 85.`);
  if (r.budget_hit) lines.push(`Some checks were not probed: the check stopped at its ${r.budget_hit}.`);
  lines.push('', 'Store readiness:');
  for (const s of STORES) {
    const st = stores[s];
    const label = st.status === 'ready' ? 'ready' : st.status === 'unverified' ? 'unverified' : 'NOT ready';
    let tail = st.blockers.length ? `, blocked by ${st.blockers.join(', ')}` : '';
    if (st.status === 'unverified') tail = `, could not verify ${unverifiedText(st)}`;
    lines.push(`- ${st.name}${s === 'registry' ? ' (valid remote)' : ''}: ${label} (score ${st.score})${tail}`);
  }
  lines.push('');
  if (issues.length) {
    lines.push(`Checks to fix (${issues.length}):`);
    for (const c of issues) {
      lines.push(`- [${c.status}] ${c.id}: ${c.title}. ${c.detail}`);
      if (c.fix) lines.push(`  Fix: ${c.fix}`);
    }
  } else {
    lines.push('All checks pass or do not apply.');
  }
  lines.push('', `Report: ${r.report_url}`, `README badge: ${md}`, '', AUDIT_LINE);
  const structured = {
    url: r.url,
    score: r.score,
    grade: r.grade,
    auth: r.auth || 'unknown',
    stores,
    issues,
    report_url: r.report_url,
    badge_url: r.badge_url,
    badge_markdown: md,
    checked_at: r.checked_at,
    cached: !!r.cached,
  };
  return { text: lines.join('\n'), structured };
}

function formatExplain(e) {
  const lines = [
    `${e.id}: ${e.title} (${e.group}, weight ${e.weight})`,
    '',
    `What it means: ${e.meaning}`,
    `Rule: ${e.rule}`,
    `Counts for: ${e.counts_for.join(', ') || 'none'}`,
    `Blocks store readiness for: ${e.blocks.join(', ') || 'none (score only)'}`,
    '',
    'Sources:',
    ...(e.sources.length ? e.sources.map((s) => `- ${s.title}: ${s.url}`) : ['- Heuristic, no store publishes a rule']),
    `Full source table: ${e.sources_file}`,
  ];
  return lines.join('\n');
}

async function callTool(name, args, deps) {
  if (name === 'explain_check') {
    const id = typeof args.check_id === 'string' ? args.check_id.trim() : '';
    const e = id ? explainCheck(id) : null;
    if (!e) return textResult(`Unknown check_id "${id}". Valid ids: ${CHECK_IDS.join(', ')}. Source table: ${SOURCES_URL}`, null, true);
    return textResult(formatExplain(e), e);
  }
  // check_mcp_server
  const url = typeof args.url === 'string' ? args.url.trim() : '';
  if (!url) return textResult('Missing "url": pass the https URL of the MCP endpoint, for example https://example.com/mcp.', null, true);
  if (args.fresh !== undefined && typeof args.fresh !== 'boolean') return textResult('"fresh" must be true or false.', null, true);
  const out = await deps.checkTarget(url, args.fresh === true);
  const b = out.body || {};
  if (out.http === 200 && typeof b.score === 'number') {
    const { text, structured } = formatCheck(b);
    return textResult(text, structured);
  }
  if (b.error === 'rate_limited') return textResult(`Rate limited: 20 live checks per hour per client. Try again in ${b.retry_after} seconds, or check the same URL without fresh to get a cached result.`, null, true);
  if (b.error === 'bad_url') return textResult(`Not a checkable URL (${b.detail || 'bad_url'}). Pass a public https URL of an MCP endpoint, for example https://example.com/mcp.`, null, true);
  if (b.error === 'blocked_host') return textResult(`This host cannot be checked: ${b.detail || 'private or reserved address'}. Only public https hosts are allowed.`, null, true);
  if (b.error === 'blocked_by_firewall') return textResult(`Could not check: ${b.detail || 'a firewall or bot protection blocked the request'}`, null, true);
  if (b.error === 'unreachable') return textResult(`The server did not answer: ${b.detail || 'no response'}. Make sure it is public, served over https, and answers POST initialize within 8 seconds.\n\n${AUDIT_LINE}`, null, true);
  return textResult(`Check failed: ${b.error || 'HTTP ' + out.http}${b.detail ? ' (' + b.detail + ')' : ''}.`, null, true);
}

async function dispatch(msg, deps) {
  const { id, method } = msg;
  const params = msg.params && typeof msg.params === 'object' ? msg.params : {};
  switch (method) {
    case 'initialize': {
      const asked = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
      return rpcResult(id, {
        protocolVersion: MCP_PROTOCOLS.includes(asked) ? asked : MCP_PROTOCOL,
        capabilities: { tools: { listChanged: false } },
        serverInfo: {
          name: 'mcpstamp-check',
          title: 'McpStamp Check',
          version: SERVER_VERSION,
          description: 'Readiness score for remote MCP servers: Claude, ChatGPT, Gemini and MCP Registry.',
          websiteUrl: 'https://www.mcpstamp.com/check/',
        },
        instructions: INSTRUCTIONS,
      });
    }
    case 'ping':
      return rpcResult(id, {});
    case 'tools/list':
      return rpcResult(id, { tools: TOOLS });
    case 'tools/call': {
      const name = params.name;
      if (typeof name !== 'string' || !TOOLS.some((t) => t.name === name)) {
        return rpcError(id, -32602, `Unknown tool: ${typeof name === 'string' ? name : '(missing name)'}`, { tools: TOOLS.map((t) => t.name) });
      }
      const args = params.arguments && typeof params.arguments === 'object' && !Array.isArray(params.arguments) ? params.arguments : {};
      return rpcResult(id, await callTool(name, args, deps));
    }
    case 'resources/list':
      return rpcError(id, -32601, 'Method not found: this server offers tools only');
    default:
      return rpcError(id, -32601, `Method not found: ${String(method).slice(0, 100)}`);
  }
}

/**
 * Handle a request to /mcp.
 * deps.checkTarget(url, fresh) -> {http, body} (same code path as GET /api/check).
 */
export async function handleMcp(req, deps) {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: MCP_CORS });
  if (req.method !== 'POST') {
    return reply(rpcError(null, -32000, 'Method not allowed: this server has no server-initiated stream and no sessions. Send JSON-RPC with POST.'), 405, { allow: 'POST, OPTIONS' });
  }
  const pv = req.headers.get('mcp-protocol-version');
  if (pv && !MCP_PROTOCOLS.includes(pv)) {
    return reply(rpcError(null, -32600, `Unsupported MCP-Protocol-Version: ${pv.slice(0, 40)}. Supported: ${MCP_PROTOCOLS.join(', ')}`), 400);
  }
  const len = Number(req.headers.get('content-length') || 0);
  if (len > MAX_BODY) return reply(rpcError(null, -32600, 'Request body too large'), 413);
  let text;
  try { text = await req.text(); } catch { return reply(rpcError(null, -32700, 'Parse error: unreadable body'), 400); }
  if (text.length > MAX_BODY) return reply(rpcError(null, -32600, 'Request body too large'), 413);
  let msg;
  try { msg = JSON.parse(text); } catch { return reply(rpcError(null, -32700, 'Parse error: body is not valid JSON'), 400); }
  if (Array.isArray(msg)) return reply(rpcError(null, -32600, 'Invalid Request: JSON-RPC batches are not supported (protocol 2025-06-18 and later)'), 400);
  if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0') return reply(rpcError(msg && msg.id, -32600, 'Invalid Request: expected a JSON-RPC 2.0 object'), 400);
  const hasId = 'id' in msg && msg.id !== null && (typeof msg.id === 'string' || typeof msg.id === 'number');
  if (typeof msg.method !== 'string') {
    // A response from the client (to a request we never send) or junk.
    if (('result' in msg || 'error' in msg) && 'id' in msg) return reply(null, 202);
    return reply(rpcError(hasId ? msg.id : null, -32600, 'Invalid Request: missing method'), 400);
  }
  if (!hasId) {
    if ('id' in msg) return reply(rpcError(null, -32600, 'Invalid Request: id must be a string or number'), 400);
    return reply(null, 202); // notification
  }
  try {
    const out = await dispatch(msg, deps);
    return reply(out, 200, { 'mcp-protocol-version': MCP_PROTOCOLS.includes(pv) ? pv : MCP_PROTOCOL });
  } catch (e) {
    return reply(rpcError(msg.id, -32603, 'Internal error: ' + String((e && e.message) || e).slice(0, 200)), 200);
  }
}

export const MCP_INFO = { endpoint: 'POST /stamp/mcp', transport: 'streamable-http', protocol: MCP_PROTOCOL, tools: TOOLS.map((t) => t.name), engine: ENGINE_VERSION };
