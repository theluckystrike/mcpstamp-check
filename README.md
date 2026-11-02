# McpStamp Check

Score any remote MCP server for readiness for the **Claude Directory**, **ChatGPT Apps**, **Gemini Connected Apps** and the **MCP Registry**: a 0-100 score, an A-F grade, per-store readiness and a one-line fix for every failing check.

Try it: <https://www.mcpstamp.com/check/>

Readiness Index: <https://www.mcpstamp.com/readiness/> ranks the remote servers listed in the official MCP Registry by this engine's score, with per-store readiness for each server.

## Badge

After a check, embed your badge in your README (`<id>` is in the check result):

```markdown
[![McpStamp](https://www.mcpstamp.com/badge/<id>.svg)](https://www.mcpstamp.com/check/?id=<id>)
```

The badge shows `McpStamp | 87 B`, coloured by grade, or a grey `unchecked`.

## MCP server

McpStamp Check is itself a remote MCP server (Streamable HTTP, protocol 2025-11-25, no sign-in):

```
https://mcp.zovo.one/stamp/mcp
```

| Tool | What it does |
|---|---|
| `check_mcp_server(url, fresh?)` | Score, grade, readiness per store, every failing check with its fix, report URL and badge markdown |
| `explain_check(check_id)` | What a check means, which stores it blocks, and the store or spec source |

Add it to your client:

```sh
# Claude Code
claude mcp add --transport http mcpstamp https://mcp.zovo.one/stamp/mcp
```

```jsonc
// Cursor: ~/.cursor/mcp.json
{ "mcpServers": { "mcpstamp": { "url": "https://mcp.zovo.one/stamp/mcp" } } }

// VS Code: .vscode/mcp.json
{ "servers": { "mcpstamp": { "type": "http", "url": "https://mcp.zovo.one/stamp/mcp" } } }
```

Then ask: "Check https://example.com/mcp with McpStamp". Live checks share the API limit (20 per hour per client). It is listed in the MCP Registry as `io.github.theluckystrike/mcpstamp-check`.

## GitHub Action

Gate your CI on readiness. The action calls the public API, writes a job summary (score, stores, fixes) and fails the step when the score is below `min-score` or a store in `fail-on-store` is not ready.

```yaml
name: McpStamp Check
on:
  workflow_dispatch:
  push:
    branches: [main]
jobs:
  mcpstamp:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: theluckystrike/mcpstamp-check@v1
        id: stamp
        with:
          url: https://example.com/mcp
          min-score: 80
          fail-on-store: claude,chatgpt
      - run: echo "Score ${{ steps.stamp.outputs.score }} (${{ steps.stamp.outputs.grade }}): ${{ steps.stamp.outputs.report-url }}"
```

| Input | Default | Meaning |
|---|---|---|
| `url` | (required) | The https URL of your MCP endpoint |
| `min-score` | `0` | Fail when the score is below this value |
| `fail-on-store` | empty | Comma list of `claude`, `chatgpt`, `gemini`, `registry` that must be ready (a store whose blocking checks could not run, for example tools behind sign-in, is not ready) |
| `fresh` | `true` | `false` accepts a result up to 10 minutes old. On a rate limit the action falls back to the cached result |
| `api-base` | `https://mcp.zovo.one/stamp` | API base URL |

Outputs: `score`, `grade`, `report-url`, `badge-url`, `ready-stores`.

The action is a composite action that runs `action/run.mjs` with the runner's Node.js (18 or later), with no dependencies and no build step. Check a deployed URL: run it after your deploy step.

## API

Base URL: `https://mcp.zovo.one/stamp` (also proxied at `https://www.mcpstamp.com/api/`).

| Request | Response |
|---|---|
| `GET /api/check?url=<https MCP URL>[&fresh=1]` | Result JSON (cached for 10 minutes) |
| `GET /api/result/<id>` | Last stored result, 404 if none |
| `GET /api/checks` | The check table below |
| `GET /badge?url=<url>` or `GET /badge/<id>.svg` | SVG badge |
| `POST /mcp` | MCP Streamable HTTP endpoint (see above) |

Errors: `400 {error:"bad_url"|"blocked_host"}`, `429 {error:"rate_limited", retry_after}`, `502 {error:"unreachable"|"blocked_by_firewall", detail}` (`blocked_by_firewall`: the server's WAF or bot protection answered with a 403 HTML page or a Cloudflare challenge, so nothing was scored).
Limits: 20 live checks per hour per IP; at most 10 HTTP requests to the checked server per check and 25 s wall time per check; 8 s timeout and 1 MB body cap per request; https only, ports 443/8443, no IP literals or private names; every URL fetched (first URL, each of max 3 redirect hops, each discovery URL) is re-validated and its DNS answers (DNS-over-HTTPS) must be public. Results are kept 30 days; a badge request for a result older than 7 days triggers one background re-check. Credentials in the URL (the segment after `/t/`, random-looking path segments of 24+ characters, secret query values) are shown and stored as `REDACTED`.

## Proxies

A trusted proxy (the mcpstamp.com Pages Functions) may send `x-mcpstamp-proxy-key: <PROXY_KEY secret>` and `x-mcpstamp-client-ip: <visitor IP>` so the rate limit applies per visitor, not per proxy.

## Scoring

Each check is `pass` (1), `warn` (0.5), `fail` (0) or `skip` (not counted). Score = weighted pass ratio over the checks that apply. Grades: A >= 90, B >= 80, C >= 65, D >= 50, else F. Each store gets `status`: `ready` (no blocking check failed and none was skipped), `unverified` (none failed, but a blocking check could not run, for example tools behind sign-in) or `not_ready` (a blocking check failed). `ready` is true only for `ready`. When the tools sit behind sign-in and cannot be inspected, the score is capped at 85. Skipped checks carry `skip_reason`: `not_applicable`, `needs_sign_in`, `not_probed` (request or time budget), `not_reached` (handshake did not complete) or `blocked`; each store lists `unverified_reasons`. A check may carry `store_status` when one store treats it more softly (for example legacy SSE is a warning for Claude and the Registry). The `registry` store means "a valid remote for the MCP Registry" (public https, answers as Streamable HTTP or SSE), not that the server is published there.

The table below is generated from the `CHECKS` export in `src/check.mjs` (`node scripts/scoring-table.mjs --write`; a test fails when it is out of date). "Blocks" lists the stores that are not ready when the check fails. `GET /api/checks` returns the same data plus the stores each check counts toward. Auth checks are skipped for servers without sign-in.

<!-- scoring-table:start (generated by scripts/scoring-table.mjs from CHECKS) -->
| Check | Group | What it tests | Weight | Blocks (fail = not ready) |
|---|---|---|---|---|
| `https` | transport | Served over HTTPS | 10 | claude, chatgpt, gemini, registry |
| `initialize` | transport | initialize over Streamable HTTP | 15 | claude, chatgpt, gemini, registry |
| `protocol_version` | transport | Supported protocol version negotiated | 6 | gemini |
| `content_type` | transport | JSON or SSE response Content-Type | 3 | - |
| `jsonrpc_errors` | transport | JSON-RPC error for unknown method | 4 | - |
| `get_stream` | transport | GET answers SSE or 405 | 3 | - |
| `latency` | transport | initialize latency | 5 | - |
| `server_info` | metadata | serverInfo name and version | 6 | - |
| `instructions` | metadata | Server instructions | 4 | - |
| `capabilities_tools` | metadata | tools capability declared | 3 | - |
| `auth_method` | auth | Sign-in method the store supports (OAuth or none) | 6 | chatgpt, gemini |
| `auth_challenge` | auth | 401 carries WWW-Authenticate resource_metadata | 6 | - |
| `auth_prm` | auth | Protected resource metadata (RFC 9728) | 8 | claude, chatgpt |
| `auth_resource` | auth | Resource metadata "resource" equals the server URL | 4 | claude |
| `auth_as_metadata` | auth | Authorization server metadata (RFC 8414 / OIDC) | 8 | claude, chatgpt, gemini |
| `auth_gemini_discovery` | auth | First metadata URL Gemini tries answers 200 with the required fields | 4 | gemini |
| `auth_chatgpt_metadata` | auth | issuer equals the authorization_servers entry; token_endpoint_auth_methods_supported (ChatGPT) | 4 | chatgpt |
| `auth_pkce` | auth | PKCE S256 advertised | 6 | claude, chatgpt, gemini |
| `auth_registration` | auth | Client registration (DCR or Client ID Metadata Documents) | 6 | - |
| `auth_refresh` | auth | refresh_token grant advertised | 3 | - |
| `tools_list` | tools | tools/list returns tools | 10 | claude, chatgpt, gemini |
| `tool_schema` | tools | inputSchema is an object schema | 6 | claude, chatgpt, gemini |
| `tool_names` | tools | Tool names are valid and portable | 5 | - |
| `tool_annotations` | tools | readOnlyHint or destructiveHint on every tool | 10 | claude, chatgpt |
| `tool_open_world` | tools | Explicit readOnlyHint, destructiveHint and openWorldHint (ChatGPT) | 5 | chatgpt |
| `tool_titles` | tools | Human-readable title on every tool | 5 | claude, chatgpt |
| `tool_descriptions` | tools | Tool descriptions | 6 | - |
| | | **Total weight (all checks)** | **161** | |
<!-- scoring-table:end -->

Every rule is traced to the store or spec text in [SOURCES.md](SOURCES.md).

## Use the engine

`src/check.mjs` is a pure ES module with no dependencies. It runs in Node 20+ and in Cloudflare Workers:

```js
import { checkServer, CHECKS } from './src/check.mjs';
const result = await checkServer('https://example.com/mcp', { fetch, timeoutMs: 8000 });
console.log(result.score, result.grade, result.stores.claude);
```

Every fetched URL passes a host guard (syntax plus DNS). By default DNS goes through DNS-over-HTTPS (1.1.1.1) and the check refuses when DNS cannot be read. In Node, pass the system resolver so LAN and `/etc/hosts` names are judged by the same answers `fetch` will use:

```js
import { nodeResolve } from './src/resolve-node.mjs';
await checkServer(url, { fetch, resolve: nodeResolve });
```

CLI: `node scripts/check-cli.mjs https://example.com/mcp [--json]`

## Develop

```sh
npm test             # node --test, mock fetch, no network (engine, Worker, MCP endpoint, action)
npx wrangler deploy  # Worker "mcpstamp-check"
```

Contact: support@zovo.one

## License

MIT
