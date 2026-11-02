# McpStamp Check

Score any remote MCP server for readiness for the **Claude Directory**, **ChatGPT Apps**, **Gemini Connected Apps** and the **MCP Registry**: a 0-100 score, an A-F grade, per-store readiness and a one-line fix for every failing check.

Try it: <https://www.mcpstamp.com/check/>

## Badge

After a check, embed your badge in your README (`<id>` is in the check result):

```markdown
[![McpStamp](https://www.mcpstamp.com/badge/<id>.svg)](https://www.mcpstamp.com/check/?id=<id>)
```

The badge shows `McpStamp | 87 B`, coloured by grade, or a grey `unchecked`.

## API

Base URL: `https://mcp.zovo.one/stamp` (also proxied at `https://www.mcpstamp.com/api/`).

| Request | Response |
|---|---|
| `GET /api/check?url=<https MCP URL>[&fresh=1]` | Result JSON (cached for 10 minutes) |
| `GET /api/result/<id>` | Last stored result, 404 if none |
| `GET /api/checks` | The check table below |
| `GET /badge?url=<url>` or `GET /badge/<id>.svg` | SVG badge |

Errors: `400 {error:"bad_url"|"blocked_host"}`, `429 {error:"rate_limited", retry_after}`, `502 {error:"unreachable", detail}`.
Limits: 20 live checks per hour per IP; at most 5 HTTP requests to the checked server per check; 8 s timeout and 1 MB body cap per request; https only, ports 443/8443, no IP literals or private names, max 3 redirects (each re-validated).

## Proxies

A trusted proxy (the mcpstamp.com Pages Functions) may send `x-mcpstamp-proxy-key: <PROXY_KEY secret>` and `x-mcpstamp-client-ip: <visitor IP>` so the rate limit applies per visitor, not per proxy.

## Scoring

Each check is `pass` (1), `warn` (0.5), `fail` (0) or `skip` (not counted). Score = weighted pass ratio over the checks that apply. Grades: A >= 90, B >= 80, C >= 65, D >= 50, else F. A store is **ready** when none of its blocking checks fail. When the tools sit behind sign-in and cannot be inspected, the score is capped at 85.

| Check | Group | What it tests | Weight | Counts for | Blocks |
|---|---|---|---|---|---|
| `https` | transport | Served over HTTPS | 10 | claude, chatgpt, gemini, registry | claude, chatgpt, gemini, registry |
| `initialize` | transport | initialize over Streamable HTTP | 15 | claude, chatgpt, gemini, registry | claude, chatgpt, gemini, registry |
| `protocol_version` | transport | Supported protocol version negotiated | 6 | claude, chatgpt, gemini, registry | gemini |
| `content_type` | transport | JSON or SSE response Content-Type | 3 | claude, chatgpt, gemini, registry | - |
| `jsonrpc_errors` | transport | JSON-RPC error for unknown method | 4 | claude, chatgpt, gemini, registry | - |
| `get_stream` | transport | GET answers SSE or 405 | 3 | claude, chatgpt, gemini, registry | - |
| `latency` | transport | initialize latency | 5 | claude, chatgpt, gemini, registry | - |
| `server_info` | metadata | serverInfo name and version | 6 | claude, chatgpt, gemini, registry | - |
| `instructions` | metadata | Server instructions | 4 | claude, chatgpt, gemini | - |
| `capabilities_tools` | metadata | tools capability declared | 3 | claude, chatgpt, gemini, registry | - |
| `auth_challenge` | auth | 401 carries WWW-Authenticate resource_metadata | 6 | claude, chatgpt, gemini | - |
| `auth_prm` | auth | Protected resource metadata (RFC 9728) | 8 | claude, chatgpt, gemini | claude, chatgpt |
| `auth_resource` | auth | Resource metadata "resource" equals the server URL | 4 | claude, chatgpt, gemini | claude |
| `auth_as_metadata` | auth | Authorization server metadata (RFC 8414 / OIDC) | 8 | claude, chatgpt, gemini | claude, chatgpt, gemini |
| `auth_pkce` | auth | PKCE S256 advertised | 6 | claude, chatgpt, gemini | claude, chatgpt, gemini |
| `auth_registration` | auth | Client registration (DCR or Client ID Metadata Documents) | 6 | claude, chatgpt, gemini | - |
| `auth_refresh` | auth | refresh_token grant advertised | 3 | claude, chatgpt, gemini | - |
| `tools_list` | tools | tools/list returns tools | 10 | claude, chatgpt, gemini, registry | claude, chatgpt, gemini |
| `tool_schema` | tools | inputSchema is an object schema | 6 | claude, chatgpt, gemini, registry | claude, chatgpt, gemini |
| `tool_names` | tools | Tool names are valid and portable | 5 | claude, chatgpt, gemini, registry | - |
| `tool_annotations` | tools | readOnlyHint and destructiveHint on every tool | 10 | claude, chatgpt, gemini | claude, chatgpt |
| `tool_open_world` | tools | Explicit readOnlyHint, destructiveHint and openWorldHint (ChatGPT) | 5 | chatgpt | chatgpt |
| `tool_titles` | tools | Human-readable title on every tool | 5 | claude, chatgpt, gemini | claude, chatgpt |
| `tool_descriptions` | tools | Tool descriptions | 6 | claude, chatgpt, gemini | - |

Every rule is traced to the store or spec text in [SOURCES.md](SOURCES.md).

## Use the engine

`src/check.mjs` is a pure ES module with no dependencies. It runs in Node 20+ and in Cloudflare Workers:

```js
import { checkServer, CHECKS } from './src/check.mjs';
const result = await checkServer('https://example.com/mcp', { fetch, timeoutMs: 8000 });
console.log(result.score, result.grade, result.stores.claude);
```

CLI: `node scripts/check-cli.mjs https://example.com/mcp [--json]`

## Develop

```sh
npm test             # node --test, mock fetch, no network
npx wrangler deploy  # Worker "mcpstamp-check"
```

Contact: support@zovo.one

## License

MIT
