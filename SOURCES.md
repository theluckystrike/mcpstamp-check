# McpStamp Check: externally verifiable requirements by store

Collected 2026-11-02. Scope: only checks a scorer can run from outside over HTTP/DNS, without logging in.
Legend: **MUST** = blocker or stated as mandatory. **SHOULD** = recommended. **INFO** = client behavior useful for a check. "unverified" = not confirmed in a primary source.
Gemini sources are local files in saved copies of developers.google.com/connected-apps pages (canonical URL under developers.google.com/connected-apps/...).

## Check -> source map (what engine v1.0.0 encodes)

| check | rule encoded | blocks | sources |
|---|---|---|---|
| `https` | URL is https:// | all | C1, Registry R1, Gemini G1 |
| `initialize` | POST initialize returns JSON-RPC result (JSON or SSE); 401 counts only with OAuth discovery | all | S2, S3, G2 (Streamable HTTP only), C5 |
| `protocol_version` | 2025-11-25/2025-06-18 pass, 2025-03-26 warn, 2024-11-05 or newer-than-requested fail | gemini | G2 (2025-03-26 to 2025-11-25), S3 |
| `content_type` | application/json or text/event-stream | - | S2 |
| `jsonrpc_errors` | unknown method -> -32601 | - | JSON-RPC 2.0, S3 |
| `get_stream` | GET -> text/event-stream or 405 (401 ok) | - | S2, G2 |
| `latency` | initialize < 1.5 s pass, < 4 s warn | - | heuristic (no store publishes a number) |
| `server_info` | serverInfo.name + version | - | S3 |
| `instructions` | instructions >= 40 chars | - | G1, G2, O4 |
| `capabilities_tools` | capabilities.tools present | - | S4 |
| `auth_challenge` | 401 has WWW-Authenticate Bearer resource_metadata | - | C3, O2, S1 |
| `auth_prm` | RFC 9728 doc with authorization_servers | claude, chatgpt | C3, O2, S1 |
| `auth_resource` | PRM resource equals the server URL exactly | claude | C3 ("must equal the URL as the user enters it in Claude, including any path component") |
| `auth_as_metadata` | RFC 8414/OIDC doc with authorization_endpoint, token_endpoint, response_types_supported ["code"] | claude, chatgpt, gemini | gdocs connected-apps_mcp_oauth, S1, O2 |
| `auth_pkce` | code_challenge_methods_supported includes S256 | claude, chatgpt, gemini | S1, O2, gdocs oauth |
| `auth_registration` | registration_endpoint or client_id_metadata_document_supported | - (warn) | C3, O2, gdocs oauth (manual client id allowed) |
| `auth_refresh` | grant_types_supported includes refresh_token | - | gdocs oauth (persistent linking), C3 |
| `tools_list` | tools/list returns >= 1 tool | claude, chatgpt, gemini | S4 |
| `tool_schema` | inputSchema (and outputSchema if present) type object | claude, chatgpt, gemini | S4 |
| `tool_names` | unique, spec charset/length; warn if not ^[A-Za-z_][A-Za-z0-9_-]{0,63}$ | - | S4, C2 (64 chars) |
| `tool_annotations` | readOnlyHint on every tool, destructiveHint where readOnlyHint is false | claude, chatgpt | C1, C2, O1 |
| `tool_open_world` | all three hints explicit booleans | chatgpt | O1 |
| `tool_titles` | title or annotations.title on every tool | claude, chatgpt | C1, C2, O4 |
| `tool_descriptions` | every description >= 20 chars (fail), 60-2000 (pass) | - | C2, G2 (heuristic thresholds) |

## 1. Anthropic Claude Connectors Directory (remote MCP)

Sources: C1 https://claude.com/docs/connectors/building/submission.md, C2 .../building/review-criteria.md, C3 .../building/authentication.md, C4 .../building/index.md, C5 .../building/troubleshooting.md

- **HTTPS URL**: "Your server is remote and reachable over HTTPS: the portal asks for an `https://` URL." (C1) **MUST**
- **Transport**: "Use Streamable HTTP ... Claude also supports the legacy HTTP+SSE transport, which is being deprecated in favor of Streamable HTTP." (C4) Streamable HTTP **SHOULD**; SSE accepted (warn only)
- **Auth spec versions**: "Claude follows the 2025-03-26, 2025-06-18, and 2025-11-25 authorization specifications" (C4). INFO. No list of supported `protocolVersion` values for initialize was published: unverified
- **Annotations (title + hint)**: "Every tool must include a `title` and the applicable hint: `readOnlyHint: true` for read-only tools, and `destructiveHint: true` for tools that modify or delete data." (C2). Requirements list: "every tool includes a `title` and the applicable `readOnlyHint` or `destructiveHint`" (C1). Portal: "If any tools are flagged for missing titles or annotations, fix them on your server before submitting." (C1) **MUST** (`title` = tool `title` or `annotations.title`; exact field read by the portal is unverified). `openWorldHint`: not required
- **Tool name length**: "Tool names must be 64 characters or fewer." (C2) **MUST**
- **No catch-all read/write tool**: "A single tool that accepts both safe HTTP methods ... and unsafe methods ... is rejected." (C2) **MUST**. Heuristic check only: a `method` enum with GET+POST in inputSchema
- **Descriptions**: "state precisely what the tool does and when to invoke it" (C2) **SHOULD**. Prompt-injection patterns ("Contain hidden, obfuscated, or encoded instructions", "attempt to override system instructions") cause rejection (C2) **MUST**. Heuristic only
- **Errors**: "generic errors such as 'Internal Server Error' or 'Bad Request' with no detail fail review" (C2) **MUST** (check by calling an unknown tool or sending bad args)
- **Result size**: "Maximum tool result size: ~150,000 characters" (claude.ai/Desktop); Claude Code "25,000 tokens" (C4) **MUST** (hard client limit)
- **Tool call timeout**: "240 seconds per tool call" (claude.ai/Desktop) (C4) **MUST**
- **OAuth endpoint latency**: "Claude waits up to 10 seconds for a response from your OAuth discovery, registration, and token endpoints, and up to 30 seconds for refresh token requests." (C3) **MUST** (measure discovery + DCR endpoints)
- **No-auth allowed**: `none` "No authentication (authless server) | Supported by default" (C3). Checklist: "OAuth 2.0 if your tools act on a user's account, or no authentication for public data" (C1) INFO: authless passes
- **Auth types accepted**: `oauth_dcr` and `oauth_cimd` "Supported by default"; `static_headers` beta; "A machine-to-machine `client_credentials` grant isn't supported" (C3) **MUST** (client_credentials-only AS = fail)
- **401 required to start sign-in**: "A `401` is required to start sign-in, and Claude ignores a `WWW-Authenticate` header on a `200` response" (C3) **MUST**
- **WWW-Authenticate resource_metadata**: "answer unauthenticated requests with a `401` whose `WWW-Authenticate` header points at the document" (C3) **SHOULD** (fallback probing `/.well-known/oauth-protected-resource/<path>` then root exists: "Treat this as a fallback")
- **PRM `resource` exact match**: "the document's `resource` field must equal the URL as the user enters it in Claude, including any path component" (C3) **MUST**
- **PRM `authorization_servers` first entry**: "If you list more than one, Claude uses the first entry and doesn't fall back to later entries" (C3) **MUST** (check the first entry resolves)
- **AS metadata**: RFC 8414 or OIDC at `/.well-known/`; "Claude tries `/.well-known/oauth-authorization-server` (RFC 8414) first, then falls back to `/.well-known/openid-configuration`" (C5) **MUST** (one of them 200 + JSON)
- **Client registration**: needs `registration_endpoint` (DCR) or CIMD or a pre-registered client (C5) **MUST** (one of three; pre-registered not visible from outside)
- **CIMD selection rule**: "Claude selects CIMD only when your authorization server metadata advertises both `"client_id_metadata_document_supported": true` and `"none"` in `token_endpoint_auth_methods_supported` ... If either is missing, Claude falls back to DCR." (C3) **MUST** for CIMD path
- **CIMD preferred at scale**: "For servers expecting high traffic from the directory, prefer CIMD or `oauth_anthropic_creds` over DCR." (C3) **SHOULD**
- **PKCE S256**: "Your authorization server must support S256 PKCE" and should advertise `"code_challenge_methods_supported": ["S256"]` (C3) **MUST**
- **Scopes**: `scope` in WWW-Authenticate controls requested scopes, else PRM `scopes_supported`; "Claude also appends `offline_access` when your authorization server metadata lists it in `scopes_supported`" (C3) **SHOULD**
- **Callback URLs**: "register exactly this redirect URI: `https://claude.ai/api/mcp/auth_callback`"; Claude Code loopback `http://localhost/callback` and `http://127.0.0.1/callback` with port ignored; CIMD at `https://claude.ai/oauth/claude-code-client-metadata` (C3) **MUST** (testable only via DCR POST with that redirect_uri, which creates a client: opt-in check)
- **Token endpoint content type**: "Your `/token` endpoint must accept `Content-Type: application/x-www-form-urlencoded`"; `/register` uses `application/json` (C3) **MUST**
- **Refresh errors**: return `invalid_grant` for dead refresh tokens; rotate refresh tokens for public clients (C3) **MUST** (not testable without a token)
- **Audience / resource**: "Claude sends the RFC 8707 `resource` parameter ... set to the canonical form of your MCP server URL ... lowercase scheme and host, no trailing slash, no fragment, and no default port" (C5) **MUST** (not testable without login)
- **No cross-host redirect**: a 301/302/307/308 to another host drops `Authorization` and fails (C5) **MUST**
- **Public IPv4 DNS**: rejected if any resolved address is private (10/8, 172.16/12, 192.168/16), CGNAT 100.64/10, loopback/link-local, mixed; "Connectors are IPv4-only, so a hostname that only publishes `AAAA` records can't be reached" (C5) **MUST**
- **Reachability**: "`curl -i https://.../your-mcp-path` returns a response. A `401` or `405` is fine" (C5) **MUST**
- **WAF / egress**: Anthropic egress `160.79.104.0/21`; AS host must also be reachable from it (C3) INFO (not testable from outside Anthropic)
- **Unsupported features**: "Resource subscriptions; Sampling; Advanced or draft capabilities" (C4) SHOULD NOT depend on them
- **Origin header validation**: listed in a search snippet of the checklist, not in the fetched page. unverified for Claude (see spec section 5)

## 2. OpenAI ChatGPT Apps / Plugins (Apps SDK, developer mode, submission)

Sources: O1 https://developers.openai.com/apps-sdk/app-submission-guidelines (now titled plugin guidelines), O2 https://developers.openai.com/apps-sdk/build/auth, O3 https://developers.openai.com/apps-sdk/deploy/submission ("Upload and submit your plugin"), O4 https://developers.openai.com/plugins/build/mcp-server, O5 https://developers.openai.com/api/docs/guides/custom-mcp-server (search summary only, not fetched in full)

- **HTTPS, public, stable**: "a stable, publicly reachable HTTPS endpoint"; "Do not use Secure MCP Tunnel alone, a temporary tunnel, or a local endpoint for public submission." (O4) **MUST**
- **Transport**: "Support the MCP streamable HTTP transport." (O4) **MUST** for submission. Developer mode also accepts SSE (O5, from search summary: unverified wording)
- **Protocol versions**: none listed (O4 links only the 2025-06-18 spec). unverified
- **Annotations (3 explicit booleans)**: "Set `readOnlyHint`, `destructiveHint`, and `openWorldHint` to explicit boolean values" (O1) **MUST**. Third-party guides say missing annotations fail the automated scan; O1 says only "If our automated review flags an annotation issue, you can submit an appeal." Blocker status: likely, unverified
- **Annotation semantics**: readOnlyHint "`true` only when the tool cannot change state"; destructiveHint "`true` when a tool can cause irreversible or difficult to reverse outcomes"; openWorldHint "`true` when a tool accesses the public internet or open-ended external entities" (O4) **MUST** (accuracy reviewed by humans)
- **Title**: "Each tool needs: An action-oriented name and human-readable title." (O4) **MUST** (O1 does not mention `title`)
- **Input schema**: "An explicit input schema." (O4) **MUST**; output schema "when the tool returns structured data" (O4) SHOULD
- **Tool names**: "Tool names must be unique within your MCP server." (O1) **MUST**. No length/charset rule from OpenAI (use spec 1-128 `[A-Za-z0-9_.-]`)
- **Descriptions**: "Each tool must have a nonempty description" (O1) **MUST**
- **No generic executor**: "Do not use discovery, operation selection, or schema fetching with a generic executor"; "Expose each model-callable operation as a separate tool" (O1) **MUST** (heuristic)
- **Inputs**: "Do not request the full conversation history"; "Do not request precise user location data" (O1) **MUST** (heuristic on param names like `conversation_history`, `latitude`)
- **Server instructions**: optional; "Keep the most important details in the first 512 characters." (O4) **SHOULD**
- **Auth modes**: portal supports "no authentication, OAuth, and mixed unauthenticated/OAuth access"; "the portal doesn't provide an API-key connection flow or a bearer-token input"; "public submission rejects nonempty server headers" (O3) INFO: no-auth allowed, static API key not allowed
- **PRM**: serve `/.well-known/oauth-protected-resource` "or advertise the same URL in a `WWW-Authenticate` header on `401 Unauthorized` responses"; `resource` = "the canonical HTTPS identifier for your MCP server"; `authorization_servers` required (O2) **MUST**
- **AS metadata**: provider "must expose one of the well-known discovery documents" (RFC 8414 or OIDC); `issuer` must equal the `authorization_servers` entry exactly (O2) **MUST**
- **PKCE S256 (blocker)**: "MCP servers are unsupported when their authorization server metadata omits this field or does not advertise `S256`" (O2) **MUST**
- **token_endpoint_auth_methods_supported**: listed as a required metadata field (O2) **MUST**
- **CIMD preferred**: "ChatGPT prioritizes CIMD when it is available." `client_id_metadata_document_supported: true`; ChatGPT CIMD client_id `https://chatgpt.com/oauth/client.json` (or `https://chatgpt.com/oauth/{callback_id}/client.json`); auth methods `none` and `private_key_jwt` (O2) **SHOULD**. DCR: `registration_endpoint` "when you support dynamic client registration" (O2). One of CIMD/DCR/predefined client needed: **MUST**
- **Redirect URIs**: stable `https://chatgpt.com/connector_platform_oauth_redirect`; otherwise `https://chatgpt.com/connector/oauth/{callback_id}` (O2) **MUST** (allowlist)
- **RFC 9207 iss**: stable redirect requires `authorization_response_iss_parameter_supported: true` and `iss` in every response, exact string match (O2) **MUST** for stable redirect only
- **Resource / audience**: ChatGPT sends `resource=` on authorization and token requests; "copy that value into the access token (commonly the `aud` claim)" (O2) **MUST** (not testable without login)
- **401 + WWW-Authenticate on bad token**: "respond with `401 Unauthorized` and a `WWW-Authenticate` header" (O2) **MUST** (testable with a junk bearer token)
- **Advertised scopes enabled**: "make sure every advertised scope is enabled for the OAuth client" (O2) **MUST** (not testable)
- **No client_credentials**: ChatGPT does not use "machine-to-machine OAuth grants such as client credentials" (O2) INFO
- **Per-tool securitySchemes**: `noauth` / `oauth2` per tool, "Stick to per-tool declarations"; `_meta["mcp/www_authenticate"]` with `error` and `error_description` for the linking UI (O2) **SHOULD** (MUST for mixed-auth linking UI)
- **Domain challenge**: plain-text token at `/.well-known/openai-apps-challenge`, "Return only the exact token," "not JSON"; base "must be an HTTPS origin on the MCP hostname or an eligible parent domain" (O3) **MUST** at submission (check only that the path returns 200 text/plain; token value is private)
- **URL is fixed**: "the current update flow does not support URL changes" (O3) INFO
- **Daily scan**: "OpenAI scans your hosted MCP server daily." (O3) INFO (uptime matters)
- **UI / CSP**: iframe origins via `_meta.ui.csp.frameDomains` or legacy `_meta["openai/widgetCSP"].frame_domains` (O1) **MUST** if iframes used
- **Latency/size**: "Meet the latency and availability needs" (O4); no numeric timeout or size limit published: unverified

## 3. Google Gemini Connected Apps (Connected Apps Platform)

Sources (local): G1 connected-apps_mcp.html, G2 connected-apps_mcp_server-optimization.html, G3 connected-apps_mcp_oauth.html, G4 connected-apps_gpc_prerequisites.html, G5 connected-apps_gpc_perform-the-steps.html, G6 connected-apps_mcp_dev-mode.html, G7 connected-apps_mcp_dev-mode_usage.html

- **HTTPS, Streamable HTTP**: "Your MCP server must be publicly reachable over HTTPS using the Streamable HTTP transport" (G4) **MUST**; dev mode: "make sure your URL starts with https://" (G7)
- **No legacy SSE**: "strictly supports the Streamable HTTP transport ... version 2025-03-26 and higher. It does not support the legacy HTTP with SSE transport" (G2) **MUST**
- **Single endpoint, POST, Accept**: all JSON-RPC via POST; requests send `Accept: application/json, text/event-stream`; server may answer JSON or SSE (G2) **MUST**
- **GET 405 OK**: "returning HTTP 405 Method Not Allowed is explicitly supported" (G2) INFO
- **Protocol version cap**: "supports the MCP specification up to version 2025-11-25. Newer specification releases are not yet supported." Developer "is responsible for ensuring your MCP server strictly adheres to a protocol version supported ... (2025-11-25) during the initialize handshake" (G2) **MUST** (negotiated version must be in 2025-03-26..2025-11-25)
- **Server instructions**: "we strongly recommend providing clear server instructions" (G1); "Assume this text will be added directly to the model's system prompt"; don't relist tool names (G2) **SHOULD**
- **Annotations on every tool**: "Declare explicit protocol annotations for every tool" (G1); `destructiveHint: true` and `openWorldHint: true` trigger confirmation; `readOnlyHint: true` on query tools; "Explicitly declaring annotations on all tools ensures predictable model routing" (G2) **SHOULD** (strong; not stated as blocker). Console: confirmation "automatically pre-selected if your tool's MCP annotations specify `destructiveHint: true`" (G5)
- **Tool naming**: "Use snake_case or camelCase for tool function names"; verb_noun; avoid generic names like "execute", `do_everything_tool` (G2) **SHOULD**. No length rule stated
- **Tool count**: "MCP servers exposing dozens of tools or deeply nested 'mega-tool' schemas will be flagged during review for fixes." (G2) **SHOULD** (warn above ~24 tools; threshold unverified)
- **Schema shape**: flat schemas; deep nesting or `oneOf`/`anyOf` = "too broad"; use enums; IDs as strings (G2) **SHOULD**
- **No internal tools**: omit health checks, setup, dev helpers from `tools/list` (G2) **SHOULD**
- **structuredContent unsupported**: "Because structuredContent is not yet supported in the Connected Apps Platform, manually serialize your data" into TextContent (G2) **MUST** (text content must carry the data)
- **Description hygiene**: no "VERY IMPORTANT:", "**CRITICAL**", no mentioning other apps' tools, no params named `system_prompt`, `conversation_history`, `full_context` (G2) **MUST** (security section, "Avoid this practice at all costs")
- **Schema frozen at registration**: snapshot of tools, args and instructions; "Changing the MCP server schema may break the integration and may cause the application to be disabled" (G2) INFO (versioned path `/v1` recommended **SHOULD**)
- **Subdomain/audience**: Gemini-specific subdomain must have matching `/.well-known/oauth-protected-resource` and "token audience / RFC 8707 resource validation" (G2) **MUST**
- **No-auth allowed**: "No: Select this option if your MCP server is publicly accessible without authentication" (G5) INFO
- **Auth models**: M2M OAuth client credentials supported; user-delegated authorization code; "Client ID metadata or Dynamic client registration (recommended) ... Google checks for CIMD first and falls back to DCR" (G5) INFO
- **registration_endpoint required (conflict)**: "Even if your server supports Client ID Metadata Documents, the Gemini app ... currently requires a dedicated registration_endpoint to be present in the discovery JSON" (G3) **MUST** unless client id/secret entered manually. Conflicts with G5 (CIMD first); score as MUST for auto-registration
- **AS metadata required fields**: `authorization_endpoint`, `token_endpoint` valid string URLs; `response_types_supported` must contain `code`; `registration_endpoint` (G3) **MUST**. "The integration fails if mandatory fields are missing"
- **AS discovery order + first-response trap**: tries `/.well-known/oauth-authorization-server` then `/.well-known/openid-configuration` (path-appended for path issuers); "uses the first URL that returns a response—including an error"; "receives a 404 or 500, it will not attempt to guess other URLs" (G3) **MUST** (first URL should return 200)
- **PKCE**: "PKCE is mandatory for all OAuth 2.1"; if supported, include `code_challenge_methods_supported: ["S256"]` and `grant_types_supported` (G3) **MUST** for OAuth 2.1
- **scopes_supported**: "If you support scope, you must include the scopes_supported field." (G3) **MUST** (conditional)
- **Refresh tokens**: "we strongly recommend configuring your authorization server to issue them"; Persistent Linking: do not rotate refresh token, return the same one (G3) **SHOULD** (conflicts with MCP spec rotation rule for public clients)
- **Redirect URIs to allowlist**: `https://oauth-redirect.googleusercontent.com/r/*`, `https://oauth-redirect-sandbox.googleusercontent.com/r/*`, `https://oauth-redirect-test.googleusercontent.com/r/*`, and the same three hosts with `/a/*` (G3); console shows app-specific URIs (G5) **MUST**
- **Revocation endpoint**: optional `/revoke` (G3) **SHOULD**
- **Domain verification**: `https://<your-domain>/.well-known/google-connected-apps` JSON `{"verification_tokens": [...]}`, "returns HTTP 200 OK directly without HTTP redirects" (G4, G5) **MUST** at registration (check: 200, no redirect, valid JSON with `verification_tokens` array)
- **Single global endpoint**: "Each connected app supports a single global MCP server endpoint. Separate data center URLs are not supported." (G4) **MUST**
- **Google egress IPs**: 108.177.64.0/20, 142.250.88.0/22, 172.217.80.0/20, 192.178.20.0/22, 192.179.0.0/20, 74.125.232.0/24, 136.121.40.0/21 on port 443 (G4) INFO
- **MCP Apps UI**: single UI resource max 15 MB, total 100 MB; MIME `text/html`, `text/javascript`, `text/css`, `text/html;profile=mcp-app` (G2) **MUST** if UI used
- **Error codes**: custom JSON-RPC codes -32300..-32502 (rate limit, permission, deadline) (G2) **SHOULD**
- **Timeouts**: "guardrails around ... execution latency" (G2); no number published. unverified

## 4. Official MCP Registry (registry.modelcontextprotocol.io)

Sources: R1 https://modelcontextprotocol.io/registry/remote-servers, R2 https://modelcontextprotocol.io/registry/authentication, R3 https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json, R4 github.com/modelcontextprotocol/registry internal/validators/utils.go + validators.go, R5 registry docs remote-servers.mdx (via gh code search), R6 docs/reference/server-json/official-registry-requirements.md

- **Public URL**: "A remote server MUST be publicly accessible at its specified URL." (R1) **MUST** (registry does not probe it at publish: unverified; scorer should probe)
- **Remote URL HTTPS, not localhost**: `IsValidRemoteURL` rejects `localhost`, `127.0.0.1`, `*.localhost` and non-`https` schemes (R4) **MUST**
- **Transport type**: `remotes[].type` "only streamable-http and sse are supported" (R4); "Remote servers should use the Streamable HTTP transport. The SSE transport is deprecated" (R1) **MUST** type in set; streamable-http **SHOULD**
- **Unique remote URL**: "remote URL ... is already used by server ..." fails publish (R4 tests, registry_service.go) **MUST**
- **Name pattern**: `^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$`, length 3..200; namespace "must start and end with alphanumeric characters" (R3, R4) **MUST**
- **Namespace auth**: GitHub `io.github.<user>/*`; domain `com.example.*/*` reverse-DNS (R2) **MUST**
- **HTTP auth file**: `https://<domain>/.well-known/mcp-registry-auth` containing `v=MCPv1; k=ed25519; p=<base64>` (or `k=ecdsap384`) (R2). DNS alternative: TXT `v=MCPv1; k=ed25519; p=...` (R2) **MUST** for domain namespaces (check file or TXT exists and parses)
- **URL host vs namespace**: "the Registry does not check that the remote URL is on `example.com`" (R5) INFO (scorer may flag mismatch as trust warning)
- **Required fields**: `name`, `description` (1..100 chars), `version` (max 255); `title` 1..100 (R3) **MUST**
- **websiteUrl / icon src HTTPS**: "websiteUrl must use https scheme"; "icon src must use https scheme"; icon `src` max 255, mimeType in png/jpeg/jpg/svg+xml/webp (R3, R4) **MUST**
- **_meta**: only `io.modelcontextprotocol.registry/publisher-provided` kept, max 4096 bytes (R6) **MUST**
- **Preview status**: "The MCP Registry is currently in preview. Breaking changes or data resets may occur" (R1) INFO
- Registry has no rule on annotations, auth, or protocol versions (none found).

## 5. MCP specification 2025-11-25 (transport, lifecycle, tools, authorization)

Sources: S1 https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization, S2 .../basic/transports, S3 .../basic/lifecycle, S4 .../server/tools, S5 .../schema (annotation defaults; from schema knowledge, not re-fetched: unverified wording)

Transport and lifecycle
- **Single endpoint POST+GET**: "The server MUST provide a single HTTP endpoint path ... that supports both POST and GET methods." (S2) **MUST**
- **Response content type**: for a request the server "MUST either return `Content-Type: text/event-stream` ... or `Content-Type: application/json`" (S2) **MUST**
- **Notifications -> 202**: "the server MUST return HTTP status code 202 Accepted with no body" (S2) **MUST**
- **GET**: "MUST either return `Content-Type: text/event-stream` ... or else return HTTP 405 Method Not Allowed" (S2) **MUST**
- **Origin**: "Servers MUST validate the `Origin` header on all incoming connections"; "If the `Origin` header is present and invalid, servers MUST respond with HTTP 403 Forbidden" (S2) **MUST** (test with `Origin: https://evil.example`)
- **Protocol header**: "If the server receives a request with an invalid or unsupported `MCP-Protocol-Version`, it MUST respond with `400 Bad Request`"; missing header -> assume `2025-03-26` (S2) **MUST**
- **Session ID**: "MUST only contain visible ASCII characters (0x21 to 0x7E)"; terminated session -> "MUST respond ... with HTTP 404 Not Found"; missing session on non-init request SHOULD -> 400 (S2) **MUST/SHOULD**
- **Version negotiation**: "If the server supports the requested protocol version, it MUST respond with the same version. Otherwise, the server MUST respond with another protocol version it supports." (S3) **MUST** (test with `2025-11-25` and with bogus `1999-01-01`)
- **InitializeResult**: `protocolVersion`, `capabilities`, `serverInfo` (`name`, `version` required; `title`, `description`, `icons`, `websiteUrl` optional), optional `instructions` (S3) **MUST** for required fields
- **tools capability**: "Servers that support tools MUST declare the `tools` capability" (S4) **MUST**
- **Timeouts**: "Implementations SHOULD establish timeouts for all sent requests" (S3) INFO

Tools
- **Tool names**: "SHOULD be between 1 and 128 characters"; only "A-Z, a-z, 0-9, _, -, ." ; "SHOULD NOT contain spaces, commas"; "SHOULD be unique within a server" (S4) **SHOULD** (regex `^[A-Za-z0-9_.-]{1,128}$`)
- **inputSchema**: "MUST be a valid JSON Schema object (not `null`)"; no-param tools: `{ "type": "object", "additionalProperties": false }` recommended (S4) **MUST**
- **outputSchema**: "Servers MUST provide structured results that conform to this schema" (S4) **MUST** if declared
- **structuredContent**: "SHOULD also return the serialized JSON in a TextContent block" (S4) **SHOULD** (Gemini makes this effectively MUST)
- **Annotations**: optional in spec; "clients MUST consider tool annotations to be untrusted unless they come from trusted servers" (S4). Defaults: readOnlyHint false, destructiveHint true, idempotentHint false, openWorldHint true (S5, unverified wording; Gemini G2 confirms readOnly/destructive defaults)
- **Errors**: unknown tool -> JSON-RPC error (example `-32602`); execution errors -> `isError: true` (S4) **SHOULD**

Authorization (only applies if the server requires auth; "Authorization is OPTIONAL")
- **PRM required**: "MCP servers MUST implement OAuth 2.0 Protected Resource Metadata (RFC9728)"; document "MUST include the `authorization_servers` field containing at least one authorization server" (S1) **MUST**
- **PRM discovery**: MUST do one of: `WWW-Authenticate` `resource_metadata` on 401, or well-known at `/.well-known/oauth-protected-resource/<mcp-path>` or root (S1) **MUST**
- **scope in challenge**: "MCP servers SHOULD include a `scope` parameter in the `WWW-Authenticate` header" (S1) **SHOULD**
- **AS discovery**: AS "MUST provide at least one of" RFC 8414 or OIDC Discovery. Path issuers: `/.well-known/oauth-authorization-server/<path>`, `/.well-known/openid-configuration/<path>`, `<path>/.well-known/openid-configuration` (S1) **MUST**
- **CIMD**: "Authorization servers and MCP clients SHOULD support OAuth Client ID Metadata Documents"; advertised via `client_id_metadata_document_supported: true` (S1) **SHOULD**
- **DCR**: "MAY support" RFC 7591; "included for backwards compatibility" (S1) **MAY**
- **Client priority**: pre-registered, then CIMD, then DCR, then prompt user (S1) INFO
- **PKCE**: "If `code_challenge_methods_supported` is absent ... MCP clients MUST refuse to proceed"; "Authorization servers providing OpenID Connect Discovery 1.0 MUST include `code_challenge_methods_supported`"; clients MUST use `S256` (S1) **MUST** (`S256` in list)
- **HTTPS AS endpoints**: "All authorization server endpoints MUST be served over HTTPS." (S1) **MUST**
- **Redirect URIs**: "MUST be either `localhost` or use HTTPS"; AS "MUST validate exact redirect URIs" (S1) **MUST**
- **Resource indicator**: clients MUST send RFC 8707 `resource` = canonical server URI (no fragment, no trailing slash preferred) (S1) INFO for server; PRM `resource` should match it
- **Audience**: "MCP servers MUST validate that access tokens were issued specifically for them"; "Invalid or expired tokens MUST receive a HTTP 401 response" (S1) **MUST** (testable: junk token -> 401)
- **Token in query**: "Access tokens MUST NOT be included in the URI query string" (S1) **MUST** (server should not accept `?access_token=`)
- **Status codes**: 401 auth required/invalid token, 403 insufficient scope (with `error="insufficient_scope"`), 400 malformed (S1) **MUST**
- **Refresh rotation**: "For public clients, authorization servers MUST rotate refresh tokens" (S1) **MUST** (not testable without login)

## Not found / unverified
- Claude and OpenAI: no published list of accepted `protocolVersion` values for initialize.
- OpenAI and Gemini: no numeric tool-call timeout or result-size limit.
- CORS: no store requires CORS headers for server-to-server MCP calls (none found). Only relevant for browser clients (e.g. MCP Inspector).
- OpenAI: whether a missing annotation blocks the automated scan (third-party guides say yes; official page mentions appeals only).
