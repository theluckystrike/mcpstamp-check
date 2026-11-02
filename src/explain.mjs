// Plain-language meaning and sources for every check (summary of SOURCES.md).
import { CHECKS, STORE_TITLES, STORE_MEANING, SKIP_REASONS } from './check.mjs';

export const SOURCES_URL = 'https://github.com/theluckystrike/mcpstamp-check/blob/main/SOURCES.md';

const CLAUDE = 'https://claude.com/docs/connectors/building';
const SPEC = 'https://modelcontextprotocol.io/specification/2025-11-25';
const GEMINI = 'https://developers.google.com/connected-apps';

export const SOURCE_LINKS = {
  C1: { title: 'Claude Connectors Directory: submission', url: `${CLAUDE}/submission.md` },
  C2: { title: 'Claude Connectors Directory: review criteria', url: `${CLAUDE}/review-criteria.md` },
  C3: { title: 'Claude Connectors Directory: authentication', url: `${CLAUDE}/authentication.md` },
  C4: { title: 'Claude Connectors Directory: overview (transports, auth spec versions)', url: `${CLAUDE}/index.md` },
  C5: { title: 'Claude Connectors Directory: troubleshooting', url: `${CLAUDE}/troubleshooting.md` },
  O1: { title: 'OpenAI Apps SDK: submission guidelines', url: 'https://developers.openai.com/apps-sdk/app-submission-guidelines' },
  O2: { title: 'OpenAI Apps SDK: authentication', url: 'https://developers.openai.com/apps-sdk/build/auth' },
  O3: { title: 'OpenAI: upload and submit your plugin (authentication limitations)', url: 'https://developers.openai.com/apps-sdk/deploy/submission' },
  O4: { title: 'OpenAI: build an MCP server', url: 'https://developers.openai.com/plugins/build/mcp-server' },
  G1: { title: 'Google Connected Apps: MCP servers', url: `${GEMINI}/mcp` },
  G2: { title: 'Google Connected Apps: MCP server optimization', url: `${GEMINI}/mcp/server-optimization` },
  G3: { title: 'Google Connected Apps: MCP OAuth', url: `${GEMINI}/mcp/oauth` },
  R1: { title: 'MCP Registry: remote servers', url: 'https://modelcontextprotocol.io/registry/remote-servers' },
  S1: { title: 'MCP spec 2025-11-25: authorization', url: `${SPEC}/basic/authorization` },
  S2: { title: 'MCP spec 2025-11-25: transports', url: `${SPEC}/basic/transports` },
  S3: { title: 'MCP spec 2025-11-25: lifecycle', url: `${SPEC}/basic/lifecycle` },
  S4: { title: 'MCP spec 2025-11-25: tools', url: `${SPEC}/server/tools` },
  JSONRPC: { title: 'JSON-RPC 2.0 specification', url: 'https://www.jsonrpc.org/specification' },
};

// id -> [meaning, rule as encoded, source keys]
const TEXT = {
  https: ['Store clients only connect to public HTTPS endpoints.', 'The URL uses https://.', ['C1', 'R1', 'G1']],
  initialize: ['The server must complete the MCP handshake over the Streamable HTTP transport on this exact URL. Legacy HTTP+SSE is not supported by Gemini and not accepted for ChatGPT submission; Claude and the MCP Registry still accept it but it is deprecated.', 'POST initialize returns a JSON-RPC result (JSON or SSE). A 401 passes when OAuth discovery works; a 401 without OAuth discovery is not verified. Legacy SSE fails for ChatGPT and Gemini and warns for Claude and the Registry.', ['S2', 'S3', 'G2', 'C4', 'O4', 'R1', 'C5']],
  protocol_version: ['Clients negotiate a protocol version in initialize. Gemini supports 2025-03-26 up to 2025-11-25 only. Claude and OpenAI publish no list of accepted versions, so this check blocks only Gemini.', '2025-11-25 or 2025-06-18 pass, 2025-03-26 warns, 2024-11-05 or a version newer than requested fails (blocks Gemini).', ['G2', 'S3']],
  content_type: ['Clients parse the reply by its Content-Type.', 'JSON-RPC replies are application/json or text/event-stream.', ['S2']],
  jsonrpc_errors: ['Clients and reviewers expect standard JSON-RPC errors, not HTML pages or results.', 'An unknown method returns error code -32601 (Method not found).', ['JSONRPC', 'S3']],
  get_stream: ['The Streamable HTTP endpoint must answer GET with an SSE stream or 405.', 'GET returns text/event-stream or HTTP 405 (401 is fine on servers with auth).', ['S2', 'G2']],
  latency: ['Slow handshakes time out in store clients and feel broken to users.', 'initialize under 1.5 s passes, under 4 s warns. This threshold is a heuristic: no store publishes a number.', []],
  server_info: ['Clients show serverInfo in their UI and logs.', 'initialize returns serverInfo with name and version.', ['S3']],
  instructions: ['Instructions tell the model when to use the server and its limits. Gemini and OpenAI recommend them.', 'initialize.instructions has at least 40 characters.', ['G1', 'G2', 'O4']],
  capabilities_tools: ['Clients only call tools/list when the server declares the tools capability.', 'initialize.capabilities.tools is present.', ['S4']],
  auth_method: ['Stores sign users in with OAuth or connect without auth. ChatGPT and Gemini cannot send a static API key or token; Claude accepts a static request-header credential only in a beta for a limited set of organizations.', 'A server that answers 401/403 must offer MCP OAuth discovery. Without it: fail for ChatGPT and Gemini, warning for Claude.', ['O2', 'O3', 'G3', 'C3']],
  auth_challenge: ['A 401 with a resource_metadata pointer is how clients find your OAuth setup.', '401 responses carry WWW-Authenticate: Bearer resource_metadata="...".', ['C3', 'O2', 'S1']],
  auth_prm: ['Protected resource metadata (RFC 9728) names the authorization server. ChatGPT needs it to start sign-in. Claude also follows the 2025-03-26 auth spec, so for Claude a missing document is only a warning when authorization server metadata is found on the server origin.', 'A protected resource metadata document lists authorization_servers. Missing: fail for ChatGPT; for Claude a warning when origin metadata works, else fail.', ['C3', 'C4', 'C5', 'O2', 'S1']],
  auth_resource: ['Claude rejects sign-in when the metadata "resource" differs from the URL the user entered.', 'The "resource" value equals the server URL exactly, path included.', ['C3']],
  auth_as_metadata: ['Clients read authorization server metadata to find the authorize and token endpoints.', 'RFC 8414 or OIDC metadata has authorization_endpoint, token_endpoint and response_types_supported ["code"].', ['G3', 'S1', 'O2']],
  auth_gemini_discovery: ['The Gemini console fetches <issuer>/.well-known/oauth-authorization-server, then <issuer>/.well-known/openid-configuration (path issuers: suffix appended to the path), and uses the first URL that returns any response, even an error. Metadata served only at another location is never read.', 'The first Gemini URL that answers returns HTTP 200 with authorization_endpoint, token_endpoint and response_types_supported ["code"].', ['G3']],
  auth_chatgpt_metadata: ['OpenAI lists the metadata issuer and token_endpoint_auth_methods_supported as fields that must be correct: the issuer must be the exact value used in authorization_servers.', 'Authorization server metadata issuer equals the protected resource metadata authorization_servers entry (exact string), and token_endpoint_auth_methods_supported is a non-empty list.', ['O2']],
  auth_pkce: ['MCP clients refuse to sign in without PKCE S256.', 'code_challenge_methods_supported includes S256.', ['S1', 'O2', 'G3']],
  auth_registration: ['Without Dynamic Client Registration or Client ID Metadata Documents, every store needs a manually issued client id.', 'registration_endpoint or client_id_metadata_document_supported is advertised (warn only).', ['C3', 'O2', 'G3']],
  auth_refresh: ['Without refresh tokens, users are signed out when the access token expires.', 'grant_types_supported includes refresh_token.', ['G3', 'C3']],
  tools_list: ['Store reviewers test the tools. A server with no listable tools cannot be reviewed.', 'tools/list returns at least one tool.', ['S4']],
  tool_schema: ['Model APIs reject tools whose input schema is not a JSON object schema.', 'Every inputSchema (and outputSchema, if present) has type "object".', ['S4']],
  tool_names: ['Model APIs limit tool names to a strict character set and 64 characters.', 'Names are unique and match the spec; a warning when not ^[A-Za-z_][A-Za-z0-9_-]{0,63}$.', ['S4', 'C2']],
  tool_annotations: ['Claude requires the applicable readOnlyHint or destructiveHint on every tool; ChatGPT requires all three hints (see tool_open_world).', 'Every tool sets readOnlyHint or destructiveHint (a boolean).', ['C1', 'C2', 'O1']],
  tool_open_world: ['OpenAI app review requires all three hints as explicit values.', 'readOnlyHint, destructiveHint and openWorldHint are explicit booleans on every tool.', ['O1']],
  tool_titles: ['Store UIs and consent screens show the tool title.', 'Every tool has a title (or annotations.title).', ['C1', 'C2', 'O4']],
  tool_descriptions: ['Models choose tools by their description. Reviewers reject vague ones.', 'Every description has at least 20 characters (fail below); 60-2000 characters pass.', ['C2', 'G2']],
};

export function explainCheck(id) {
  const c = CHECKS.find((x) => x.id === id);
  if (!c) return null;
  const [meaning, rule, keys] = TEXT[c.id] || ['', '', []];
  return {
    id: c.id,
    title: c.title,
    group: c.group,
    weight: c.weight,
    meaning,
    rule,
    counts_for: c.stores.map((s) => STORE_TITLES[s]),
    store_meaning: Object.fromEntries(c.stores.map((s) => [STORE_TITLES[s], STORE_MEANING[s]])),
    blocks: c.blocks.map((s) => STORE_TITLES[s]),
    sources: keys.map((k) => SOURCE_LINKS[k]).filter(Boolean),
    sources_file: SOURCES_URL,
  };
}

export const CHECK_IDS = CHECKS.map((c) => c.id);
export { STORE_MEANING, SKIP_REASONS };
