# Claude Code credential endpoints

Pipelock recognizes the following Claude Code credential carriers. These additions cover the client’s sign-in refresh and revocation, profile, managed settings, organization policy, telemetry, and hosted MCP requests. They don’t grant an exception to other paths on these hosts.

The source is Anthropic’s native Linux x86-64 Claude Code **2.1.310** executable, installed as `~/.local/share/claude/versions/2.1.310`. Its own `--version` reports `2.1.310 (Claude Code)`. The SHA-256 is `b73676430af12f97316a798b8371f81d640f90a58bdcb8f3ce56a835bb47df56`. Locations below are zero-based byte offsets into the executable’s embedded JavaScript, not line numbers. The producer’s [network configuration documentation](https://code.claude.com/docs/en/network-config) confirms the API, token exchange/refresh/revocation, and MCP hosts. The executable supplies the exact routes and carriers.

| Host | Exact path | Carrier | Producer byte offset |
|------|------------|---------|----------------------|
| `api.anthropic.com` | `/api/oauth/profile` | Authorization Bearer | 240639603 |
| `api.anthropic.com` | `/api/oauth/validate` | Authorization Bearer | 240641317 |
| `api.anthropic.com` | `/api/oauth/claude_cli/roles` | Authorization Bearer | 237696624 (URL), 240647327 (request) |
| `api.anthropic.com` | `/api/oauth/claude_cli/create_api_key` | Authorization Bearer | 237696624 (URL), 240648077 (request) |
| `api.anthropic.com` | `/api/claude_cli_profile` | X-Api-Key | 240639085 |
| `api.anthropic.com` | `/api/claude_code/settings` | Authorization Bearer or X-Api-Key | 254417026 (URL), 254419870–254422098 (headers) |
| `api.anthropic.com` | `/api/claude_code/policy_limits` | Authorization Bearer or X-Api-Key | 239359836 (path), 246117290 and 246124459 (request), 240935044–240936210 (headers) |
| `api.anthropic.com` | `/api/event_logging/v2/batch` | Authorization Bearer or X-Api-Key | 241202589 (URL), 241219525 (headers) |
| `api.anthropic.com` | `/api/claude_code/metrics` | Authorization Bearer or X-Api-Key | 268225929 (URL), 268226400 (request using `kj` headers), 240935044–240936210 (headers) |
| `api.anthropic.com` | `/api/claude_code/organizations/metrics_enabled` | Authorization Bearer or X-Api-Key | 261268678 (URL and `kj` call), 240935044–240936210 (headers) |
| `platform.claude.com` | `/v1/oauth/token` | POST JSON `refresh_token`, with `grant_type: "refresh_token"` | 237696624 (URL), 240644304 (request) |
| `platform.claude.com` | `/v1/oauth/token/revoke` | POST JSON `token`, with `token_type_hint: "refresh_token"` | 240646860 |
| `mcp-proxy.anthropic.com` | `/v1/mcp/{server_id}` | Authorization Bearer | 237697331 (URL), 278592933 (path), 278578129 (header) |

The MCP server ID occupies one nonempty path segment. It doesn’t permit a trailing slash or child paths. Other listed paths match exactly. The existing `api.anthropic.com/v1` API allowance remains documented in [provider key coverage](provider-key-dlp-coverage.md).

Refresh and revocation require a complete JSON object without duplicate keys. Only the named credential field qualifies. A second credential in another field, including a split or encoded copy, retains DLP enforcement. The forwarded body stays unchanged. Queries, fragments, other methods, other media types, and other destinations don’t earn the OAuth body allowance. Other DLP rules still apply.

URL credentials remain blocked, including on these endpoints. Header exceptions don’t allow credentials in message bodies, and MCP stdio/HTTP tool input doesn’t inherit the network destination’s exception. Fetch scans its destination URL and doesn’t forward these authentication headers. Cleartext forward-proxy requests don’t earn a credential allowance; TLS-intercepted requests use their verified upstream destination. Encrypted CONNECT passthrough doesn’t inspect inner headers or bodies.

This table isn’t a blanket allowance for the client’s organization, marketplace, account-settings, cloud-session, or browser sign-in APIs. Those need their own route and carrier evidence before admission.
