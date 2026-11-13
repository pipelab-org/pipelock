# Provider-Key DLP Coverage

Pipelock's built-in provider-key DLP is prefix-first, not entropy-first. A
default rule is added only when the key shape has a distinctive provider prefix
and a useful length/charset boundary. This avoids blocking normal UUIDs, digests,
session IDs, request IDs, and opaque model/provider IDs.

## Covered By Default

The table lists compiled credential-audience rules and credentials that need explicit operator policy. Pipelock filters the matching DLP finding only when the proxy's verified destination host, API route, and credential carrier qualify. The scheme must be encrypted (`https` or `wss`); git, registry, and download-grant rules require `https`. Provider keys and messaging tokens qualify only on their documented authentication header, except for the structured Discord Gateway carrier below. Each allowance records `dlp_credential_audience_allow`. A core-floor credential (`Slack Token`, `GitHub Token`, `GitHub Fine-Grained PAT`, `GitLab PAT`) in a URL stays blocked even at its audience host, because the immutable core URL floor runs before any audience check. Other credential matches, the SSRF floors, and all other applicable checks still run. An audience allow doesn't approve the whole request.

Body, URL, unrelated-header, and WebSocket-frame copies of header-only credentials remain blocked. The one body exception is the Anthropic OAuth refresh and revocation JSON field at `platform.claude.com`, described in [Claude Code credential endpoints](claude-code-credentials.md). Google API keys have a separate `key` query-parameter allowance at the routes in the table; only that whole parameter value is exempt from query entropy. Adjacent query values, URL paths, and userinfo retain their checks. Google OAuth tokens require a Bearer `Authorization` header on the Gmail, Drive, and Storage JSON API routes listed below. Other Google API services and legacy Storage XML routes need explicit operator policy; the exact-route `suppress` control below applies to their body/header findings. GitHub token classes use an `Authorization` header with the Bearer or token scheme at `api.github.com`, `uploads.github.com`, or `rubygems.pkg.github.com`, plus the separate git and registry Basic rules below. `GitLab PAT` uses `PRIVATE-TOKEN` or `Authorization: Bearer` at `gitlab.com`, and `GitLab CI Job Token` uses `JOB-TOKEN`. Other GitLab token classes have no audience. URL, body, other-header, and WebSocket-frame matches for these carrier-restricted token classes remain blocked.

A separate git-over-HTTPS rule lets `GitHub Token`, `GitHub Fine-Grained PAT`, and `GitLab PAT` travel as `Authorization: Basic` to the git host (`github.com`, `gitlab.com`, or a declared enterprise host), and only on a git transport path: `<repo>/info/refs?service=git-upload-pack` or `?service=git-receive-pack`, `<repo>/git-upload-pack`, `<repo>/git-receive-pack`, or a Git LFS path under `<repo>/info/lfs/`, as defined by gitprotocol-http(5) and the Git LFS batch and locking API documents. The path is checked as forwarded; a percent-encoded path or one containing `..`, `.`, or `//` segments doesn't qualify. Basic on any other path at the git host, Bearer or token at `github.com`, and Basic at `api.github.com` all block. GitLab Bearer and `PRIVATE-TOKEN` use `/api/v4` at `gitlab.com`, and `GitLab PAT` also uses exactly `/api/graphql`; declared operator-owned hosts retain their instance API root.

`JWT Token` has separate release-download query, GHCR Bearer, qualifying registry Basic-password, and provider sign-in Bearer rules. `Azure SAS Token` has query-only download rules. See the shared notes below the table. `dlp.github_enterprise_hosts` and `dlp.gitlab_hosts` add exact operator-named hosts for enterprise and self-managed instances. A declared host is trusted with the credential: if it's attacker-controlled, it receives the token by design. AWS secret keys and private keys have no audience. Compiled audience allowances don't use `exempt_domains` or `suppress`. The audience is available without a paid license.

| Rule | Shape | Compiled API endpoint and carrier | Source |
|------|-------|--------------------------|--------|
| Anthropic API Key | `sk-ant-` + 20+ token chars | `api.anthropic.com/v1` (`X-Api-Key` or `Authorization: Bearer`), plus the exact [Claude Code endpoints and carriers](claude-code-credentials.md) | [Anthropic API overview](https://platform.claude.com/docs/en/api/overview); [OpenAI SDK compatibility](https://docs.claude.com/en/api/openai-sdk) |
| OpenAI API Key | `sk-proj-` + 20+ token chars | `api.openai.com/v1` (`Authorization: Bearer`) | [OpenAI API overview](https://developers.openai.com/api/reference/overview) |
| OpenAI Service Key | `sk-svcacct-` + 20+ token chars | `api.openai.com/v1` (`Authorization: Bearer`) | [OpenAI API overview](https://developers.openai.com/api/reference/overview) |
| Fireworks API Key | `fw_` + 22 alphanumeric chars | `api.fireworks.ai/inference/v1` or `/v1` (`Authorization: Bearer`) | [Fireworks authentication](https://docs.fireworks.ai/api-reference/authentication); unverified binding carried from prior defaults |
| LLM Router API Key | `sk-or-v1-` + 20+ hex chars | `openrouter.ai/api/v1` (`Authorization: Bearer`) | [OpenRouter API overview](https://openrouter.ai/docs/api_reference/overview) |
| Answer Engine API Key | `pplx-` + 20+ alphanumeric chars | `api.perplexity.ai` (`Authorization: Bearer`; root-level API routes) | [Perplexity quickstart](https://docs.perplexity.ai/docs/getting-started/quickstart) |
| Web Research API Key | `tvly-` + 20+ token chars | `api.tavily.com` (`Authorization: Bearer`; root-level API routes) | [Tavily quickstart](https://docs.tavily.com/documentation/quickstart) |
| Google API Key | `AIza` + 35 token chars | `generativelanguage.googleapis.com/v1` or `/v1beta`, `language.googleapis.com/v1`, `translation.googleapis.com/language/translate/v2` (`X-Goog-Api-Key` or exactly one `key` query parameter); `maps.googleapis.com/maps/api` (`key` query parameter only) | [Google API keys](https://cloud.google.com/docs/authentication/api-keys) |
| Google OAuth Token | `ya29.` + 20+ token chars | `gmail.googleapis.com/gmail/v1`, `www.googleapis.com/drive/v3`, `storage.googleapis.com/storage/v1`, plus the corresponding `/upload` and `/resumable/upload` prefixes (`Authorization: Bearer`) | Published [Gmail](https://www.googleapis.com/discovery/v1/apis/gmail/v1/rest), [Drive](https://www.googleapis.com/discovery/v1/apis/drive/v3/rest), and [Storage](https://www.googleapis.com/discovery/v1/apis/storage/v1/rest) discovery documents |
| Discord Bot Token | three base64url segments | `discord.com/api` (`Authorization: Bot`); `gateway.discord.gg/` (`wss` client Identify/Resume JSON, only `d.token`) | [Discord developer reference](https://docs.discord.com/developers/reference), [Gateway](https://docs.discord.com/developers/events/gateway), [Identify and Resume](https://docs.discord.com/developers/events/gateway-events) |
| Slack Token | `xox[bpras]-` or `xwfp-` + 15+ token chars | `slack.com/api` or exactly `mcp.slack.com/mcp` (`Authorization: Bearer`) | [Slack Web API](https://docs.slack.dev/apis/web-api/), [Slack MCP server](https://docs.slack.dev/ai/slack-mcp-server/), [token types](https://docs.slack.dev/authentication/tokens/), [token rotation](https://docs.slack.dev/authentication/using-token-rotation/) |
| Slack App Token | `xapp-` multi-segment | `slack.com/api` (`Authorization: Bearer`) | [apps.connections.open](https://docs.slack.dev/reference/methods/apps.connections.open/), [token types](https://docs.slack.dev/authentication/tokens/) |
| GitHub Token | `gh[pour]_` or `ghs_` | `api.github.com`, `uploads.github.com/repos`, `rubygems.pkg.github.com` (`Authorization: Bearer` or `Authorization: token`); `github.com` git transport paths (`Authorization: Basic`); `ghcr.io`, `maven.pkg.github.com`, `nuget.pkg.github.com` ([registry Basic](#registry-carriers)) | [GitHub REST authentication](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api), [release assets](https://docs.github.com/en/rest/releases/assets), [RubyGems authentication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-rubygems-registry) |
| GitHub Fine-Grained PAT | `github_pat_` | `api.github.com`, `uploads.github.com/repos`, `rubygems.pkg.github.com` (`Authorization: Bearer` or `Authorization: token`); `github.com` git transport paths (`Authorization: Basic`); `ghcr.io`, `maven.pkg.github.com`, `nuget.pkg.github.com` ([registry Basic](#registry-carriers)) | [GitHub REST authentication](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api), [RubyGems authentication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-rubygems-registry) |
| GitLab PAT | `glpat-` | `gitlab.com/api/v4` or exactly `/api/graphql` (`PRIVATE-TOKEN` or `Authorization: Bearer`; `Authorization: Basic` only on git transport paths) | [GitLab REST authentication](https://docs.gitlab.com/api/rest/authentication/); [GitLab GraphQL](https://docs.gitlab.com/api/graphql/getting_started/) |
| GitLab CI Job Token | `glcbt-` | `gitlab.com/api/v4` (`JOB-TOKEN` only) | [GitLab REST authentication](https://docs.gitlab.com/api/rest/authentication/) |
| Hugging Face Token | `hf_` + bounded alphanumeric suffix | `huggingface.co/api`, documented `huggingface.co/{repo}/resolve/{revision}/{filename}` downloads, or `router.huggingface.co/v1` (`Authorization: Bearer`) | [Hugging Face tokens](https://huggingface.co/docs/hub/security-tokens), [file download reference](https://huggingface.co/docs/huggingface_hub/en/package_reference/file_download) |
| Databricks Token | `dapi` + 32+ hex chars | No automatic audience; workspace-specific hosts require explicit operator policy | [Databricks PAT authentication](https://docs.databricks.com/aws/en/dev-tools/auth/pat) |
| Replicate API Token | `r8_` + 40 hex chars | `api.replicate.com/v1` (`Authorization: Bearer`) | [Replicate authentication](https://replicate.com/docs/topics/authentication); unverified binding carried from prior defaults |
| Together AI Key | `tok_` + 40+ lowercase alphanumeric chars | `api.together.ai/v1` or `api.together.xyz/v1` (`Authorization: Bearer`) | [Together quickstart](https://docs.together.ai/docs/quickstart), [publisher SDK default](https://github.com/togethercomputer/together-python/blob/807b79024fdcc4c3d37f49cc65b8d885322ae6b4/src/together/constants.py) |
| Pinecone API Key | `pcsk_` + 36+ alphanumeric chars | `api.pinecone.io` (`Api-Key`; root-level control-plane routes). Data-plane hosts require explicit operator policy | [Pinecone authentication](https://docs.pinecone.io/guides/get-started/authentication) |
| Groq API Key | `gsk_` + 48+ alphanumeric chars | `api.groq.com/openai/v1` (`Authorization: Bearer`) | [Groq API keys](https://console.groq.com/docs/api-keys) |
| Doppler Token | `dp.` + token kind (`ct`, `pt`, `sa`, `said`, `scim`, `audit` or `st`) + `.` + 40-44 alphanumeric chars; a service token may carry its config name first, as in `dp.st.<config>.` | `api.doppler.com/v3` (`Authorization: Bearer`) | [Doppler API reference](https://docs.doppler.com/reference/api), [token formats](https://docs.doppler.com/reference/auth-token-formats) |
| Amazon Bedrock Long-Term API Key | case-sensitive `ABSK` followed by the base64 of `BedrockAPIKey-`, then a base64 payload | No automatic audience; regional endpoints require explicit operator policy | [Securing Amazon Bedrock API keys](https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management/) |
| Amazon Bedrock Short-Term API Key | case-sensitive `bedrock-api-key-` followed by the fixed base64 preamble AWS publishes, then a base64 payload | No automatic audience; regional endpoints require explicit operator policy | [Securing Amazon Bedrock API keys](https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management/) |
| Heroku OAuth Token | case-sensitive `HRKU-` plus exactly 60 base64url characters (65 characters total). Heroku publishes no alphabet; the published 65-character example uses letters, digits, and an underscore. The UUID form shown on the same page is also matched | No automatic audience; both `api.heroku.com` and `id.heroku.com` are documented | [Heroku OAuth](https://devcenter.heroku.com/articles/oauth) |
| HashiCorp Vault Token | `hvs.` + 24+ alphanumeric chars, or case-sensitive `hvb.` + 24+ base64url chars | No automatic audience; Vault is self-hosted | [Vault token prefixes](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-prefixes) |
| xAI API Key | `xai-` + 80+ token chars | `api.x.ai/v1` (`Authorization: Bearer`) | [xAI API reference](https://docs.x.ai/docs/api-reference) |
| JWT Token | three base64url segments | `release-assets.githubusercontent.com` ([release grant in an HTTPS URL query](#download-grant-bounds)); `ghcr.io` ([registry JWT in HTTPS `Authorization: Bearer`](#registry-carriers)); JWT matches within a qualifying GitHub-token [registry Basic password](#registry-carriers), without JWT claim checks; `chatgpt.com/backend-api`, `api.x.ai/v1`, `cli-chat-proxy.grok.com/v1` ([sign-in JWT in HTTPS `Authorization: Bearer`](#sign-in-bearer-carriers)). Other carriers don't qualify | Release redirect shape observed locally; [registry token specification](https://distribution.github.io/distribution/spec/auth/jwt/) |
| Azure SAS Token | `sig=` + base64 HMAC-SHA256 | HTTPS URL query only: beside a qualifying release grant at `release-assets.githubusercontent.com`; attestation bundles at `tmaproduction.blob.core.windows.net` or `tmastaging.blob.core.windows.net` under `/attestations/`; Actions logs/artifacts at the exact `productionresultssa0` through `productionresultssa19`, `productionresultssa30` through `productionresultssa49`, and `productionresultssa100` through `productionresultssa199` accounts under `blob.core.windows.net`, beneath `/actions-results/`. [Download bounds](#download-grant-bounds) apply | [GitHub attestation bundle example](https://docs.github.com/en/rest/orgs/attestations); Actions results accounts from GitHub's meta API `domains.actions` |

Route prefixes match whole path segments. Escaped paths, repeated slashes, and `.` or `..` segments don't earn a provider API exception. Other vendor hosts and routes need explicit operator policy. This supported endpoint set is deliberately narrower than a vendor-wide domain wildcard. The endpoint rules and their vendor sources are in [`credential_endpoints.go`](../../internal/scanner/credential_endpoints.go).

Discord Gateway authentication requires a complete client text frame over `wss` to `gateway.discord.gg/`. Only the string value of `d.token` in opcode 2 (Identify) or 6 (Resume) qualifies. A token in any other field, including presence or activity text, remains blocked. Malformed JSON, duplicate keys, and non-string authentication tokens block. Binary, control, server, and incomplete cross-message payloads don't qualify. Existing WebSocket limits and redaction restrictions still apply; redaction mode rejects fragmented messages.

Hugging Face file downloads require a repository name or `namespace/name`, followed by `/resolve/{revision}/{filename}`; `datasets/`, `spaces/`, and `kernels/` repository prefixes also qualify. Subfolders can precede the filename. The allowance covers only Bearer authorization at `huggingface.co`, with the same path-normalization restrictions as other provider routes. It doesn't extend to CDN hosts or other fields.

`Hugging Face Token` and `Google OAuth Token` are outside the immutable core floor. For routes outside their compiled allowances, a scoped `suppress` entry naming the exact rule and HTTPS route can permit header/body findings. This includes Google Calendar, which is outside the compiled Gmail, Drive, and Storage routes. Such an exception also permits that rule's body findings on the selected route. A header/body suppression doesn't affect URL DLP. See [Adding a local provider shape](#adding-a-local-provider-shape) and the route-wide tradeoff below.

### Workspace and index hosts

Databricks PATs have no automatic audience. Pinecone's automatic audience covers only the control-plane host `api.pinecone.io`, using `Api-Key`. Workspace and index subdomains don't establish ownership of an account, so neither vendor's account-specific hosts inherit a wildcard allowance.

For an operator-owned workspace or index, an existing `suppress` entry can permit that non-core credential rule in request bodies and scanned headers at one exact HTTPS route. For example:

```yaml
suppress:
  - rule: Databricks Token
    path: https://workspace-a.cloud.databricks.com/api/2.0/clusters/list
    reason: operator-owned workspace API endpoint
  - rule: Pinecone API Key
    path: https://index-a.svc.us-east1-gcp.pinecone.io/query
    reason: operator-owned index query endpoint
```

Replace these example hosts with the exact hosts you operate. These entries match only their written routes; another host or path stays scanned. Suppression is route-wide for the named rule in bodies and scanned headers, so it permits more than a particular authentication header. It doesn't change URL DLP: a credential in a URL still blocks. Keep credentials in the vendor's documented header. `Api-Key` is in the default sensitive-header list; deployments with a custom `sensitive_headers` list must include it to scan Pinecone headers. See [Suppression](../guides/suppression.md) for matching semantics and auditing.

### Registry carriers

Registry Basic requires HTTPS and the exact `Authorization: Basic` carrier at `ghcr.io`, `maven.pkg.github.com`, or `nuget.pkg.github.com`. The decoded username must match `^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$` and must not itself match a registry token. The whole password must match the case-sensitive compiled registry password pattern: `gh[pour]_` plus at least 36 alphanumeric/underscore characters, `ghs_` plus at least 36 alphanumeric/dot/hyphen/underscore characters, or `github_pat_` plus at least 36 alphanumeric/underscore characters. GitHub documents username/password login for [containers](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry), [Maven](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry), and [NuGet](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-nuget-registry); qualifying for DLP filtering doesn't establish that a registry supports every token class.

The separate GHCR registry JWT rule requires HTTPS `Authorization: Bearer` at `ghcr.io`, an `aud` string or audience-array entry naming that host, and a nonempty `access` array. JWT matches within a qualifying GitHub-token Basic password use the whole-password rule above, without these JWT claim checks. RubyGems GitHub-token Bearer authentication uses the normal provider audience; RubyGems isn't a registry Basic audience. [GitHub's RubyGems documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-rubygems-registry) specifies a classic PAT for personal-token authentication; this DLP audience doesn't establish fine-grained PAT support. These filters don't authenticate a signature or prove who issued a token. The compiled host and carrier rules are defined in [`dlp_patterns.go`](../../internal/config/dlp_patterns.go) and [`credential_audience.go`](../../internal/scanner/credential_audience.go).

### Sign-in bearer carriers

Coding clients that sign in with OAuth send the access token, a JWT, as the `Authorization: Bearer` value to their vendor's own API. The `JWT Token` match is filtered only when the whole header is `Bearer` plus one token, over HTTPS, at one of these exact hosts and under its path, and the token's `iss` and `client_id` claims equal the listed values:

| Host | Path | `iss` | `client_id` | Source |
|---|---|---|---|---|
| `chatgpt.com` | `/backend-api/...` | `https://auth.openai.com` | `app_EMoamEEZ73f0CkXaXp7hrann` | [Codex CLI](https://github.com/openai/codex) `rust-v0.167.0`: `codex-rs/login/src/server.rs`, `codex-rs/login/src/auth/manager.rs`, `codex-rs/cloud-config/src/bundle_loader.rs` |
| `api.x.ai` | `/v1/...` | `https://auth.x.ai` | `b1a00492-073a-47ea-816f-4c329264a828` | [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) `v8.0.51`: `internal/auth/xai/types.go` |
| `cli-chat-proxy.grok.com` | `/v1/...` | `https://auth.x.ai` | `b1a00492-073a-47ea-816f-4c329264a828` | Same |

Pipelock can't verify the token's signature, so the claims are a routing check, not proof of origin. A JWT whose `iss` or `client_id` claim names another issuer or client stays blocked at these hosts. A token from another issuer that copies the listed claims passes this check, but it can reach only the listed host and path for those claims. Subdomains, other paths, escaped or dot path segments, cleartext, other headers, URL queries, and bodies don't qualify.

### Download grant bounds

Release query JWTs require the compiled header/claim shape, `iss=github.com`, the destination host in `aud`, and a positive `exp - nbf` span of at most 3600 seconds. This is Pipelock's local cap based on observed grants, not a provider maximum. Attestation bundle SAS requires one of the two exact table hosts, an unencoded, normalized path beneath `/attestations/`, read-only blob fields (`sp=r`, `sr=b`, `spr=https`), and each required signed field once in its documented format, including `st` and `se`. Its positive `se - st` span must be at most 24 hours. Both rules check the current time against the grant's validity window with Pipelock's 15-minute clock-skew tolerance.

The release SAS rule requires a qualifying co-located JWT and the complete user-delegation SAS shape; attestation SAS doesn't require a co-located JWT.

Actions SAS uses the same required signed fields and read-only blob checks as attestation SAS, with its exact compiled account list and a clean, unencoded log or artifact path under `/actions-results/`. Its positive `se - st` span must be at most 24 hours, the attestation bound. GitHub documents these download links as valid for one minute ([job logs](https://docs.github.com/en/rest/actions/workflow-jobs#download-job-logs-for-a-workflow-run), [artifacts](https://docs.github.com/en/rest/actions/artifacts#download-an-artifact)), but the SAS it signs runs from 5 seconds before issue to 10 minutes after, so a one-minute cap would refuse every live download. The existing current-window check and 15-minute clock-skew tolerance also apply to Actions SAS.

The `rscd` and `rsct` response overrides pass query entropy only in the recognized download shape. Pipelock doesn't verify JWT or SAS signatures or authenticate issuance. The allowance filters only qualifying matches and query-entropy values; other DLP matches, SSRF, and all other applicable checks still run.

These grants apply to fetch URLs and redirects, and HTTPS requests inspected inside a forward-proxy CONNECT tunnel with TLS interception. Cleartext HTTP, request bodies, headers, WebSocket frames, and destination-free MCP input don't earn the SAS query allowance. Encrypted CONNECT passthrough exposes no query to scan. Qualifying Actions results grants are structural exemptions and remain neutral to adaptive scoring. The predicates and local bounds live in [`credential_audience.go`](../../internal/scanner/credential_audience.go) and [`credential_audience_actions_results.go`](../../internal/scanner/credential_audience_actions_results.go).

## Intentionally Not Covered By Default

These providers are excluded until their public docs or secret-scanning partner
metadata exposes a distinctive, stable, low-FP key shape:

| Provider family | Reason |
|-----------------|--------|
| Bare `sk-` providers | A generic `sk-` token is indistinguishable from many unrelated provider keys and customer tokens. |
| Raw 32/40/64 hex providers | Collides with hashes, IDs, checksums, and trace/session values. |
| Cohere, Mistral, DeepSeek, Voyage, Hume, Vapi, Cerebras | Public docs describe bearer/API-key authentication but do not provide a shape that is safe enough for a default regex. |
| Baseten, Modal, Novita, DeepInfra, Hyperbolic, SambaNova, Nebius | No stable, provider-distinctive prefix was found in public docs during the 2026-06-20 review pass. |
| `sk_car_` / `jina_`-style providers | Key format is undisclosed in vendor docs and the prefix collides with common identifiers (`sk_car_` with car/cart snake_case; `jina_` with ordinary identifiers), so a default pattern would false-positive; add a custom pattern + exempt host if you use these. |

## Adding A Local Provider Shape

If your deployment knows a provider's internal key shape, add a custom pattern
with both controls:

```yaml
dlp:
  patterns:
    - name: "Internal Provider API Key"
      regex: '\bintprov_[A-Za-z0-9_-]{32,}\b'
      severity: critical
      exempt_domains:
        - "api.provider.example"

suppress:
  - rule: "Internal Provider API Key"
    path: "https://api.provider.example/*"
    reason: "provider-bound credential"
```

`exempt_domains` prevents URL DLP from blocking a custom key on the provider's own host. `suppress` covers request-body and request-header findings on the same provider route. The same key remains blocked on every other destination.

The compiled audience entries don't use suppressions. Immutable core DLP names cannot be suppressed. A core DLP name can still carry a compiled audience: `Slack Token` is allowed only in an `Authorization: Bearer` header at the Slack API endpoints in the table. `GitHub Token` and `GitHub Fine-Grained PAT` use only the hosts and header carriers in the table, including the [registry Basic constraints](#registry-carriers). `GitLab PAT` is allowed only on an encrypted `PRIVATE-TOKEN` or `Authorization: Bearer` header at `gitlab.com/api/v4` or exactly `gitlab.com/api/graphql`, or as `Authorization: Basic` on a git transport path there. A declared enterprise host also joins the git rule, so the confused-deputy residual for declared hosts covers git traffic too. No operator YAML can suppress those names, set them to warn, or add `exempt_domains`. `dlp.github_enterprise_hosts` and `dlp.gitlab_hosts` are the only way to name an enterprise or self-managed host, and a declared host the operator doesn't control receives the credential by design. `Google OAuth Token` is a built-in pattern outside the core floor; its compiled audience allows only a Bearer `Authorization` header at the exact Gmail, Drive, and Storage endpoints in the table.

## Provider-Opaque Fields

Some provider APIs legitimately carry long opaque identifiers or provider-bound
token-like values inside known JSON fields. Pipelock scans those fields with
their provider provenance intact: a match that is valid only inside that
provider-opaque field is capped at warn, while the same token shape in ordinary
content still blocks according to its severity. Malformed JSON, multiple JSON
roots, or a critical match outside the validated opaque field fail closed rather
than inheriting the downgrade.
