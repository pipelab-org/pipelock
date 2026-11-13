// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// audienceAPIEndpointAllowed narrows the compiled host/carrier metadata to
// documented API routes. A prefix ends on a path segment, not a string prefix.
// Escaped delimiters and non-normal paths never earn an endpoint exception.
func audienceAPIEndpointAllowed(candidate credentialAudienceCandidate, host, target, surface string) bool {
	switch candidate.patternName {
	case "Anthropic API Key", "OpenAI API Key", "OpenAI Service Key", "OpenAI Admin Key", "Fireworks API Key", "LLM Router API Key", "Groq API Key", "Doppler Token", "Heroku OAuth Token", "xAI API Key", "Replicate API Token", "Together AI Key", "Hugging Face Token", "Slack Token", "Slack App Token", "Slack Workflow Token", "Discord Bot Token", "Google API Key", "Answer Engine API Key", "Web Research API Key", "Pinecone API Key", "Google OAuth Token", "GitLab PAT", "GitLab CI Job Token", "GitHub Token", "GitHub Fine-Grained PAT":
	default:
		return true
	}
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if strings.ContainsAny(path, "%\\") || strings.Contains(path, "//") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	under := func(prefix string) bool { return path == prefix || strings.HasPrefix(path, prefix+"/") }
	switch candidate.patternName {
	case "Google OAuth Token":
		// Root hosts, resource paths, and media-upload prefixes are published in:
		// https://www.googleapis.com/discovery/v1/apis/gmail/v1/rest
		// https://www.googleapis.com/discovery/v1/apis/drive/v3/rest
		// https://www.googleapis.com/discovery/v1/apis/storage/v1/rest
		var prefix string
		switch host {
		case "gmail.googleapis.com":
			prefix = "/gmail/v1"
		case "www.googleapis.com":
			prefix = "/drive/v3"
		case "storage.googleapis.com":
			prefix = "/storage/v1"
		default:
			return false
		}
		return under(prefix) || under("/upload"+prefix) || under("/resumable/upload"+prefix)
	case "GitLab PAT", "GitLab CI Job Token":
		// https://docs.gitlab.com/api/rest/ (the public REST root is /api/v4).
		// https://docs.gitlab.com/api/graphql/getting_started/ (access token,
		// Authorization: Bearer, exactly /api/graphql). Job tokens stay REST-only.
		// Explicit operator declarations retain the instance's own API root.
		return host != "gitlab.com" || under("/api/v4") ||
			(candidate.patternName == "GitLab PAT" && path == "/api/graphql")
	case "GitHub Token", "GitHub Fine-Grained PAT":
		// https://docs.github.com/en/rest/releases/assets (upload host, /repos).
		// The REST and RubyGems hosts expose their APIs at the root.
		return host != "uploads.github.com" || under("/repos")
	case "Anthropic API Key":
		// https://platform.claude.com/docs/en/api/overview (x-api-key, /v1).
		// https://docs.claude.com/en/api/openai-sdk (OpenAI SDK Bearer, /v1).
		// Claude Code 2.1.310 publishes additional first-party carriers.
		// Exact paths and producer offsets: docs/security/claude-code-credentials.md.
		if host == "platform.claude.com" {
			return surface == credentialAudienceAnthropicOAuthSurface &&
				(path == "/v1/oauth/token" || path == "/v1/oauth/token/revoke")
		}
		if host == "mcp-proxy.anthropic.com" {
			id, found := strings.CutPrefix(path, "/v1/mcp/")
			return surface == CredentialAudienceAuthorizationHeaderSurface &&
				found && id != "" && !strings.Contains(id, "/")
		}
		if host != "api.anthropic.com" {
			return false
		}
		switch path {
		case "/api/oauth/profile", "/api/oauth/validate",
			"/api/oauth/claude_cli/roles", "/api/oauth/claude_cli/create_api_key":
			return surface == CredentialAudienceAuthorizationHeaderSurface
		case "/api/claude_cli_profile":
			return surface == credentialAudienceXKeySurface
		case "/api/claude_code/settings", "/api/claude_code/policy_limits",
			"/api/claude_code/metrics", "/api/claude_code/organizations/metrics_enabled",
			"/api/event_logging/v2/batch":
			return surface == CredentialAudienceAuthorizationHeaderSurface || surface == credentialAudienceXKeySurface
		default:
			return surface != credentialAudienceAnthropicOAuthSurface && under("/v1")
		}
	case "OpenAI API Key", "OpenAI Service Key", "OpenAI Admin Key":
		// https://developers.openai.com/api/reference/overview (Bearer, /v1).
		return under("/v1")
	case "Fireworks API Key":
		// https://docs.fireworks.ai/api-reference/introduction
		// Inference uses /inference/v1; the management API uses /v1.
		return under("/inference/v1") || under("/v1")
	case "LLM Router API Key":
		// https://openrouter.ai/docs/api/reference/overview (Bearer, /api/v1).
		return under("/api/v1")
	case "Groq API Key":
		// https://console.groq.com/docs/overview (Bearer, /openai/v1).
		return under("/openai/v1")
	case "Doppler Token":
		// https://docs.doppler.com/reference/api (Bearer, /v3).
		return under("/v3")
	case "Heroku OAuth Token":
		// https://devcenter.heroku.com/articles/platform-api-reference
		// Clients address api.heroku.com over HTTPS. Version 3 is an Accept
		// header, not a path prefix, so a normal path on that host is the API.
		return true
	case "xAI API Key", "Replicate API Token", "Together AI Key":
		// https://docs.x.ai/docs/api-reference
		// https://replicate.com/docs/reference/http
		// https://docs.together.ai/docs/quickstart
		return under("/v1")
	case "Hugging Face Token":
		// https://huggingface.co/docs/hub/api (Bearer, /api).
		// https://huggingface.co/docs/api-inference/quicktour (router, /v1).
		if host == "huggingface.co" {
			return under("/api") || huggingFaceDownloadPathAllowed(path)
		}
		return host == "router.huggingface.co" && under("/v1")
	case "Slack Token", "Slack App Token", "Slack Workflow Token":
		// https://docs.slack.dev/apis/web-api/ (Authorization Bearer, /api).
		// https://docs.slack.dev/ai/slack-mcp-server/ (Bearer, /mcp).
		if host == "mcp.slack.com" {
			return path == "/mcp"
		}
		return under("/api")
	case "Discord Bot Token":
		// https://docs.discord.com/developers/reference (Authorization Bot, /api).
		// https://docs.discord.com/developers/events/gateway documents the WSS
		// host; gateway-events documents d.token in Identify and Resume.
		if host == "gateway.discord.gg" {
			return surface == credentialAudienceDiscordGatewaySurface && u.Scheme == "wss" && path == "/"
		}
		return host == "discord.com" && surface != credentialAudienceDiscordGatewaySurface && under("/api")
	case "Google API Key":
		// https://cloud.google.com/docs/authentication/api-keys-use
		// https://ai.google.dev/gemini-api/docs/api-key
		// https://developers.google.com/maps/documentation/javascript/get-api-key
		if surface == credentialAudienceURLQuerySurface {
			q, err := url.ParseQuery(u.RawQuery)
			if err != nil || len(q["key"]) != 1 {
				return false
			}
		}
		switch host {
		case "maps.googleapis.com":
			return surface == credentialAudienceURLQuerySurface && under("/maps/api")
		case "generativelanguage.googleapis.com":
			return under("/v1") || under("/v1beta")
		case "language.googleapis.com":
			return under("/v1")
		case "translation.googleapis.com":
			return under("/language/translate/v2")
		default:
			return false
		}
	case "Answer Engine API Key", "Web Research API Key", "Pinecone API Key":
		// These APIs publish root-level routes without one shared path prefix:
		// https://docs.perplexity.ai/docs/getting-started/quickstart (Bearer)
		// https://docs.tavily.com/documentation/quickstart (Bearer)
		// https://docs.pinecone.io/reference/api/authentication (Api-Key)
		return true
	default:
		// Existing Git/registry/download predicates and programmatic custom rules
		// keep their own compiled contracts. YAML cannot supply this metadata.
		return true
	}
}

// apiKeyQueryAllowed allows exactly one whole key in its documented parameter.
// A match in any other query key or value keeps URL DLP enforcement. The caller
// separately proves that the query-less URL contains no credential matches.
func apiKeyQueryAllowed(p *compiledPattern, u *url.URL) bool {
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q["key"]) != 1 {
		return false
	}
	value := q.Get("key")
	start, end, ok := p.matchSpan(value)
	if !ok || start != 0 || end != len(value) {
		return false
	}
	for key, values := range q {
		if p.matches(IterativeDecode(key)) {
			return false
		}
		if key == "key" {
			continue
		}
		for _, value := range values {
			if p.matches(IterativeDecode(value)) {
				return false
			}
		}
	}
	return p.credentialAudienceCarrierMask&config.CredentialAudienceCarrierAPIKeyQuery != 0
}

// huggingFaceDownloadPathAllowed follows hf_hub_url's published file route:
// https://huggingface.co/docs/huggingface_hub/en/package_reference/file_download
// That page documents authentication tokens for download and metadata calls.
// The publisher client defines optional namespaces and repository-type prefixes:
// https://github.com/huggingface/huggingface_hub/blob/main/src/huggingface_hub/utils/_validators.py
// https://github.com/huggingface/huggingface_hub/blob/main/src/huggingface_hub/constants.py
// The caller already rejected escaped, empty interior and non-normal segments.
func huggingFaceDownloadPathAllowed(path string) bool {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	switch segments[0] {
	case "datasets", "spaces", "kernels":
		segments = segments[1:]
	}
	// repo_id is either a repository name or namespace/name. Both revision
	// and filename must follow resolve; subfolders belong to the filename.
	for _, resolveIndex := range []int{1, 2} {
		if len(segments) >= resolveIndex+3 && segments[resolveIndex] == "resolve" && segments[len(segments)-1] != "" {
			return true
		}
	}
	return false
}
