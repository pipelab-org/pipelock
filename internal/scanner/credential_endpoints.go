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
	case "Anthropic API Key", "OpenAI API Key", "OpenAI Service Key", "Fireworks API Key", "LLM Router API Key", "Groq API Key", "xAI API Key", "Replicate API Token", "Together AI Key", "Hugging Face Token", "Slack Token", "Slack App Token", "Discord Bot Token", "Google API Key", "Answer Engine API Key", "Web Research API Key", "Pinecone API Key", "Google OAuth Token", "GitLab PAT", "GitLab CI Job Token", "GitHub Token", "GitHub Fine-Grained PAT":
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
		// Explicit operator declarations retain the instance's own API root.
		return host != "gitlab.com" || under("/api/v4")
	case "GitHub Token", "GitHub Fine-Grained PAT":
		// https://docs.github.com/en/rest/releases/assets (upload host, /repos).
		// The REST and RubyGems hosts expose their APIs at the root.
		return host != "uploads.github.com" || under("/repos")
	case "Anthropic API Key":
		// https://platform.claude.com/docs/en/api/overview (x-api-key, /v1).
		return under("/v1")
	case "OpenAI API Key", "OpenAI Service Key":
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
	case "xAI API Key", "Replicate API Token", "Together AI Key":
		// https://docs.x.ai/docs/api-reference
		// https://replicate.com/docs/reference/http
		// https://docs.together.ai/docs/quickstart
		return under("/v1")
	case "Hugging Face Token":
		// https://huggingface.co/docs/hub/api (Bearer, /api).
		// https://huggingface.co/docs/api-inference/quicktour (router, /v1).
		if host == "huggingface.co" {
			return under("/api")
		}
		return host == "router.huggingface.co" && under("/v1")
	case "Slack Token", "Slack App Token":
		// https://docs.slack.dev/apis/web-api/ (Authorization Bearer, /api).
		// https://docs.slack.dev/ai/slack-mcp-server/ (Bearer, /mcp).
		if host == "mcp.slack.com" {
			return path == "/mcp"
		}
		return under("/api")
	case "Discord Bot Token":
		// https://docs.discord.com/developers/reference (Authorization Bot, /api).
		// Gateway Identify carries a token inside JSON, not an HTTP auth header,
		// and is not a credential-audience exception.
		return under("/api")
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
