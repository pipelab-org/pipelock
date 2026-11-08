// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestAnthropicClientHeaderEndpoints(t *testing.T) {
	s := MustNew(credentialAudienceEntropyConfig())
	defer s.Close()
	key := "sk-" + "ant-oat01-" + strings.Repeat("a", 32)
	for _, tc := range []struct{ host, path, header string }{
		{"api.anthropic.com", "/api/oauth/profile", "Authorization"},
		{"api.anthropic.com", "/api/oauth/validate", "Authorization"},
		{"api.anthropic.com", "/api/oauth/claude_cli/roles", "Authorization"},
		{"api.anthropic.com", "/api/oauth/claude_cli/create_api_key", "Authorization"},
		{"api.anthropic.com", "/api/claude_cli_profile", "X-Api-Key"},
		{"api.anthropic.com", "/api/claude_code/settings", "Authorization"},
		{"api.anthropic.com", "/api/claude_code/policy_limits", "Authorization"},
		{"api.anthropic.com", "/api/claude_code/metrics", "Authorization"},
		{"api.anthropic.com", "/api/claude_code/organizations/metrics_enabled", "Authorization"},
		{"api.anthropic.com", "/api/event_logging/v2/batch", "Authorization"},
		{"mcp-proxy.anthropic.com", "/v1/mcp/server-id", "Authorization"},
	} {
		t.Run(tc.host+tc.path, func(t *testing.T) {
			target := "https://" + tc.host + tc.path
			value := key
			if tc.header == "Authorization" {
				value = "Bearer " + key
			}
			matches := s.ScanTextForDLP(t.Context(), value).Matches
			if len(matches) == 0 {
				t.Fatal("fixture did not match")
			}
			kept, allows := s.FilterHeaderDLPMatches(matches, target, tc.header, value)
			if len(kept) != 0 || len(allows) != 1 {
				t.Fatalf("header kept=%v allows=%v", kept, allows)
			}
			for _, bad := range []string{
				target + "/extra", target + "/", strings.Replace(target, "https:", "http:", 1),
				strings.Replace(target, tc.host, tc.host+".vendor.example", 1),
				strings.Replace(target, tc.path, "/unrelated", 1),
				strings.Replace(target, tc.path, strings.Replace(tc.path, "/api/", "/api%2f", 1), 1) + "/..",
			} {
				if got, _ := s.FilterHeaderDLPMatches(matches, bad, tc.header, value); len(got) == 0 {
					t.Fatalf("allowed %s", bad)
				}
			}
			for _, carrier := range []string{"X-Other", "Cookie"} {
				if got, _ := s.FilterHeaderDLPMatches(matches, target, carrier, value); len(got) == 0 {
					t.Fatal("wrong header allowed")
				}
			}
			if got, _ := s.FilterTextDLPMatchesForDestination(matches, target, "body"); len(got) == 0 {
				t.Fatal("body allowed")
			}
			for _, u := range []string{target + "?value=" + key, target + "/" + key} {
				if result := s.Scan(t.Context(), u); result.Allowed {
					t.Fatal("URL credential allowed")
				}
			}
		})
	}
	for _, path := range []string{"/api/claude_code/settings", "/api/claude_code/policy_limits", "/api/claude_code/metrics", "/api/claude_code/organizations/metrics_enabled", "/api/event_logging/v2/batch"} {
		matches := s.ScanTextForDLP(t.Context(), key).Matches
		if got, _ := s.FilterHeaderDLPMatches(matches, "https://api.anthropic.com"+path, "X-Api-Key", key); len(got) != 0 {
			t.Fatalf("API key blocked at %s", path)
		}
	}
}

func TestAnthropicOAuthCarrierQualification(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	key := "sk-" + "ant-ort01-" + strings.Repeat("a", 32)
	tokenBody := func(token, extra string) []byte {
		return []byte(fmt.Sprintf("{\"grant_type\":\"refresh_token\",\"refresh_token\":%q%s}", token, extra))
	}
	body := tokenBody(key, "")
	const target = "https://platform.claude.com/v1/oauth/token"
	for _, tc := range []struct {
		name, target, method, media string
		body                        []byte
		cancel, allow               bool
	}{
		{name: "refresh", allow: true},
		{name: "revocation", target: target + "/revoke", body: []byte(fmt.Sprintf("{\"token_type_hint\":\"refresh_token\",\"token\":%q}", key)), allow: true},
		{name: "media trailing separator", media: "application/json;", allow: true},
		{name: "non POST", method: http.MethodGet},
		{name: "wrong media", media: "text/plain"},
		{name: "malformed media", media: "application/json;broken"},
		{name: "cancelled context", cancel: true},
		{name: "bad URL", target: "://"},
		{name: "HTTP", target: "http://platform.claude.com/v1/oauth/token"},
		{name: "WebSocket", target: "wss://platform.claude.com/v1/oauth/token"},
		{name: "query", target: target + "?extra=1"},
		{name: "empty query", target: target + "?"},
		{name: "fragment", target: target + "#fragment"},
		{name: "wrong host", target: "https://api.vendor.example/v1/oauth/token"},
		{name: "unknown path", target: target + "/extra"},
		{name: "escaped path", target: "https://platform.claude.com/v1/oauth%2ftoken"},
		{name: "invalid JSON", body: append(append([]byte(nil), body...), '{')},
		{name: "duplicate JSON key", body: tokenBody(key, ",\"refresh_token\":\"ordinary\"")},
		{name: "escaped duplicate JSON key", body: tokenBody(key, ",\"refresh_\\u0074oken\":\"ordinary\"")},
		{name: "nested duplicate JSON key", body: tokenBody(key, ",\"extra\":{\"x\":1,\"x\":2}")},
		{name: "array", body: []byte("[]")},
		{name: "null", body: []byte("null")},
		{name: "empty object", body: []byte("{}")},
		{name: "wrong discriminator", body: []byte(strings.Replace(string(body), "\"grant_type\":\"refresh_token\"", "\"grant_type\":\"authorization_code\"", 1))},
		{name: "discriminator type", body: []byte(strings.Replace(string(body), "\"grant_type\":\"refresh_token\"", "\"grant_type\":true", 1))},
		{name: "empty credential", body: tokenBody("", "")},
		{name: "credential type", body: []byte("{\"grant_type\":\"refresh_token\",\"refresh_token\":[]}")},
		{name: "nonmatching credential", body: tokenBody("ordinary", "")},
		{name: "credential prefix", body: tokenBody("prefix "+key, "")},
		{name: "credential suffix", body: tokenBody(key+" suffix", "")},
		{name: "credential in remainder", body: tokenBody(key, fmt.Sprintf(",\"extra\":%q", key))},
		{name: "encoded credential in remainder", body: tokenBody(key, fmt.Sprintf(",\"extra\":%q", base64.StdEncoding.EncodeToString([]byte(key))))},
		{name: "split credential in remainder", body: tokenBody(key, fmt.Sprintf(",\"extra\":[%q,%q]", key[:12], key[12:]))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest, method, media := tc.target, tc.method, tc.media
			if dest == "" {
				dest = target
			}
			if method == "" {
				method = http.MethodPost
			}
			if media == "" {
				media = "application/json"
			}
			input := tc.body
			if input == nil {
				input = body
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			got := s.OAuthCredentialAudienceSurface(ctx, input, dest, method, media)
			want := "body"
			if tc.allow {
				want = credentialAudienceAnthropicOAuthSurface
			}
			if got != want {
				t.Fatalf("surface=%s want=%s", got, want)
			}
			// A rejected carrier must retain ordinary body DLP for the token.
			matches := s.ScanTextForDLP(t.Context(), key).Matches
			if len(matches) == 0 {
				t.Fatal("credential fixture did not match")
			}
			kept, allows := s.FilterTextDLPMatchesForDestination(matches, dest, got)
			if tc.allow {
				if len(kept) != 0 || len(allows) != 1 {
					t.Fatalf("qualified carrier kept=%v allows=%v", kept, allows)
				}
			} else if len(kept) == 0 || len(allows) != 0 {
				t.Fatalf("fallback dropped credential: kept=%v allows=%v", kept, allows)
			}
		})
	}
	matches := s.ScanTextForDLP(t.Context(), key).Matches
	for _, target := range []string{"https://platform.claude.com/v1/messages", "https://mcp-proxy.anthropic.com/v1/messages", "https://api.anthropic.com/v1/oauth/token"} {
		if got, _ := s.FilterTextDLPMatchesForDestination(matches, target, credentialAudienceAnthropicOAuthSurface); len(got) == 0 {
			t.Fatal("OAuth body on wrong endpoint")
		}
	}
}

func TestAnthropicCredentialAudienceEndpointHosts(t *testing.T) {
	candidate := credentialAudienceCandidate{patternName: "Anthropic API Key"}
	for _, tc := range []struct {
		host, path, surface string
		allow               bool
	}{
		{"api.anthropic.com", "/v1/messages", CredentialAudienceAuthorizationHeaderSurface, true},
		{"platform.claude.com", "/v1/oauth/token", credentialAudienceAnthropicOAuthSurface, true},
		{"mcp-proxy.anthropic.com", "/v1/mcp/server-id", CredentialAudienceAuthorizationHeaderSurface, true},
		{"api.vendor.example", "/v1/messages", CredentialAudienceAuthorizationHeaderSurface, false},
		{"api.anthropic.com.vendor.example", "/v1/messages", CredentialAudienceAuthorizationHeaderSurface, false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			if got := audienceAPIEndpointAllowed(candidate, tc.host, "https://"+tc.host+tc.path, tc.surface); got != tc.allow {
				t.Fatalf("endpoint allowed=%t want=%t", got, tc.allow)
			}
		})
	}
}

func TestAnthropicOAuthRequiresCompiledPattern(t *testing.T) {
	body := []byte(`{"grant_type":"refresh_token","refresh_token":"` + "sk-" + "ant-" + strings.Repeat("a", 32) + `"}`)
	const target = "https://platform.claude.com/v1/oauth/token"
	for _, tc := range []struct {
		name     string
		patterns []config.DLPPattern
	}{
		{name: "no patterns"},
		{name: "unrelated pattern", patterns: []config.DLPPattern{{Name: "Other credential", Regex: "ordinary", Severity: config.SeverityHigh}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := credentialAudienceEntropyConfig()
			cfg.DLP.Patterns = tc.patterns
			s := MustNew(cfg)
			t.Cleanup(s.Close)
			if got := s.OAuthCredentialAudienceSurface(t.Context(), body, target, http.MethodPost, "application/json"); got != "body" {
				t.Fatal("missing configured pattern qualified")
			}
		})
	}
	s := MustNew(credentialAudienceEntropyConfig())
	defer s.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := s.OAuthCredentialAudienceSurface(ctx, body, target, http.MethodPost, "application/json"); got != "body" {
		t.Fatal("canceled scan qualified")
	}
	for _, p := range s.dlpPatterns {
		if p.name == "Anthropic API Key" {
			p.credentialAudienceHosts = nil
		}
	}
	if got := s.OAuthCredentialAudienceSurface(t.Context(), body, target, http.MethodPost, "application/json"); got != "body" {
		t.Fatal("missing compiled metadata qualified")
	}
}

func TestAnthropicClientWrongHeaderCarrier(t *testing.T) {
	s := MustNew(credentialAudienceEntropyConfig())
	defer s.Close()
	key := "sk-" + "ant-" + strings.Repeat("a", 32)
	for _, tc := range []struct{ target, header, value string }{
		{"https://platform.claude.com/v1/oauth/token", "Authorization", "Bearer " + key},
		{"https://platform.claude.com/v1/oauth/token/revoke", "X-Api-Key", key},
		{"https://mcp-proxy.anthropic.com/v1/mcp/server-id", "X-Api-Key", key},
		{"https://api.anthropic.com/api/claude_cli_profile", "Authorization", "Bearer " + key},
		{"https://api.anthropic.com/api/oauth/profile", "X-Api-Key", key},
	} {
		matches := s.ScanTextForDLP(t.Context(), tc.value).Matches
		if len(matches) == 0 {
			t.Fatal("fixture did not match")
		}
		if got, _ := s.FilterHeaderDLPMatches(matches, tc.target, tc.header, tc.value); len(got) == 0 {
			t.Fatalf("wrong carrier allowed at %s", tc.target)
		}
	}
}
