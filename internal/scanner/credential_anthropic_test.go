// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/http"
	"strings"
	"testing"
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
	s := MustNew(credentialAudienceEntropyConfig())
	defer s.Close()
	key := "sk-" + "ant-ort01-" + strings.Repeat("a", 32)
	body := []byte(`{"grant_type":"refresh_token","refresh_token":"` + key + `","client_id":"client","scope":"user:profile"}`)
	const target = "https://platform.claude.com/v1/oauth/token"
	for _, tc := range []struct {
		target, method, media string
		body                  []byte
		allow                 bool
	}{
		{target, http.MethodPost, "application/json", body, true},
		{target, http.MethodGet, "application/json", body, false},
		{target, http.MethodPost, "text/plain", body, false},
		{target + "?extra=1", http.MethodPost, "application/json", body, false},
		{target + "?", http.MethodPost, "application/json", body, false},
		{target + "#fragment", http.MethodPost, "application/json", body, false},
		{"wss://platform.claude.com/v1/oauth/token", http.MethodPost, "application/json", body, false},
		{target, http.MethodPost, "application/json", []byte(`null`), false},
		{target, http.MethodPost, "application/json", []byte(`{}`), false},
		{target, http.MethodPost, "application/json", []byte(`{"grant_type":"refresh_token","refresh_token":""}`), false},
		{target, http.MethodPost, "application/json", []byte(`{"grant_type":"refresh_token","refresh_token":"ordinary"}`), false},
		{"://", http.MethodPost, "application/json", body, false},
		{target, http.MethodPost, "application/json;", body, true},
		{target, http.MethodPost, "application/json;broken", body, false},
	} {
		if got := s.OAuthCredentialAudienceSurface(t.Context(), tc.body, tc.target, tc.method, tc.media); (got == credentialAudienceAnthropicOAuthSurface) != tc.allow {
			t.Fatalf("%+v surface=%s", tc, got)
		}
	}
	matches := s.ScanTextForDLP(t.Context(), key).Matches
	for _, target := range []string{"https://platform.claude.com/v1/messages", "https://mcp-proxy.anthropic.com/v1/messages", "https://api.anthropic.com/v1/oauth/token"} {
		if got, _ := s.FilterTextDLPMatchesForDestination(matches, target, credentialAudienceAnthropicOAuthSurface); len(got) == 0 {
			t.Fatal("OAuth body on wrong endpoint")
		}
	}
}

func TestAnthropicOAuthRequiresCompiledPattern(t *testing.T) {
	cfg := credentialAudienceEntropyConfig()
	cfg.DLP.Patterns = nil
	s := MustNew(cfg)
	defer s.Close()
	body := []byte(`{"grant_type":"refresh_token","refresh_token":"` + "sk-" + "ant-" + strings.Repeat("a", 32) + `"}`)
	const target = "https://platform.claude.com/v1/oauth/token"
	if got := s.OAuthCredentialAudienceSurface(t.Context(), body, target, http.MethodPost, "application/json"); got != "body" {
		t.Fatal("missing configured pattern qualified")
	}
	s = MustNew(credentialAudienceEntropyConfig())
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
