// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSignInBearerAudience(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	codex := registryJWT(t, map[string]any{
		"iss": "https://auth.openai.com", "aud": []string{"https://api.openai.com/v1"},
		"client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
	})
	xai := registryJWT(t, map[string]any{
		"iss": "https://auth.x.ai", "aud": "b1a00492-073a-47ea-816f-4c329264a828",
		"client_id": "b1a00492-073a-47ea-816f-4c329264a828",
	})
	otherClient := registryJWT(t, map[string]any{"iss": "https://auth.openai.com", "client_id": "app_other"})
	otherIssuer := registryJWT(t, map[string]any{"iss": "https://auth.vendor.example", "client_id": "app_EMoamEEZ73f0CkXaXp7hrann"})
	noClient := registryJWT(t, map[string]any{"iss": "https://auth.openai.com"})
	issArray := registryJWT(t, map[string]any{"iss": []string{"https://auth.openai.com"}, "client_id": "app_EMoamEEZ73f0CkXaXp7hrann"})
	registry := registryJWT(t, map[string]any{"aud": "ghcr.io", "access": []any{map[string]any{"type": "repository"}}})
	dupIss := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://auth.vendor.example","iss":"https://auth.openai.com","client_id":"app_EMoamEEZ73f0CkXaXp7hrann"}`)) +
		"." + strings.Repeat("a", 16)

	cases := []struct {
		name, token, header, value, target string
		allow                              bool
		host                               string
	}{
		{"codex responses", codex, "Authorization", "Bearer " + codex, "https://chatgpt.com/backend-api/codex/responses", true, "chatgpt.com"},
		{"codex wham", codex, "Authorization", "Bearer " + codex, "https://chatgpt.com/backend-api/wham/accounts/check", true, "chatgpt.com"},
		{"codex host case and dot", codex, "Authorization", "Bearer " + codex, "https://ChatGPT.com./backend-api/codex/models", true, "chatgpt.com"},
		{"xai chat proxy", xai, "Authorization", "Bearer " + xai, "https://cli-chat-proxy.grok.com/v1/chat/completions", true, "cli-chat-proxy.grok.com"},
		{"xai api", xai, "Authorization", "Bearer " + xai, "https://api.x.ai/v1/responses", true, "api.x.ai"},
		{"codex token at xai blocked", codex, "Authorization", "Bearer " + codex, "https://api.x.ai/v1/responses", false, ""},
		{"xai token at chatgpt blocked", xai, "Authorization", "Bearer " + xai, "https://chatgpt.com/backend-api/codex/responses", false, ""},
		{"other client blocked", otherClient, "Authorization", "Bearer " + otherClient, "https://chatgpt.com/backend-api/codex/responses", false, ""},
		{"other issuer blocked", otherIssuer, "Authorization", "Bearer " + otherIssuer, "https://chatgpt.com/backend-api/codex/responses", false, ""},
		{"missing client_id blocked", noClient, "Authorization", "Bearer " + noClient, "https://chatgpt.com/backend-api/codex/responses", false, ""},
		{"iss array blocked", issArray, "Authorization", "Bearer " + issArray, "https://chatgpt.com/backend-api/codex/responses", false, ""},
		{"duplicate iss blocked", dupIss, "Authorization", "Bearer " + dupIss, "https://chatgpt.com/backend-api/codex/responses", false, ""},
		{"registry jwt at chatgpt blocked", registry, "Authorization", "Bearer " + registry, "https://chatgpt.com/backend-api/codex/responses", false, ""},
		{"path outside prefix blocked", codex, "Authorization", "Bearer " + codex, "https://chatgpt.com/", false, ""},
		{"prefix without segment blocked", codex, "Authorization", "Bearer " + codex, "https://chatgpt.com/backend-api", false, ""},
		{"string prefix blocked", codex, "Authorization", "Bearer " + codex, "https://chatgpt.com/backend-apix/codex", false, ""},
		{"dot segment blocked", codex, "Authorization", "Bearer " + codex, "https://chatgpt.com/backend-api/../upload", false, ""},
		{"escaped path blocked", codex, "Authorization", "Bearer " + codex, "https://chatgpt.com/backend-api/%2e%2e/upload", false, ""},
		{"double slash blocked", codex, "Authorization", "Bearer " + codex, "https://chatgpt.com/backend-api//codex", false, ""},
		{"subdomain blocked", codex, "Authorization", "Bearer " + codex, "https://evil.chatgpt.com/backend-api/codex", false, ""},
		{"lookalike blocked", codex, "Authorization", "Bearer " + codex, "https://chatgpt.com.evil.example/backend-api/codex", false, ""},
		{"other host blocked", codex, "Authorization", "Bearer " + codex, "https://api.vendor.example/backend-api/codex", false, ""},
		{"cleartext blocked", codex, "Authorization", "Bearer " + codex, "http://chatgpt.com/backend-api/codex/responses", false, ""},
		{"basic scheme blocked", codex, "Authorization", "Basic " + codex, "https://chatgpt.com/backend-api/codex/responses", false, ""},
		{"extra field blocked", codex, "Authorization", "Bearer " + codex + " extra", "https://chatgpt.com/backend-api/codex/responses", false, ""},
		{"other header blocked", codex, "X-Api-Key", codex, "https://chatgpt.com/backend-api/codex/responses", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			matches := s.ScanTextForDLP(context.Background(), tc.token).Matches
			if !matchRetained(matches, "JWT Token") {
				t.Fatalf("fixture did not match the JWT pattern")
			}
			retained, allows := s.FilterHeaderDLPMatches(matches, tc.target, tc.header, tc.value)
			if tc.allow {
				if matchRetained(retained, "JWT Token") || !audienceAllowFor(allows, "JWT Token") {
					t.Fatalf("retained=%v allows=%#v", matchRetained(retained, "JWT Token"), allows)
				}
				if allows[0].Destination != tc.host || allows[0].Surface != "header" {
					t.Fatalf("allow record = %#v", allows[0])
				}
				return
			}
			if !matchRetained(retained, "JWT Token") || audienceAllowFor(allows, "JWT Token") {
				t.Fatalf("JWT allowed: retained=%v allows=%#v", matchRetained(retained, "JWT Token"), allows)
			}
		})
	}
}

// The route is earned only by the JWT pattern; another pattern's match in the
// same Authorization value gets nothing from it.
func TestSignInBearerAllowedOnlyForJWTPattern(t *testing.T) {
	t.Parallel()
	codex := registryJWT(t, map[string]any{"iss": "https://auth.openai.com", "client_id": "app_EMoamEEZ73f0CkXaXp7hrann"})
	c := credentialAudienceCandidate{patternName: "OpenAI API Key", headerValue: "Bearer " + codex}
	if signInBearerAllowed(c, "chatgpt.com", "https://chatgpt.com/backend-api/codex", CredentialAudienceAuthorizationHeaderSurface) {
		t.Fatal("non-JWT pattern earned the sign-in route")
	}
	c.patternName = "JWT Token"
	if signInBearerAllowed(c, "chatgpt.com", "https://chatgpt.com/backend-api/codex", credentialAudienceURLQuerySurface) {
		t.Fatal("URL query surface earned the sign-in route")
	}
	if !signInBearerAllowed(c, "chatgpt.com", "https://chatgpt.com/backend-api/codex", CredentialAudienceAuthorizationHeaderSurface) {
		t.Fatal("valid route refused")
	}
	if signInBearerAllowed(c, "chatgpt.com", "://bad", CredentialAudienceAuthorizationHeaderSurface) {
		t.Fatal("unparseable target allowed")
	}
	c.headerValue = "Bearer not.a-jwt"
	if signInBearerAllowed(c, "chatgpt.com", "https://chatgpt.com/backend-api/codex", CredentialAudienceAuthorizationHeaderSurface) {
		t.Fatal("malformed token allowed")
	}
	c.headerValue = "Bearer a.%%%.b"
	if signInBearerAllowed(c, "chatgpt.com", "https://chatgpt.com/backend-api/codex", CredentialAudienceAuthorizationHeaderSurface) {
		t.Fatal("undecodable payload allowed")
	}
}

// signInBearerAllowed decides the scheme and header shape itself, so a caller
// that reaches it with a wss target or a malformed header value is refused here
// and not only by the callers' own checks.
func TestSignInBearerAllowedSchemeAndHeaderShape(t *testing.T) {
	t.Parallel()
	codex := registryJWT(t, map[string]any{"iss": "https://auth.openai.com", "client_id": "app_EMoamEEZ73f0CkXaXp7hrann"})
	const surface = CredentialAudienceAuthorizationHeaderSurface
	for _, tc := range []struct {
		name, target, value string
		allow               bool
	}{
		{"https bearer", "https://chatgpt.com/backend-api/codex", "Bearer " + codex, true},
		{"wss target", "wss://chatgpt.com/backend-api/codex", "Bearer " + codex, false},
		{"http target", "http://chatgpt.com/backend-api/codex", "Bearer " + codex, false},
		{"basic scheme", "https://chatgpt.com/backend-api/codex", "Basic " + codex, false},
		{"extra field", "https://chatgpt.com/backend-api/codex", "Bearer " + codex + " extra", false},
		{"bare token", "https://chatgpt.com/backend-api/codex", codex, false},
		{"empty value", "https://chatgpt.com/backend-api/codex", "", false},
	} {
		c := credentialAudienceCandidate{patternName: "JWT Token", headerValue: tc.value}
		if got := signInBearerAllowed(c, "chatgpt.com", tc.target, surface); got != tc.allow {
			t.Errorf("%s: allowed=%t want %t", tc.name, got, tc.allow)
		}
	}
}
