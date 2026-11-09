// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
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

// The route requires the compiled sign-in carrier; a pattern name alone
// cannot earn it.
func TestSignInBearerAllowedOnlyForJWTPattern(t *testing.T) {
	t.Parallel()
	codex := registryJWT(t, map[string]any{"iss": "https://auth.openai.com", "client_id": "app_EMoamEEZ73f0CkXaXp7hrann"})
	c := credentialAudienceCandidate{patternName: "JWT Token", headerValue: "Bearer " + codex, valueIdentity: sha256.Sum256([]byte(codex)), hasValueIdentity: true}
	if signInBearerAllowed(c, "chatgpt.com", "https://chatgpt.com/backend-api/codex", CredentialAudienceAuthorizationHeaderSurface) {
		t.Fatal("pattern without the compiled carrier earned the sign-in route")
	}
	c.carrierMask = config.CredentialAudienceCarrierSignInBearer
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
	c.valueIdentity = sha256.Sum256([]byte("not.a-jwt"))
	if signInBearerAllowed(c, "chatgpt.com", "https://chatgpt.com/backend-api/codex", CredentialAudienceAuthorizationHeaderSurface) {
		t.Fatal("malformed token allowed")
	}
	c.headerValue = "Bearer a.%%%.b"
	c.valueIdentity = sha256.Sum256([]byte("a.%%%.b"))
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
		c := credentialAudienceCandidate{patternName: "JWT Token", carrierMask: config.CredentialAudienceCarrierSignInBearer, headerValue: tc.value, valueIdentity: sha256.Sum256([]byte(codex)), hasValueIdentity: true}
		if got := signInBearerAllowed(c, "chatgpt.com", tc.target, surface); got != tc.allow {
			t.Errorf("%s: allowed=%t want %t", tc.name, got, tc.allow)
		}
	}
}

func TestSignInBearerMatchedValue(t *testing.T) {
	t.Parallel()
	route := signInBearerRoutes[0]
	token := registryJWT(t, map[string]any{"iss": route.issuer, "client_id": route.clientID})
	other := registryJWT(t, map[string]any{"iss": "https://auth.vendor.example", "client_id": "app_other"})
	target := "https://" + route.host + route.prefix + "/responses"
	s := MustNew(credentialAudienceTestConfig())
	t.Cleanup(s.Close)
	for _, tc := range []struct {
		name, matched, value string
		allow                bool
	}{
		{"whole token", token, "Bearer " + token, true},
		{"whitespace", token, "  bEaReR\t" + token + "  ", true},
		{"different token", other, "Bearer " + token, false},
		{"trailing garbage", token, "Bearer " + token + "!", false},
		{"prefix garbage", token, "Bearer !" + token, false},
		{"second token", other, "Bearer " + token + "!" + other, false},
		{"token elsewhere", token, "Bearer placeholder " + token, false},
		{"case differs", token[:len(token)-16] + strings.Repeat("A", 16), "Bearer " + token, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matches := s.ScanTextForDLP(t.Context(), tc.matched).Matches
			if !matchRetained(matches, "JWT Token") {
				t.Fatal("fixture must match JWT pattern")
			}
			retained, allows := s.FilterHeaderDLPMatches(matches, target, "Authorization", tc.value)
			if audienceAllowFor(allows, "JWT Token") != tc.allow || matchRetained(retained, "JWT Token") == tc.allow {
				t.Fatalf("allow=%t retained=%v records=%v", tc.allow, retained, allows)
			}
			if tc.matched == token {
				scrubbed := s.ScrubAuthorizedCredentialFromJoinedHeaders("Authorization", tc.value, target)
				if (scrubbed != tc.value) != tc.allow {
					t.Fatalf("scrubbed=%t want %t", scrubbed != tc.value, tc.allow)
				}
			}
		})
	}
	candidate := credentialAudienceCandidate{carrierMask: config.CredentialAudienceCarrierSignInBearer, headerValue: "Bearer " + token}
	if signInBearerAllowed(candidate, route.host, target, CredentialAudienceAuthorizationHeaderSurface) {
		t.Fatal("missing match identity earned allowance")
	}
}

func TestSignInBearerCustomPattern(t *testing.T) {
	t.Parallel()
	route := signInBearerRoutes[0]
	token := registryJWT(t, map[string]any{"iss": route.issuer, "client_id": route.clientID})
	cfg := credentialAudienceTestConfig()
	for i := range cfg.DLP.Patterns {
		if cfg.DLP.Patterns[i].Name == "JWT Token" {
			cfg.DLP.Patterns[i].Regex += `|custom-[a-z]+`
		}
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	matches := s.ScanTextForDLP(t.Context(), token).Matches
	if !matchRetained(matches, "JWT Token") {
		t.Fatal("custom JWT pattern must still detect token")
	}
	retained, allows := s.FilterHeaderDLPMatches(matches, "https://"+route.host+route.prefix+"/responses", "Authorization", "Bearer "+token)
	if !matchRetained(retained, "JWT Token") || audienceAllowFor(allows, "JWT Token") {
		t.Fatalf("custom JWT pattern earned allowance: retained=%v records=%v", retained, allows)
	}
}

// Binding many JWT-shaped matches in one header must parse and hash the
// bearer once, and a shared parse must decide exactly like an on-demand one.
func TestMatchedBearerTokenSharedParse(t *testing.T) {
	token := strings.Join([]string{"eyJh", "bGciOiJub25lIn0", ".eyJpc3MiOiJ4In0", ".sig"}, "")
	header := "Bearer " + token
	shared := parseBearer(header)
	for _, tc := range []struct {
		name    string
		header  string
		matched string
		want    bool
	}{
		{"whole bearer", header, token, true},
		{"substring", header, token[:10], false},
		{"other token", header, token + "x", false},
		{"two tokens", "Bearer " + token + " " + token, token, false},
		{"basic scheme", "Basic " + token, token, false},
		{"empty match", header, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := credentialAudienceCandidate{headerValue: tc.header, valueIdentity: sha256.Sum256([]byte(tc.matched)), hasValueIdentity: tc.matched != ""}
			_, onDemand := matchedBearerToken(candidate)
			if onDemand != tc.want {
				t.Fatalf("on-demand parse = %v, want %v", onDemand, tc.want)
			}
			candidate.bearer = parseBearer(tc.header)
			if _, got := matchedBearerToken(candidate); got != onDemand {
				t.Fatalf("shared parse = %v, on-demand = %v", got, onDemand)
			}
		})
	}
	if !shared.ok || shared.token != token {
		t.Fatal("shared parse lost the bearer token")
	}
}
