// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
)

func TestCredentialAudienceEndpointAndCarrier(t *testing.T) {
	s := MustNew(credentialAudienceEntropyConfig())
	defer s.Close()
	discord := "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27)
	google := "AI" + "za" + strings.Repeat("a", 35)
	groq := "gsk_" + strings.Repeat("a", 48)
	anthropic := "sk-" + "ant-" + strings.Repeat("a", 24)
	for _, tc := range []struct {
		name, target, value, header string
		allow                       bool
	}{
		{"discord header", "https://discord.com/api/v10/users/@me", discord, "Bot", true},
		{"discord wrong route", "https://discord.com/webhooks/1/2", discord, "Bot", false},
		{"discord route delimiter", "https://discord.com/apix/webhooks", discord, "Bot", false},
		{"discord escaped route", "https://discord.com/api%2fv10/users/@me", discord, "Bot", false},
		{"discord traversal", "https://discord.com/api/../webhooks", discord, "Bot", false},
		{"discord repeated slash", "https://discord.com/api//webhooks", discord, "Bot", false},
		{"discord wrong scheme", "https://discord.com/api/v10/users/@me", discord, "Bearer", false},
		{"discord body", "https://discord.com/api/v10/users/@me", discord, "", false},
		{"google storage", "https://storage.googleapis.com/bucket/object", google, "X-Goog-Api-Key", false},
		{"google header", "https://generativelanguage.googleapis.com/v1beta/models", google, "X-Goog-Api-Key", true},
		{"groq subdomain", "https://other.groq.com/openai/v1/chat/completions", groq, "Bearer", false},
		{"groq header", "https://api.groq.com/openai/v1/chat/completions", groq, "Bearer", true},
		{"groq wrong route", "https://api.groq.com/unrelated", groq, "Bearer", false},
		{"anthropic body", "https://api.anthropic.com/v1/messages", anthropic, "", false},
		{"anthropic header", "https://api.anthropic.com/v1/messages", anthropic, "X-Api-Key", true},
		{"anthropic openai sdk bearer", "https://api.anthropic.com/v1/chat/completions", anthropic, "Bearer", true},
		{"anthropic wrong scheme", "https://api.anthropic.com/v1/messages", anthropic, "Basic", false},
		{"anthropic bearer wrong route", "https://api.anthropic.com/admin", anthropic, "Bearer", false},
		{"anthropic subdomain", "https://other.anthropic.com/v1/messages", anthropic, "X-Api-Key", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matches := s.ScanTextForDLP(context.Background(), tc.value).Matches
			if len(matches) == 0 {
				t.Fatal("fixture does not match DLP")
			}
			var kept []TextDLPMatch
			var allows []CredentialAudienceAllow
			if tc.header == "" {
				kept, allows = s.FilterTextDLPMatchesForDestination(matches, tc.target, "body")
			} else {
				name, value := "Authorization", tc.header+" "+tc.value
				if strings.HasPrefix(tc.header, "X-") {
					name, value = tc.header, tc.value
				}
				kept, allows = s.FilterHeaderDLPMatches(matches, tc.target, name, value)
			}
			if (len(kept) == 0) != tc.allow || (len(allows) > 0) != tc.allow {
				t.Fatalf("allow=%v retained=%d records=%+v", tc.allow, len(kept), allows)
			}
		})
	}
	for _, fixture := range []struct{ key, target string }{
		{"dapi" + strings.Repeat("a", 32), "https://other.cloud.databricks.com/api/2.0/clusters/list"},
		{"pcsk_" + strings.Repeat("a", 36), "https://other.svc.us-east1-gcp.pinecone.io/query"},
	} {
		if got := s.Scan(context.Background(), fixture.target+"?value="+fixture.key); got.Allowed {
			t.Fatal("credential at an arbitrary account host allowed")
		}
		matches := s.ScanTextForDLP(context.Background(), fixture.key).Matches
		kept, _ := s.FilterTextDLPMatchesForDestination(matches, fixture.target, CredentialAudienceAuthorizationHeaderSurface)
		if len(kept) == 0 {
			t.Fatal("credential header at an arbitrary account host allowed")
		}
	}
	for _, target := range []string{
		"https://discord.com/api/webhooks/1/" + discord,
		"https://discord.com/api/webhooks/1/2?value=" + discord,
		"https://storage.googleapis.com/bucket/" + google,
		"https://storage.googleapis.com/bucket/object?value=" + google,
		"https://other.groq.com/?value=" + groq,
	} {
		if result := s.Scan(context.Background(), target); result.Allowed {
			t.Fatalf("undocumented URL carrier allowed at %s", result.Scanner)
		}
	}
}

func TestGoogleAPIKeyQueryCarrierIsolation(t *testing.T) {
	s := MustNew(credentialAudienceEntropyConfig())
	defer s.Close()
	key := "AI" + "za" + "Sy9fK2qLmR7xWvT4bNcZ8pH3jD6gE1uYo0A"
	base := "https://maps.googleapis.com/maps/api/js?key=" + key
	for _, tc := range []struct {
		suffix string
		allow  bool
	}{
		{"", true},
		{"&callback=initMap", true},
		{"&key=" + key, false},
		{"&extra=" + key, false},
		{"&extra=" + base64.StdEncoding.EncodeToString([]byte(key)), false},
		{"&extra=" + url.QueryEscape("Q7mZ9pL4vR2sK8hF6dA0nT5cW3xB1jG"+"uEoYiHkSqVfDtNr"), false},
	} {
		if got := s.Scan(context.Background(), base+tc.suffix); got.Allowed != tc.allow {
			t.Fatalf("suffix %q: allowed=%v scanner=%s", tc.suffix, got.Allowed, got.Scanner)
		}
	}
}

func TestCredentialAudienceEndpointRoutes(t *testing.T) {
	for _, tc := range []struct {
		pattern, host, path string
		allow               bool
	}{
		{"Fireworks API Key", "api.fireworks.ai", "/v1/accounts", true},
		{"Hugging Face Token", "huggingface.co", "/api/whoami-v2", true},
		{"Hugging Face Token", "router.huggingface.co", "/v1/chat/completions", true},
		{"Slack Token", "mcp.slack.com", "/mcp", true},
		{"Slack Token", "mcp.slack.com", "/mcp/other", false},
		{"Google API Key", "language.googleapis.com", "/v1/documents:analyzeEntities", true},
		{"Google API Key", "translation.googleapis.com", "/language/translate/v2", true},
		{"Google API Key", "generativelanguage.googleapis.com", "/v1/models", true},
		{"Google API Key", "other.googleapis.com", "/v1/models", false},
		{"OpenAI API Key", "api.openai.com", "/v1\\42", false},
		{"OpenAI API Key", "api.openai.com", "/v1/./other", false},
	} {
		candidate := credentialAudienceCandidate{patternName: tc.pattern}
		if got := audienceAPIEndpointAllowed(candidate, tc.host, "https://"+tc.host+tc.path, CredentialAudienceAuthorizationHeaderSurface); got != tc.allow {
			t.Fatalf("%s%s: allowed=%v want %v", tc.host, tc.path, got, tc.allow)
		}
	}
	if audienceAPIEndpointAllowed(credentialAudienceCandidate{patternName: "OpenAI API Key"}, "api.openai.com", "https://api.openai.com/%zz", CredentialAudienceAuthorizationHeaderSurface) {
		t.Fatal("malformed URL earned an endpoint allow")
	}
	if !audienceAPIEndpointAllowed(credentialAudienceCandidate{patternName: "Test Custom Pattern"}, "api.vendor.example", "https://api.vendor.example", "body") {
		t.Fatal("custom contract changed")
	}
}

func TestGoogleAPIKeyQueryShapes(t *testing.T) {
	s := MustNew(credentialAudienceEntropyConfig())
	defer s.Close()
	var pattern *compiledPattern
	for _, p := range s.dlpPatterns {
		if p.name == "Google API Key" {
			pattern = p
			break
		}
	}
	if pattern == nil {
		t.Fatal("Google key pattern missing")
	}
	key := "AI" + "za" + strings.Repeat("a", 35)
	for _, query := range []string{"key=%zz", "key=" + key + "&key=" + key, "key=ordinary", "key=" + key + "&" + key + "=ordinary", "key=" + key + "&other=" + key} {
		u := &url.URL{Scheme: "https", Host: "maps.googleapis.com", Path: "/maps/api/js", RawQuery: query}
		if apiKeyQueryAllowed(pattern, u) {
			t.Fatalf("unqualified query allowed: %s", query)
		}
	}
}

func TestCredentialAudienceRemainingAPIRoutes(t *testing.T) {
	s := MustNew(credentialAudienceEntropyConfig())
	defer s.Close()
	for _, tc := range []struct {
		pattern, key, target, header string
		allow                        bool
	}{
		{"Google OAuth Token", "ya29." + strings.Repeat("a", 24), "https://www.googleapis.com/drive/v3/files", "Authorization", true},
		{"Google OAuth Token", "ya29." + strings.Repeat("a", 24), "https://storage.googleapis.com/upload/storage/v1/b/bucket/o", "Authorization", true},
		{"Google OAuth Token", "ya29." + strings.Repeat("a", 24), "https://gmail.googleapis.com/resumable/upload/gmail/v1/users/me/messages", "Authorization", true},
		{"Google OAuth Token", "ya29." + strings.Repeat("a", 24), "https://storage.googleapis.com/bucket/object", "Authorization", false},
		{"Google OAuth Token", "ya29." + strings.Repeat("a", 24), "https://other.googleapis.com/path", "Authorization", false},
		{"GitLab PAT", "glpat-" + strings.Repeat("a", 20), "https://gitlab.com/api/v4/user", "Private-Token", true},
		{"GitLab PAT", "glpat-" + strings.Repeat("a", 20), "https://gitlab.com/project/path", "Private-Token", false},
		{"GitLab PAT", "glpat-" + strings.Repeat("a", 20), "https://gitlab.com/api/graphql", "Authorization", true},
		{"GitLab PAT", "glpat-" + strings.Repeat("a", 20), "https://gitlab.com/api/graphqlx", "Authorization", false},
		{"GitLab PAT", "glpat-" + strings.Repeat("a", 20), "https://gitlab.com/api/graphql/extra", "Authorization", false},
		{"GitLab CI Job Token", "glcbt-" + strings.Repeat("a", 20), "https://gitlab.com/api/graphql", "Job-Token", false},
		{"GitLab CI Job Token", "glcbt-" + strings.Repeat("a", 20), "https://gitlab.com/api/v4/job", "Job-Token", true},
		{"GitHub Token", "ghp_" + strings.Repeat("a", 36), "https://uploads.github.com/repos/o/r/releases/1/assets", "Authorization", true},
		{"GitHub Token", "ghp_" + strings.Repeat("a", 36), "https://uploads.github.com/unrelated", "Authorization", false},
	} {
		matches := s.ScanTextForDLP(context.Background(), tc.key).Matches
		if len(matches) == 0 {
			t.Fatalf("fixture for %s not detected", tc.pattern)
		}
		value := tc.key
		if tc.header == "Authorization" {
			value = "Bearer " + value
		}
		kept, allows := s.FilterHeaderDLPMatches(matches, tc.target, tc.header, value)
		if (len(kept) == 0) != tc.allow || (len(allows) > 0) != tc.allow {
			t.Fatalf("%s at %s: retained=%d allows=%d want allowed=%v", tc.pattern, tc.target, len(kept), len(allows), tc.allow)
		}
	}
}

// TestGoogleAPIKeyQueryRescanWithoutEntropy pins the remaining-query DLP rescan
// on its own: with query entropy off, only that rescan sees an encoded second
// key beside the exempt key parameter.
func TestGoogleAPIKeyQueryRescanWithoutEntropy(t *testing.T) {
	cfg := credentialAudienceEntropyConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	s := MustNew(cfg)
	defer s.Close()
	key := "AI" + "za" + "Sy9fK2qLmR7xWvT4bNcZ8pH3jD6gE1uYo0A"
	other := "AI" + "za" + "Sy0aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV"
	base := "https://maps.googleapis.com/maps/api/js?key=" + key
	if got := s.Scan(context.Background(), base+"&callback=initMap"); !got.Allowed {
		t.Fatalf("documented key query blocked by %s: %s", got.Scanner, got.Reason)
	}
	for _, encoded := range []string{base64.StdEncoding.EncodeToString([]byte(other)), hex.EncodeToString([]byte(other))} {
		if got := s.Scan(context.Background(), base+"&extra="+encoded); got.Allowed {
			t.Fatalf("encoded second key beside the key parameter allowed: %s", encoded)
		}
	}
}

func TestTogetherAudiencePublishedHosts(t *testing.T) {
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()
	credential := "tok_" + strings.Repeat("a", 40)
	matches := s.ScanTextForDLP(t.Context(), credential).Matches
	if len(matches) != 1 {
		t.Fatalf("fixture must match once: %+v", matches)
	}
	for _, tc := range []struct {
		target string
		allow  bool
	}{
		{"https://api.together.ai/v1/chat/completions", true},
		{"https://api.together.xyz/v1/chat/completions", true},
		{"https://api.together.xyz.evil.example/v1/chat/completions", false},
		{"http://api.together.xyz/v1/chat/completions", false},
		{"https://api.together.xyz/unrelated", false},
	} {
		kept, allows := s.FilterHeaderDLPMatches(matches, tc.target, "Authorization", "Bearer "+credential)
		if (len(kept) == 0) != tc.allow || (len(allows) == 1) != tc.allow {
			t.Fatalf("%s: kept=%+v allows=%+v", tc.target, kept, allows)
		}
		kept, _ = s.FilterTextDLPMatchesForDestination(matches, tc.target, "body")
		if len(kept) != 1 {
			t.Fatal("body carrier allowed")
		}
	}
}

func TestHuggingFaceDownloadAudience(t *testing.T) {
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()
	credential := "hf_" + strings.Repeat("a", 34)
	matches := s.ScanTextForDLP(t.Context(), credential).Matches
	if len(matches) != 1 {
		t.Fatalf("fixture must match once: %+v", matches)
	}
	for _, tc := range []struct {
		path  string
		allow bool
	}{
		{"/org/repo/resolve/main/model.bin", true},
		{"/repo/resolve/main/subfolder/model.bin", true},
		{"/datasets/org/repo/resolve/main/data.csv", true},
		{"/spaces/org/repo/resolve/main/app.py", true},
		{"/kernels/org/repo/resolve/main/kernel.py", true},
		{"/org/repo/resolvex/main/model.bin", false},
		{"/extra/org/repo/resolve/main/model.bin", false},
		{"/org/repo/resolve/main", false},
		{"/org/repo/resolve/main/", false},
		{"/org/repo/blob/main/model.bin", false},
		{"/org/repo/resolve/main/../model.bin", false},
		{"/org/repo/resolve/main//model.bin", false},
		{"/org/repo/resolve/refs%2Fpr%2F1/model.bin", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			target := "https://huggingface.co" + tc.path
			kept, allows := s.FilterHeaderDLPMatches(matches, target, "Authorization", "Bearer "+credential)
			if (len(kept) == 0) != tc.allow || (len(allows) == 1) != tc.allow {
				t.Fatalf("kept=%+v allows=%+v", kept, allows)
			}
			for _, surface := range []string{"body", "url", "websocket_frame", "header"} {
				kept, _ = s.FilterTextDLPMatchesForDestination(matches, target, surface)
				if len(kept) != 1 {
					t.Fatalf("undocumented %s carrier allowed", surface)
				}
			}
		})
	}
	for _, target := range []string{"http://huggingface.co/org/repo/resolve/main/model.bin", "https://huggingface.co.evil.example/org/repo/resolve/main/model.bin", "https://cdn.vendor.example/org/repo/resolve/main/model.bin"} {
		kept, _ := s.FilterHeaderDLPMatches(matches, target, "Authorization", "Bearer "+credential)
		if len(kept) != 1 {
			t.Fatalf("non-audience target allowed: %s", target)
		}
	}
}
