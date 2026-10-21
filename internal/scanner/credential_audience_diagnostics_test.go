// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestTextDLPCredentialAudienceMismatches(t *testing.T) {
	const pattern = "Provider Key"
	matches := []TextDLPMatch{
		{PatternName: pattern, credentialAudienceHosts: []string{"api.provider.example"}},
		{PatternName: pattern, credentialAudienceHosts: []string{"api.provider.example"}},
		{PatternName: "Unbound Key"},
	}
	for _, tc := range []struct {
		name, target string
		want         int
	}{
		{"different host", "https://api.vendor.example/private?value=hidden", 1},
		{"websocket", "wss://api.vendor.example/v1", 1},
		{"same host", "https://api.provider.example/v1", 0},
		{"same host other port is not host mismatch", "https://api.provider.example:8443/v1", 0},
		{"empty", "", 0},
		{"malformed", "https://%/", 0},
		{"unowned path", "/v1", 0},
		{"userinfo", "https://user@api.vendor.example/", 0},
		{"cleartext not diagnosed as host mismatch", "http://api.vendor.example/", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := TextDLPCredentialAudienceMismatches(matches, tc.target, "body")
			if len(got) != tc.want {
				t.Fatalf("mismatches = %+v, want %d", got, tc.want)
			}
			if tc.want == 0 {
				if explanation := CredentialAudienceMismatchExplanation(got); explanation != "" {
					t.Fatalf("empty explanation = %q", explanation)
				}
				return
			}
			if got[0].PatternName != pattern || got[0].Surface != "body" || got[0].Destination != "api.vendor.example" || len(got[0].Hosts) != 0 || got[0].CoreRule {
				t.Fatalf("mismatch = %+v", got)
			}
			explanation := CredentialAudienceMismatchExplanation(got)
			if !strings.Contains(explanation, "credential audience mismatch") || strings.Contains(explanation, "api.provider.example") || strings.Contains(explanation, "private") || strings.Contains(explanation, "hidden") {
				t.Fatalf("explanation = %q", explanation)
			}
		})
	}
	if got := TextDLPCredentialAudienceMismatches(nil, "https://api.vendor.example", "body"); len(got) != 0 {
		t.Fatalf("no findings produced diagnosis: %+v", got)
	}
}

func TestCredentialAudienceDiagnosticsKeepDeclaredHostsPrivate(t *testing.T) {
	const declared = "git.corp.example"
	for _, tc := range []struct {
		name, value string
		core        bool
	}{
		{"GitHub Token", "ghp_" + strings.Repeat("a", 36), true},
		{"GitLab CI Job Token", "glcbt-" + strings.Repeat("d", 20), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := credentialAudienceTestConfig()
			cfg.DLP.GitHubEnterpriseHosts = []string{declared}
			cfg.DLP.GitLabHosts = []string{declared}
			sc := MustNew(cfg)
			t.Cleanup(sc.Close)
			matches := sc.ScanTextForDLP(t.Context(), tc.value).Matches
			retained, allows := sc.FilterTextDLPMatchesForDestination(matches, "https://other.vendor.example/receive", "body")
			if !matchRetained(retained, tc.name) || len(allows) != 0 {
				t.Fatalf("verdict changed: retained=%+v allows=%+v", retained, allows)
			}
			mismatches := TextDLPCredentialAudienceMismatches(retained, "https://other.vendor.example/receive", "body")
			if len(mismatches) != 1 || mismatches[0].CoreRule != tc.core || !reflect.DeepEqual(mismatches[0].Hosts, config.BuiltInCredentialAudienceHosts(tc.name)) {
				t.Fatalf("metadata = %+v", mismatches)
			}
			raw, err := json.Marshal(mismatches)
			if err != nil {
				t.Fatal(err)
			}
			explanation := CredentialAudienceMismatchExplanation(mismatches)
			if strings.Contains(string(raw)+explanation, declared) || strings.Contains(explanation, tc.value) || !strings.Contains(explanation, "built-in audience hosts") {
				t.Fatalf("unsafe diagnostic: %s %s", raw, explanation)
			}
			if strings.Contains(explanation, "suppress does not apply") != tc.core {
				t.Fatalf("core remedy = %q", explanation)
			}
			mismatches[0].Hosts[0] = "mutated.example"
			if config.BuiltInCredentialAudienceHosts(tc.name)[0] == "mutated.example" {
				t.Fatal("diagnostic mutated public audience registry")
			}
			// The diagnostic redaction must not remove declared-host allowances.
			surface := CredentialAudienceAuthorizationHeaderSurface
			if !tc.core {
				surface = credentialAudienceJobTokenSurface
			}
			retained, allows = sc.FilterTextDLPMatchesForDestination(matches, "https://"+declared+"/api/user", surface)
			if matchRetained(retained, tc.name) || !audienceAllowFor(allows, tc.name) {
				t.Fatalf("declared-host allowance changed: retained=%+v allows=%+v", retained, allows)
			}
			// URL diagnostics retain their existing core exclusion.
			result := sc.Scan(t.Context(), "https://other.vendor.example/"+tc.value)
			urlRaw, err := json.Marshal(result.CredentialAudienceMismatches)
			if err != nil || result.Allowed || strings.Contains(string(urlRaw), declared) {
				t.Fatalf("URL verdict/metadata = %+v err=%v", result, err)
			}
			if !tc.core && len(result.CredentialAudienceMismatches) == 0 {
				t.Fatal("non-core URL diagnostic disappeared")
			}
		})
	}
}

func TestTextDLPCredentialAudienceMismatchesSkipsGitAndRegistryHosts(t *testing.T) {
	matches := []TextDLPMatch{{
		PatternName:                     "Provider Key",
		credentialAudienceHosts:         []string{"api.provider.example"},
		credentialAudienceGitHosts:      []string{"git.provider.example"},
		credentialAudienceRegistryHosts: []string{"registry.provider.example"},
	}}
	for _, target := range []string{"https://git.provider.example/x", "https://registry.provider.example/x"} {
		if got := TextDLPCredentialAudienceMismatches(matches, target, "header"); len(got) != 0 {
			t.Fatalf("%s: carrier failure at an audience host reported as host mismatch: %+v", target, got)
		}
	}
	if got := TextDLPCredentialAudienceMismatches(matches, "https://other.vendor.example/x", "header"); len(got) != 1 {
		t.Fatalf("unrelated host mismatches = %+v, want 1", got)
	}
}

func TestCredentialAudienceMismatchURLTextParity(t *testing.T) {
	pattern := &compiledPattern{
		name:                            "Provider Key",
		credentialAudienceHosts:         []string{"api.provider.example", "*.service.example"},
		credentialAudienceGitHosts:      []string{"git.provider.example"},
		credentialAudienceRegistryHosts: []string{"registry.provider.example"},
	}
	match := TextDLPMatch{
		PatternName:                     pattern.name,
		credentialAudienceHosts:         pattern.credentialAudienceHosts,
		credentialAudienceGitHosts:      pattern.credentialAudienceGitHosts,
		credentialAudienceRegistryHosts: pattern.credentialAudienceRegistryHosts,
	}
	for _, tc := range []struct {
		name, target string
		want         bool
	}{
		{"unrelated", "https://other.vendor.example/private?hidden=value", true},
		{"canonical unrelated", "https://OTHER.vendor.example.:443/v1", true},
		{"audience", "https://api.provider.example/v1", false},
		{"wildcard audience", "https://api.service.example/v1", false},
		{"git carrier rejection", "https://git.provider.example/v1", false},
		{"registry carrier rejection", "https://registry.provider.example/v1", false},
		{"other port at audience", "https://api.provider.example:8443/v1", false},
		{"websocket unrelated", "wss://other.vendor.example/v1", true},
		{"cleartext", "http://other.vendor.example/v1", false},
		{"empty", "", false},
		{"malformed", "https://%/", false},
		{"relative", "/v1", false},
		{"userinfo", "https://user@other.vendor.example/v1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			urlMismatch, ok := (&Scanner{}).credentialAudienceMismatch(pattern, tc.target, "body")
			textMismatches := TextDLPCredentialAudienceMismatches([]TextDLPMatch{match}, tc.target, "body")
			if ok != tc.want || (len(textMismatches) == 1) != tc.want {
				t.Fatalf("URL mismatch = %+v (%v), text mismatches = %+v, want %v", urlMismatch, ok, textMismatches, tc.want)
			}
			if ok && !reflect.DeepEqual(urlMismatch, textMismatches[0]) {
				t.Fatalf("URL/text diagnostic drift: %+v != %+v", urlMismatch, textMismatches[0])
			}
		})
	}
	pattern.core = true
	if _, ok := (&Scanner{}).credentialAudienceMismatch(pattern, "https://other.vendor.example/v1", "url"); ok {
		t.Fatal("URL diagnostic must retain its core-pattern exclusion")
	}
	if got := TextDLPCredentialAudienceMismatches([]TextDLPMatch{match}, "https://other.vendor.example/v1", "body"); len(got) != 1 {
		t.Fatalf("text diagnostic lost surviving audience metadata: %+v", got)
	}
	pattern.core = false
	pattern.credentialAudienceHosts = nil
	match.credentialAudienceHosts = nil
	if _, ok := (&Scanner{}).credentialAudienceMismatch(pattern, "https://other.vendor.example/v1", "url"); ok {
		t.Fatal("URL diagnostic invented an audience")
	}
	if got := TextDLPCredentialAudienceMismatches([]TextDLPMatch{match}, "https://other.vendor.example/v1", "body"); len(got) != 0 {
		t.Fatalf("text diagnostic invented an audience: %+v", got)
	}
	if _, ok := (&Scanner{}).credentialAudienceMismatch(nil, "https://other.vendor.example/v1", "url"); ok {
		t.Fatal("nil pattern produced a diagnostic")
	}
}
