// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
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
			if got[0].PatternName != pattern || got[0].Surface != "body" || got[0].Destination != "api.vendor.example" || len(got[0].Hosts) != 1 || got[0].Hosts[0] != "api.provider.example" {
				t.Fatalf("mismatch = %+v", got)
			}
			explanation := CredentialAudienceMismatchExplanation(got)
			if !strings.Contains(explanation, "immutable audience hosts api.provider.example") || strings.Contains(explanation, "private") || strings.Contains(explanation, "hidden") {
				t.Fatalf("explanation = %q", explanation)
			}
			got[0].Hosts[0] = "mutated.example"
			if matches[0].credentialAudienceHosts[0] != "api.provider.example" {
				t.Fatal("diagnostic aliases the scanner's audience hosts")
			}
		})
	}
	if got := TextDLPCredentialAudienceMismatches(nil, "https://api.vendor.example", "body"); len(got) != 0 {
		t.Fatalf("no findings produced diagnosis: %+v", got)
	}
}
