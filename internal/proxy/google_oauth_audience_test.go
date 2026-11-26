// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// The forward proxy and CONNECT interceptor share this target-aware header scan.
func TestGoogleOAuthRequestCarriers(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	token := "ya29." + strings.Repeat("a", 24)
	for _, host := range []string{"cloudcode-pa.googleapis.com", "daily-cloudcode-pa.googleapis.com"} {
		for _, method := range []string{"loadCodeAssist", "generateContent", "streamGenerateContent", "fetchAvailableModels", "listExperiments", "fetchUserInfo", "fetchAdminControls", "retrieveUserQuotaSummary"} {
			target := "https://" + host + "/v1internal:" + method
			t.Run(host+"/"+method, func(t *testing.T) {
				headers := http.Header{"Authorization": {"Bearer " + token}}
				result := scanRequestHeadersForTarget(t.Context(), headers, cfg, sc, target)
				if result != nil && !result.Clean {
					t.Fatalf("provider header retained findings: %v", dlpMatchNames(result.DLPMatches))
				}
				if sc.Scan(t.Context(), target+"?access_token="+token).Allowed {
					t.Fatal("query token allowed")
				}
				body := `{"token":"` + token + `"}`
				_, bodyResult := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(body), ContentType: "application/json", MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc, Host: host, Path: "/v1internal:" + method, Target: target, Suppress: cfg.Suppress})
				if bodyResult.Clean {
					t.Fatal("body token allowed")
				}
			})
		}
	}
	for _, tc := range []struct {
		target, header string
		allow          bool
	}{
		{"https://aicode.googleapis.com/v1alpha:fetchConfig", "Authorization", true},
		{"https://play.googleapis.com/log", "Authorization", true},
		{"https://www.googleapis.com/oauth2/v2/userinfo", "Authorization", true},
		{"https://www.googleapis.com/userinfo/v2/me", "Authorization", true},
		{"https://api.vendor.example/v1internal:generateContent", "Authorization", false},
		{"https://googleapis.com.evil.example/v1internal:generateContent", "Authorization", false},
		{"https://evilgoogleapis.com/v1internal:generateContent", "Authorization", false},
		{"https://cloudcode-pa.googleapis.com.evil.example/v1internal:generateContent", "Authorization", false},
		{"http://cloudcode-pa.googleapis.com/v1internal:generateContent", "Authorization", false},
		{"https://cloudcode-pa.googleapis.com/v1internal:generateContent", "X-Api-Key", false},
		{"https://storage.googleapis.com/bucket/object", "Authorization", false},
		{"https://play.googleapis.com/log/extra", "Authorization", false},
		{"https://aicode.googleapis.com/other", "Authorization", false},
		{"https://cloudcode-pa.googleapis.com/v1internal:", "Authorization", false},
		{"https://cloudcode-pa.googleapis.com/other", "Authorization", false},
		{"https://cloudcode-pa.googleapis.com/v1internal%3AgenerateContent", "Authorization", false},
		{"https://cloudcode-pa.googleapis.com/v1internal:generateContent//", "Authorization", false},
		{"https://cloudcode-pa.googleapis.com/../v1internal:generateContent", "Authorization", false},
		{"https://cloudcode-pa.googleapis.com/v1internal:generateContent/extra", "Authorization", false},
	} {
		t.Run(tc.target+"/"+tc.header, func(t *testing.T) {
			result := scanRequestHeadersForTarget(t.Context(), http.Header{tc.header: {"Bearer " + token}}, cfg, sc, tc.target)
			clean := result == nil || result.Clean
			if clean != tc.allow {
				t.Fatalf("clean=%t want %t: %+v", clean, tc.allow, result)
			}
			if tc.allow {
				if sc.Scan(t.Context(), tc.target+"?access_token="+token).Allowed {
					t.Fatal("query token allowed")
				}
				matches := sc.ScanTextForDLP(t.Context(), token).Matches
				retained, allows := sc.FilterTextDLPMatchesForDestination(matches, tc.target, "body")
				if len(retained) == 0 || len(allows) != 0 {
					t.Fatal("body token allowed")
				}
			}
		})
	}
}
