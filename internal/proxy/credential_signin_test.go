// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func signInTestJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." + strings.Repeat("a", 24)
}

// The sign-in Bearer must pass the whole request-header scan, including the
// joined-header copy, which is where a header set with more than one value is
// decided. Scanner-level tests do not reach that path.
func TestSignInBearer_RequestHeaderScan(t *testing.T) {
	codex := signInTestJWT(t, map[string]any{"iss": "https://auth.openai.com", "client_id": "app_EMoamEEZ73f0CkXaXp7hrann"})
	other := signInTestJWT(t, map[string]any{"iss": "https://auth.vendor.example", "client_id": "app_other"})
	const target = "https://chatgpt.com/backend-api/codex/responses"

	for _, mode := range []string{config.HeaderModeSensitive, config.HeaderModeAll} {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.RequestBodyScanning.ScanHeaders = true
		cfg.RequestBodyScanning.HeaderMode = mode
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)

		for _, tc := range []struct {
			name    string
			headers http.Header
			target  string
			clean   bool
			allOnly bool // the carrier header is outside the sensitive list
			wantJWT bool // the JWT finding itself must remain, not just another block
		}{
			{"codex client headers", http.Header{
				"Authorization": {"Bearer " + codex}, "User-Agent": {"codex_cli_rs/0.167.0"}, "Chatgpt-Account-Id": {"acct-1"},
			}, target, true, false, false},
			{"authorization only", http.Header{"Authorization": {"Bearer " + codex}}, target, true, false, false},
			{"same token copied to another header", http.Header{
				"Authorization": {"Bearer " + codex}, "X-Copy": {codex}, "User-Agent": {"codex_cli_rs/0.167.0"},
			}, target, false, true, false},
			{"foreign token", http.Header{"Authorization": {"Bearer " + other}, "User-Agent": {"x"}}, target, false, false, false},
			{"other host", http.Header{"Authorization": {"Bearer " + codex}, "User-Agent": {"x"}}, "https://api.vendor.example/backend-api/codex", false, false, false},
			{"wss target", http.Header{"Authorization": {"Bearer " + codex}, "User-Agent": {"x"}}, "wss://chatgpt.com/backend-api/codex/responses", false, false, false},
			{"percent-encoded foreign token ahead of the sign-in token", http.Header{
				"Authorization": {"Bearer " + percentEncodeAll(other) + codex}, "User-Agent": {"x"},
			}, target, false, false, true},
			{"base64 foreign token ahead of the sign-in token", http.Header{
				"Authorization": {"Bearer " + base64.StdEncoding.EncodeToString([]byte(other+"!")) + codex}, "User-Agent": {"x"},
			}, target, false, false, true},
			{"unrelated secret beside token", http.Header{
				"Authorization": {"Bearer " + codex + " AKIA" + strings.Repeat("A", 16)}, "User-Agent": {"x"},
			}, target, false, false, false},
			{"secret split across headers", http.Header{
				"Authorization": {"Bearer " + codex + "AKIA" + strings.Repeat("A", 8)}, "X-Split": {"C" + strings.Repeat("A", 7)},
			}, target, false, true, false},
		} {
			if tc.allOnly && mode != config.HeaderModeAll {
				continue
			}
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				var allows []scanner.CredentialAudienceAllow
				result := scanRequestHeadersForTargetWithAudience(t.Context(), tc.headers, cfg, sc, tc.target, nil,
					func(allow scanner.CredentialAudienceAllow) error { allows = append(allows, allow); return nil })
				clean := result == nil || result.Clean
				if clean != tc.clean {
					t.Fatalf("clean=%t want %t result=%#v allows=%#v", clean, tc.clean, result, allows)
				}
				if tc.wantJWT {
					found := false
					for _, m := range result.DLPMatches {
						found = found || m.PatternName == "JWT Token"
					}
					if !found {
						t.Fatalf("decoded foreign JWT finding was dropped: %#v", result.DLPMatches)
					}
				}
			})
		}
	}
}

// percentEncodeAll encodes every byte, so the value carries no plaintext token.
func percentEncodeAll(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		fmt.Fprintf(&b, "%%%02X", v[i])
	}
	return b.String()
}
