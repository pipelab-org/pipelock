// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
)

func TestDiscordGatewayCarrierCredentialCopies(t *testing.T) {
	s := MustNew(credentialAudienceTestConfig())
	t.Cleanup(s.Close)
	credential := "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27)
	var percent strings.Builder
	for _, ch := range []byte(credential) {
		_, _ = fmt.Fprintf(&percent, "%%%02X", ch)
	}
	for _, op := range []int{2, 6} {
		control := fmt.Sprintf(`{"op":%d,"d":{"token":%q,"extra":["before","ordinary","after"]}}`, op, credential)
		if surface, _, invalid := s.WebSocketCredentialAudienceSurface(t.Context(), []byte(control), "wss://gateway.discord.gg/"); surface != credentialAudienceDiscordGatewaySurface || invalid {
			t.Fatal("control: ordinary extra fields did not earn the carrier")
		}
		for name, extra := range map[string]string{
			// Escape the first byte so the raw credential occurs only in d.token;
			// rejection must come from DLP, not the raw replacement ambiguity guard.
			"plain":   `["before","\u004d` + credential[1:] + `","after"]`,
			"base64":  fmt.Sprintf(`["before",%q,"after"]`, base64.StdEncoding.EncodeToString([]byte(credential))),
			"base32":  fmt.Sprintf(`["before",%q,"after"]`, base32.StdEncoding.EncodeToString([]byte(credential))),
			"hex":     fmt.Sprintf(`["before",%q,"after"]`, hex.EncodeToString([]byte(credential))),
			"percent": fmt.Sprintf(`["before",%q,"after"]`, percent.String()),
			"split":   fmt.Sprintf(`["before",%q,%q,"after"]`, credential[:24], credential[24:]),
		} {
			t.Run(fmt.Sprintf("op=%d/%s", op, name), func(t *testing.T) {
				frame := fmt.Sprintf(`{"op":%d,"d":{"token":%q,"extra":%s}}`, op, credential, extra)
				if strings.Count(frame, credential) != 1 {
					t.Fatal("fixture must not rely on the raw credential ambiguity guard")
				}
				if surface, view, invalid := s.WebSocketCredentialAudienceSurface(t.Context(), []byte(frame), "wss://gateway.discord.gg/"); surface != "websocket_frame" || view != nil || invalid {
					t.Fatalf("duplicate credential earned carrier: surface=%q view=%q invalid=%t", surface, view, invalid)
				}
				matches := s.ScanTextForDLPQuiet(t.Context(), frame).Matches
				kept, allows := s.FilterTextDLPMatchesForDestination(matches, "wss://gateway.discord.gg/", "websocket_frame")
				if len(kept) == 0 || len(allows) != 0 {
					t.Fatal("fallback did not keep an enforcing credential finding")
				}
			})
		}
	}
}

func TestDiscordGatewayCarrierScanCount(t *testing.T) {
	for _, count := range []int{1, 1024, maxDecodeCandidates - 4, maxDecodeCandidates - 3, (1<<20)/len(`"ordinary",`) - 4} {
		t.Run(fmt.Sprintf("strings=%d", count), func(t *testing.T) {
			remaining := []byte(`{"op":2,"d":{"extra":[` + strings.Repeat(`"ordinary",`, count-1) + `"ordinary"]}}`)
			calls := 0
			scan := func(context.Context, string) TextDLPResult {
				calls++
				return TextDLPResult{Clean: true}
			}
			extracted := extract.AllStringsFromJSONResult(remaining)
			overBudget := len(extracted.Strings) > maxDecodeCandidates
			if got := gatewayRemainderHasCredential(t.Context(), remaining, "Discord Bot Token", scan); got != overBudget {
				t.Fatalf("carrier refusal=%t, want over-budget=%t", got, overBudget)
			}
			wantCalls := len(extracted.Strings) + 4 // fields plus the four aggregate views
			if overBudget {
				wantCalls = 0
			}
			if calls != wantCalls || calls > maxDecodeCandidates+4 {
				t.Fatalf("DLP scan calls=%d, want %d within candidate budget (frame bytes=%d)", calls, wantCalls, len(remaining))
			}
			t.Logf("frame bytes=%d: DLP scan calls=%d, carrier refused=%t", len(remaining), calls, overBudget)
		})
	}
}

func TestDiscordGatewayCarrierQualification(t *testing.T) {
	cfg := credentialAudienceTestConfig()
	s := MustNew(cfg)
	defer s.Close()
	credential := "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27)
	frame := `{"op":2,"d":{"token":"` + credential + `"}}`
	for _, tc := range []struct {
		name, frame    string
		allow, invalid bool
	}{
		{"identify", frame, true, false},
		{"malformed", frame[:len(frame)-1], false, true},
		{"unrecognized token", `{"op":2,"d":{"token":"ordinary"}}`, false, false},
		{"prefix outside token", `{"op":2,"d":{"token":"extra ` + credential + `"}}`, false, false},
		{"root array", `[]`, false, true},
		{"missing opcode", `{}`, false, true},
		{"opcode type", `{"op":"2"}`, false, true},
		{"heartbeat", `{"op":1,"d":null}`, false, false},
		{"null data", `{"op":2,"d":null}`, false, true},
		{"non-string token", `{"op":2,"d":{"token":123}}`, false, true},
		{"duplicate", `{"op":3,"op":2,"d":{"token":"` + credential + `"}}`, false, true},
		{"invalid UTF8", `{"op":2,"d":{"token":"` + credential + `","x":"` + string([]byte{0xff}) + `"}}`, false, true},
		{"other pattern", `{"op":2,"d":{"token":"` + credential + `","x":"hf_` + strings.Repeat("a", 34) + `"}}`, true, false},
		{"remaining token", `{"op":2,"d":{"token":"` + credential + `","x":"` + credential + `"}}`, false, false},
		{"extraction depth", `{"op":2,"d":{"token":"` + credential + `","x":` + strings.Repeat("[", extract.MaxExtractDepth+1) + `0` + strings.Repeat("]", extract.MaxExtractDepth+1) + `}}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			surface, view, invalid := s.WebSocketCredentialAudienceSurface(t.Context(), []byte(tc.frame), "wss://gateway.discord.gg/")
			if tc.allow && (len(view) == 0 || strings.Contains(string(view), credential)) {
				t.Fatal("cross-message scan view retained the authorized credential")
			}
			if (surface == credentialAudienceDiscordGatewaySurface) != tc.allow || invalid != tc.invalid {
				t.Fatalf("surface=%q invalid=%t", surface, invalid)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if surface, _, _ := s.WebSocketCredentialAudienceSurface(ctx, []byte(frame), "wss://gateway.discord.gg/"); surface != "websocket_frame" {
		t.Fatal("canceled context earned carrier")
	}
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Discord Bot Token", Regex: `ordinary`, Severity: config.SeverityCritical}}
	customized := MustNew(cfg)
	defer customized.Close()
	if surface, _, _ := customized.WebSocketCredentialAudienceSurface(t.Context(), []byte(frame), "wss://gateway.discord.gg/"); surface != "websocket_frame" {
		t.Fatal("custom rule inherited structured carrier")
	}
}
