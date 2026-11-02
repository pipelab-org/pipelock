// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
)

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
