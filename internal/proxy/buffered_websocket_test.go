// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBufferedCheckerWebSocketBodyIsolation(t *testing.T) {
	for _, carrier := range []string{"websocket_frame", "websocket_binary"} {
		for _, mode := range []string{config.InjectionModeOff, config.InjectionModeBlock} {
			for _, text := range []string{"ordinary frame", checkertest.Directive} {
				t.Run(carrier+"/"+mode+"/"+text, func(t *testing.T) {
					srv := checkertest.New(t, "finding")
					cfg := testScannerConfig()
					srv.Configure(cfg, config.InjectionSurfaceHTTPRequestBody, mode)
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					_, got := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(text), ContentType: "text/plain", MaxBytes: 1024, Scanner: sc, Action: config.ActionBlock, AudienceSurface: carrier})
					wantFinding := text == checkertest.Directive
					if got.Clean == wantFinding || len(srv.Items()) != 0 || scanner.HasCheckerFinding(got.InjectionMatches) {
						t.Fatalf("want builtin finding=%t calls=%d result=%+v", wantFinding, len(srv.Items()), got)
					}
				})
			}
		}
	}
}

func TestBufferedCheckerDiscordGatewayIsolation(t *testing.T) {
	credential := "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27)
	const target = "wss://gateway.discord.gg/?v=10&encoding=json"
	for _, op := range []int{2, 6, 0} {
		for _, text := range []string{"ordinary message", checkertest.Directive} {
			for _, mode := range []string{config.InjectionModeOff, config.InjectionModeBlock} {
				t.Run(fmt.Sprintf("op%d/%s/%s", op, text, mode), func(t *testing.T) {
					srv := checkertest.New(t, "benign")
					cfg := testScannerConfig()
					srv.Configure(cfg, config.InjectionSurfaceHTTPRequestBody, mode)
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					frame := fmt.Sprintf(`{"op":%d,"d":{"token":%q,"message":%q}}`, op, credential, text)
					if op == 0 {
						frame = fmt.Sprintf(`{"op":0,"d":{"message":%q}}`, text)
					}
					surface, _, invalid := sc.WebSocketCredentialAudienceSurface(t.Context(), []byte(frame), target)
					if invalid || (op != 0 && surface != "discord_gateway_auth") {
						t.Fatalf("fixture did not reach auth audience: surface=%s invalid=%t", surface, invalid)
					}
					forwarded, got := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(frame), ContentType: "application/json", MaxBytes: 1024, Scanner: sc, Action: config.ActionBlock, AudienceSurface: "websocket_frame", Target: target})
					if len(srv.Items()) != 0 {
						t.Fatalf("WebSocket frame disclosed to HTTP checker: calls=%d", len(srv.Items()))
					}
					wantFinding := text == checkertest.Directive
					if got.Clean == wantFinding || (len(got.InjectionMatches) > 0) != wantFinding || scanner.HasCheckerFinding(got.InjectionMatches) {
						t.Fatalf("want builtin finding=%t result=%+v", wantFinding, got)
					}
					if !wantFinding && string(forwarded) != frame {
						t.Fatal("clean frame changed")
					}
				})
			}
		}
	}
}
