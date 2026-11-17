// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBufferedCheckerWebSocketBodyIsolation(t *testing.T) {
	for _, mode := range []string{config.InjectionModeOff, config.InjectionModeBlock} {
		for _, text := range []string{"ordinary frame", checkertest.Directive} {
			t.Run(mode+"/"+text, func(t *testing.T) {
				srv := checkertest.New(t, "finding")
				cfg := testScannerConfig()
				srv.Configure(cfg, config.InjectionSurfaceHTTPRequestBody, mode)
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				_, got := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(text), ContentType: "text/plain", MaxBytes: 1024, Scanner: sc, Action: config.ActionBlock, AudienceSurface: "websocket_frame"})
				wantFinding := text == checkertest.Directive
				if got.Clean == wantFinding || len(srv.Items()) != 0 || scanner.HasCheckerFinding(got.InjectionMatches) {
					t.Fatalf("want builtin finding=%t calls=%d result=%+v", wantFinding, len(srv.Items()), got)
				}
			})
		}
	}
}
