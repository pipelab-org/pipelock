// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A card followed by an expiry or quantity in a plain-text body must not
// reach the upstream on either HTTP request surface.
func TestTrailingDigitCardHTTPBodies(t *testing.T) {
	for _, surface := range []string{"forward", "intercept"} {
		for _, tt := range cardtest.TrailingDigitCases() {
			t.Run(surface+"/"+tt.Name, func(t *testing.T) {
				cfg := testScannerConfig()
				cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"93.184.216.34"}}
				cfg.DLP.ScanEnv = false
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = config.ActionBlock
				s := scanner.MustNew(cfg)
				t.Cleanup(s.Close)
				m := metrics.New()
				log := audit.NewNop()
				p, err := New(cfg, log, s, m)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				forwarded := false
				rt := forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
					if _, readErr := io.ReadAll(r.Body); readErr != nil {
						return nil, readErr
					}
					forwarded = true
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("accepted")), Request: r}, nil
				})
				p.client = &http.Client{Transport: rt}
				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example/notes", strings.NewReader(tt.Text))
				r.Header.Set("Content-Type", "text/plain")
				w := httptest.NewRecorder()
				if surface == "forward" {
					p.handleForwardHTTP(w, r)
				} else {
					newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: s, Logger: log, Metrics: m, ClientIP: "192.0.2.1", RequestID: "card-trailing-digit", Proxy: p}, rt).ServeHTTP(w, r)
				}
				want := http.StatusForbidden
				if tt.Clean {
					want = http.StatusOK
				}
				if forwarded != tt.Clean || w.Code != want {
					t.Fatalf("forwarded=%v status=%d want=%d", forwarded, w.Code, want)
				}
			})
		}
	}
}

func TestTrailingDigitCardWebSocketText(t *testing.T) {
	for _, tt := range cardtest.TrailingDigitCases() {
		t.Run(tt.Name, func(t *testing.T) {
			cfg := testScannerConfig()
			cfg.DLP.ScanEnv = false
			s := scanner.MustNew(cfg)
			t.Cleanup(s.Close)
			p, err := New(cfg, audit.NewNop(), s, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			var wire bytes.Buffer
			if err := wsutil.WriteClientMessage(&wire, ws.OpText, []byte(tt.Text)); err != nil {
				t.Fatal(err)
			}
			source := &receiptFrameConn{input: bytes.NewReader(wire.Bytes())}
			sink := &receiptFrameConn{input: bytes.NewReader(nil)}
			r := &wsRelay{proxy: p, cfg: cfg, scanner: s, hostname: "api.vendor.example", targetURL: "wss://api.vendor.example/notes", maxMsg: cfg.WebSocketProxy.MaxMessageBytes, scanText: true, clientConn: source, upstreamConn: sink}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			_, _, _, blocked := r.clientToUpstream(ctx, cancel, time.Minute)
			if blocked == tt.Clean {
				t.Fatalf("blocked=%v want=%v", blocked, !tt.Clean)
			}
		})
	}
}
