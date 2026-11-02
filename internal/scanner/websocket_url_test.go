// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestScanWebSocketURLLength(t *testing.T) {
	for _, scheme := range []string{"ws", "wss"} {
		for _, text := range []string{"a", "é", "%61"} {
			for _, delta := range []int{-1, 0, 1} {
				t.Run(fmt.Sprintf("%s/%s/%d", scheme, text, delta), func(t *testing.T) {
					raw := scheme + "://api.vendor.example/" + strings.Repeat(text, 20)
					cfg := testConfig()
					cfg.FetchProxy.Monitoring.MaxURLLength = len(raw) - delta
					cfg.FetchProxy.Monitoring.EntropyThreshold = 0
					s := MustNew(cfg)
					defer s.Close()
					got := s.ScanWebSocket(t.Context(), raw)
					if delta > 0 {
						want := fmt.Sprintf("URL length %d exceeds maximum %d", len(raw), len(raw)-delta)
						if got.Allowed || got.Scanner != ScannerLength || got.Reason != want {
							t.Fatalf("result=%+v want=%s", got, want)
						}
					} else if !got.Allowed {
						t.Fatalf("target at/below byte ceiling refused: %+v", got)
					}
				})
			}
		}
	}
}

func TestScanWebSocketURLPolicy(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxURLLength = 0
	s := MustNew(cfg)
	defer s.Close()
	for _, tc := range []struct{ raw, layer string }{
		{"ws://api.vendor.example", ScannerAll},
		{"wss://api.vendor.example", ScannerAll},
		{"https://api.vendor.example/", ScannerScheme},
		{"ws://api.vendor.example/%zz", ScannerParser},
		{"ws://127.0.0.2/", ScannerAll},
		{"ws://169.254.169.254/", ScannerCoreSSRF},
		{"wss://api.vendor.example/?key=" + "AKIA" + "Q9W8E7R6T5Y4U3I2", ScannerCoreDLP},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got := s.ScanWebSocket(t.Context(), tc.raw)
			if got.Scanner != tc.layer || got.Allowed != (tc.layer == ScannerAll) {
				t.Fatalf("result=%+v want layer=%s", got, tc.layer)
			}
		})
	}
	if got := s.Scan(t.Context(), "ws://api.vendor.example/"); got.Allowed || got.Scanner != ScannerScheme {
		t.Fatalf("HTTP scanner accepted WebSocket scheme: %+v", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if got := s.ScanWebSocket(ctx, "ws://api.vendor.example/"); got.Allowed || got.Scanner != ScannerContext {
			t.Fatalf("unavailable context=%+v", got)
		}
	}
}
