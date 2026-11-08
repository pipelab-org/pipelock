// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestWatchDeferredConfigSnapshot(t *testing.T) {
	if deferredWatchConfig(nil) != nil {
		t.Fatal("nil snapshot changed")
	}
	for _, enforce := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.Enforce = &enforce
		if deferredWatchConfig(cfg) != cfg {
			t.Fatal("ordinary snapshot copied")
		}
		cfg.WatchOnly = true
		hash := cfg.CanonicalPolicyHash()
		got := deferredWatchConfig(cfg)
		if got == cfg || got.WatchOnly || got.EnforceEnabled() != enforce || !cfg.WatchOnly || cfg.CanonicalPolicyHash() != hash {
			t.Fatal("effective snapshot mutated configured policy")
		}
		expected := cfg.Clone()
		expected.WatchOnly = false
		if got.CanonicalPolicyHash() != expected.CanonicalPolicyHash() || got.CanonicalPolicyHash() == hash {
			t.Fatal("effective policy hash does not describe scoped config")
		}
	}
}

func TestWatchDeferredSurfaceParity(t *testing.T) {
	for _, transport := range []string{"connect", "intercept", "reverse", "websocket"} {
		for _, enforce := range []bool{false, true} {
			for _, kind := range []string{"core", "operator", "blocklist"} {
				surface := "url"
				if transport == "connect" {
					surface = "header"
				}
				t.Run(fmt.Sprintf("%s/enforce=%t/%s", transport, enforce, kind), func(t *testing.T) {
					normal := driveAuditFloor(t, transport, kind, surface, enforce, false)
					watched := driveAuditFloor(t, transport, kind, surface, enforce, true)
					if normal.blocked != watched.blocked || normal.hits != watched.hits {
						t.Fatalf("normal=%+v watch=%+v", normal, watched)
					}
					if kind == "core" && (!watched.blocked || watched.hits != 0) {
						t.Fatalf("credential escaped: %+v", watched)
					}
					if kind == "operator" && !enforce && (watched.blocked || (watched.hits == 0 && transport != "connect" && transport != "websocket")) {
						t.Fatalf("ordinary audit traffic refused: %+v", watched)
					}
				})
			}
		}
	}
}

func TestWatchDeferredRequestReceiptConfig(t *testing.T) {
	cfg := config.Defaults()
	cfg.WatchOnly = true
	for _, tc := range []struct {
		method, target string
		watch          bool
	}{
		{http.MethodGet, "http://api.vendor.example/", true},
		{http.MethodGet, "/fetch?url=https://api.vendor.example", true},
		{http.MethodConnect, "api.vendor.example:443", false},
		{http.MethodGet, "/ws?url=wss://api.vendor.example", false},
	} {
		req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.target, nil)
		if got := watchRequestConfig(cfg, req); got.WatchOnly != tc.watch {
			t.Errorf("%s %s: watch=%t", tc.method, tc.target, got.WatchOnly)
		}
	}
}

func TestWatchDeferredCEEAdmissionMode(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		for _, admittedWatch := range []bool{false, true} {
			t.Run(fmt.Sprintf("enforce=%t/watch=%t", enforce, admittedWatch), func(t *testing.T) {
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.Enforce = &enforce
				cfg.WatchOnly = true
				cfg.CrossRequestDetection.Enabled = true
				cfg.CrossRequestDetection.Action = config.ActionBlock
				cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
				cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 65536
				cfg.CrossRequestDetection.EntropyBudget.Enabled = true
				cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 1
				cfg.CrossRequestDetection.EntropyBudget.WindowMinutes = 5
				cfg.CrossRequestDetection.EntropyBudget.Action = config.ActionBlock
				p, err := New(cfg, audit.NewNop(), scanner.MustNew(cfg), metrics.New())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				for _, watch := range []bool{true, false, true, true} {
					next := cfg.Clone()
					next.WatchOnly = watch
					if !p.Reload(next, scanner.MustNew(next)) {
						t.Fatal("reload refused")
					}
					got := p.admitCurrentCEE(t.Context(), ceeAdmitRequest{WatchOnly: admittedWatch, Outbound: []byte("scope-probe-12345678"), TargetURL: "https://api.vendor.example", ClientIP: "127.0.0.1", IncludeFragments: true})
					wantBlock := enforce && (!admittedWatch || !watch)
					if got.Result.Blocked != wantBlock || !got.Result.EntropyHit {
						t.Fatalf("watch=%t got=%+v wantBlock=%t", watch, got.Result, wantBlock)
					}
					effective := next
					if !admittedWatch {
						effective = deferredWatchConfig(next)
					}
					if got.PolicyHash != effective.CanonicalPolicyHash() {
						t.Fatal("CEE evidence uses different policy")
					}
				}
			})
		}
	}
}

func TestWatchDeferredWebSocketFrames(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		for _, kind := range []string{"core", "operator"} {
			t.Run(fmt.Sprintf("enforce=%t/%s", enforce, kind), func(t *testing.T) {
				normal := driveAuditFloor(t, "websocket", kind, "body", enforce, false)
				watched := driveAuditFloor(t, "websocket", kind, "body", enforce, true)
				if normal.blocked != watched.blocked || normal.hits != watched.hits {
					t.Fatalf("normal=%+v watch=%+v", normal, watched)
				}
				if kind == "core" && !watched.blocked {
					t.Fatalf("credential frame released: %+v", watched)
				}
				if kind == "operator" && !enforce && watched.blocked {
					t.Fatalf("audit frame refused: %+v", watched)
				}
			})
		}
	}
}
