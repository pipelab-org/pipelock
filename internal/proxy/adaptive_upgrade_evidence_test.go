// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// A warning that adaptive enforcement upgrades to a block is a refused
// request. Session evidence must record it as a block, not as a delivered
// observation, on every URL entry point.
func TestAdaptiveUpgradedWarningRecordedAsBlock(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer backend.Close()
	for _, transport := range []string{"fetch", "forward", "connect", "websocket"} {
		for _, level := range []int{1, 2, 3} {
			t.Run(fmt.Sprintf("%s/level=%d", transport, level), func(t *testing.T) {
				var proxyAddr string
				var p *Proxy
				var cleanup func()
				target := backend.URL
				if transport == "websocket" {
					var closeBackend func()
					target, closeBackend = wsEchoServer(t)
					defer closeBackend()
					target = "ws://" + target
					proxyAddr, p, cleanup = setupWSProxyDefaultWithProxy(t, adaptiveWarnTransportConfig)
				} else {
					proxyAddr, p, cleanup = setupForwardProxyWithInstance(t, adaptiveWarnTransportConfig)
				}
				defer cleanup()
				parsedTarget, err := url.Parse(target)
				if err != nil {
					t.Fatal(err)
				}
				// Independent enforced evidence has already escalated this
				// destination, so upgrade_warn turns the next warning into a block.
				rec := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyLoopback)
				scope := adaptiveScopeForHost(parsedTarget.Hostname())
				for range 50 {
					if rec.EffectiveEscalationLevel(scope) >= level {
						break
					}
					rec.RecordScopedSignal(scope, session.SignalBlock, adaptiveTestThreshold)
				}
				if got := rec.EffectiveEscalationLevel(scope); got != level {
					t.Fatalf("setup level=%d, want %d", got, level)
				}
				scoreBefore := rec.ThreatScore()

				var refused bool
				switch transport {
				case "websocket":
					conn, err := dialWSConnToTarget(proxyAddr, target)
					if err == nil {
						_ = conn.Close()
					}
					refused = err != nil
				case "connect":
					conn := dialProxy(t, proxyAddr)
					defer func() { _ = conn.Close() }()
					if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", parsedTarget.Host, parsedTarget.Host); err != nil {
						t.Fatal(err)
					}
					resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
					if err != nil {
						t.Fatal(err)
					}
					_ = resp.Body.Close()
					refused = resp.StatusCode == http.StatusForbidden
				default:
					client := http.DefaultClient
					reqURL := "http://" + proxyAddr + "/fetch?url=" + url.QueryEscape(target)
					if transport == "forward" {
						parsedProxy, err := url.Parse("http://" + proxyAddr)
						if err != nil {
							t.Fatal(err)
						}
						tr := &http.Transport{Proxy: http.ProxyURL(parsedProxy)}
						defer tr.CloseIdleConnections()
						client = &http.Client{Transport: tr}
						reqURL = target
					}
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, reqURL, nil)
					if err != nil {
						t.Fatal(err)
					}
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					_ = resp.Body.Close()
					refused = resp.StatusCode == http.StatusForbidden
				}
				if !refused {
					t.Fatal("escalated destination delivered an upgraded warning")
				}

				if got := rec.ThreatScore(); got != scoreBefore {
					t.Fatalf("upgraded warning changed score: before=%v after=%v", scoreBefore, got)
				}
				events := rec.RecentEvents()
				if len(events) == 0 {
					t.Fatal("refused finding left no session evidence")
				}
				for _, event := range events {
					if event.Kind != config.ActionBlock || event.Severity != config.SeverityCritical {
						t.Fatalf("refused request recorded as an observation: %+v", event)
					}
				}
			})
		}
	}
}

// Evidence follows the caller's adaptive decision at the returned level:
// entropy-only findings are never upgraded but block_all still refuses them.
func TestObservedFindingEvidenceFollowsAdaptiveLevel(t *testing.T) {
	cases := []struct {
		name     string
		level    int
		entropy  bool
		wantKind string
	}{
		{name: "clean_level_ordinary", level: 0, wantKind: "anomaly"},
		{name: "elevated_ordinary", level: 1, wantKind: config.ActionBlock},
		{name: "elevated_entropy", level: 1, entropy: true, wantKind: "anomaly"},
		{name: "critical_entropy_block_all", level: 3, entropy: true, wantKind: config.ActionBlock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.SessionProfiling.Enabled = true
			cfg.AdaptiveEnforcement.Enabled = true
			cfg.ApplyDefaults()
			sm := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, nil)
			t.Cleanup(sm.Close)
			p := &Proxy{metrics: metrics.New()}
			p.sessionMgrPtr.Store(sm)
			const host = "api.vendor.example"
			scope := adaptiveScopeForHost(host)
			sess := sm.GetOrCreate("192.0.2.1")
			for range 50 {
				if sess.EffectiveEscalationLevel(scope) >= tc.level {
					break
				}
				sess.RecordScopedSignal(scope, session.SignalBlock, cfg.AdaptiveEnforcement.EscalationThreshold)
			}
			if got := sess.EffectiveEscalationLevel(scope); got != tc.level {
				t.Fatalf("setup level=%d, want %d", got, tc.level)
			}
			result := scanner.Result{Allowed: false, Scanner: scanner.ScannerBlocklist, Reason: "configured destination finding"}
			if tc.entropy {
				result = scanner.Result{Allowed: false, Scanner: scanner.ScannerEntropy, Reason: "entropy finding", Class: scanner.ClassHeuristicEntropy}
			}
			sr := p.recordSessionActivityWithUserAgent(sessionActivityOptions{
				ClientIP: "192.0.2.1", Hostname: host, RequestID: "observed-finding",
				Result: result, ObserveOnly: true, Config: cfg, Logger: audit.NewNop(),
			})
			if sr.Level != tc.level {
				t.Fatalf("returned level=%d, want %d", sr.Level, tc.level)
			}
			events := sess.RecentEvents()
			if len(events) != 1 || events[0].Kind != tc.wantKind || events[0].Detail != result.Reason {
				t.Fatalf("events=%+v, want one %s for %q", events, tc.wantKind, result.Reason)
			}
		})
	}
}
