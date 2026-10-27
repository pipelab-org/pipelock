// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type capacityListener struct {
	t         *testing.T
	addr      string
	hits      *atomic.Int32
	client    *http.Client
	principal bool
	logs      *refusalLogCapture
}

func startCapacityListener(t *testing.T, maxSessions int, principal bool, configure func(*mcp.MCPProxyOpts)) (*capacityListener, *SessionManager) {
	t.Helper()
	cfg := adaptiveConfig()
	cfg.Taint.Enabled = true
	cfg.SessionProfiling.MaxSessions = maxSessions
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	sm := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, nil)
	t.Cleanup(sm.Close)
	hits := &atomic.Int32{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ordinary result"}]}}`)
	}))
	t.Cleanup(upstream.Close)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	logs := &refusalLogCapture{}
	go func() {
		opts := mcp.MCPProxyOpts{
			Scanner: sc, Store: sm.AsStore(), AdaptiveCfg: &cfg.AdaptiveEnforcement, TaintCfg: &cfg.Taint,
		}
		if principal {
			opts.ListenerBearerToken = "capacity-test-bearer"
		}
		if configure != nil {
			configure(&opts)
		}
		done <- mcp.RunHTTPListenerProxy(ctx, ln, upstream.URL, logs, opts)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("RunHTTPListenerProxy: %v", err)
		}
	})
	return &capacityListener{t: t, addr: ln.Addr().String(), hits: hits, client: &http.Client{Timeout: 5 * time.Second}, principal: principal, logs: logs}, sm
}

func (l *capacityListener) send(sessionID, tool string) (int, string) {
	l.t.Helper()
	return l.sendBody(sessionID, fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, tool))
}

func (l *capacityListener) sendBody(sessionID, body string) (int, string) {
	l.t.Helper()
	r, err := http.NewRequestWithContext(l.t.Context(), http.MethodPost, "http://"+l.addr+"/", strings.NewReader(body))
	if err != nil {
		l.t.Fatal(err)
	}
	if l.principal {
		r.Header.Set("Authorization", "Bearer capacity-test-bearer")
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Mcp-Session-Id", sessionID)
	resp, err := l.client.Do(r)
	if err != nil {
		l.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		l.t.Fatal(err)
	}
	return resp.StatusCode, string(out)
}

// Exercise the default unauthenticated partition as well as the authenticated
// partition. Routing IDs cannot multiply a verified principal's state.
func TestSessionEnforcementListenerRegistryFlood(t *testing.T) {
	for _, principal := range []bool{false, true} {
		t.Run(fmt.Sprintf("principal=%t", principal), func(t *testing.T) {
			l, sm := startCapacityListener(t, config.Defaults().SessionProfiling.MaxSessions, principal, nil)
			if status, body := l.send("victim", "read_file"); status != http.StatusOK || strings.Contains(body, `"error"`) {
				t.Fatalf("positive control: %d %s", status, body)
			}
			if _, body := l.send("victim", "exec"); !strings.Contains(body, `"error"`) {
				t.Fatal("tainted victim was not denied before flood")
			}
			// Rotate past the registry bound, as in the supplied listener reproduction.
			for i := range 4100 {
				status, body := l.sendBody(fmt.Sprintf("flood-%d", i), `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
				if status != http.StatusOK {
					t.Fatalf("notification %d: %d %s", i, status, body)
				}
			}
			before := l.hits.Load()
			if status, body := l.send("victim", "exec"); !strings.Contains(body, `"error"`) || l.hits.Load() != before {
				t.Fatalf("victim lost enforcement after registry flood: %d upstream=%d %s", status, l.hits.Load()-before, body)
			}
			if principal && sm.Len() != 1 {
				t.Fatalf("routing IDs multiplied authenticated state: %d", sm.Len())
			}
		})
	}
}

func TestSessionEnforcementListenerRegistryProtectedCapacity(t *testing.T) {
	// The source of this test bound is maxMCPListenerClients in
	// internal/mcp/mcp_http_listener_state.go, not a new product limit.
	const listenerRegistryCapacity = 4096
	events := &refusalLogCapture{}
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, events)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	dir := t.TempDir()
	emitter, rec, _ := newCoverageEmitter(t, dir)
	var record atomic.Bool
	l, sm := startCapacityListener(t, listenerRegistryCapacity+1, false, func(opts *mcp.MCPProxyOpts) {
		opts.AuditLogger = logger
		opts.ReceiptEmitterFn = func() *receipt.Emitter {
			if record.Load() {
				return emitter
			}
			return nil
		}
	})
	for i := range listenerRegistryCapacity {
		if status, body := l.send(fmt.Sprintf("protected-%d", i), "read_file"); status != http.StatusOK || strings.Contains(body, `"error"`) {
			t.Fatalf("protected client %d: %d %s", i, status, body)
		}
	}
	before := l.hits.Load()
	record.Store(true)
	if status, body := l.send("overflow", "read_file"); status != http.StatusServiceUnavailable || l.hits.Load() != before || !strings.Contains(body, "client-registry capacity exhausted (4096 clients)") || strings.Contains(body, "increase max_sessions") {
		t.Fatalf("protected registry capacity: %d upstream=%d %s", status, l.hits.Load()-before, body)
	}
	record.Store(false)
	if !strings.Contains(events.String(), `"event":"blocked"`) || !strings.Contains(events.String(), `"scanner":"mcp_protocol"`) || !strings.Contains(events.String(), `"block_class":"protective"`) || !strings.Contains(events.String(), "client-registry capacity exhausted (4096 clients)") {
		t.Fatalf("capacity audit missing: %s", events.String())
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	receipts := extractReceiptsFromDir(t, dir)
	if len(receipts) != 1 || receipts[0].ActionRecord.Layer != sessionCapacityLayer || receipts[0].ActionRecord.Verdict != config.ActionBlock {
		t.Fatalf("capacity receipt missing or misclassified: %+v", receipts)
	}
	if _, body := l.send("protected-0", "exec"); !strings.Contains(body, `"error"`) || l.hits.Load() != before {
		t.Fatalf("capacity erased oldest client's enforcement: %s", body)
	}
	if sm.Len() != listenerRegistryCapacity {
		t.Fatalf("capacity changed shared store count: %d", sm.Len())
	}
}

func TestSessionEnforcementListenerPrincipalRoutingCapacity(t *testing.T) {
	cfg := config.Defaults().SessionProfiling
	l, sm := startCapacityListener(t, cfg.MaxSessions, true, nil)
	for i := 0; i <= cfg.MaxSessions; i++ {
		if status, body := l.send(fmt.Sprintf("routing-%d", i), "read_file"); status != http.StatusOK || strings.Contains(body, `"error"`) {
			t.Fatalf("authenticated routing ID %d: %d %s", i, status, body)
		}
	}
	if sm.Len() != 1 || sm.GetOrCreate("198.51.100.7") == nil {
		t.Fatal("one authenticated caller exhausted cross-transport admission")
	}
}

// Document the limitation and the supported principal-auth mitigation through
// an actual listener and a second transport using the same SessionManager.
func TestSessionEnforcementListenerSharedCapacityGuidance(t *testing.T) {
	for _, principal := range []bool{false, true} {
		t.Run(fmt.Sprintf("principal=%t", principal), func(t *testing.T) {
			limit := testSessionConfig().MaxSessions
			l, sm := startCapacityListener(t, limit, principal, nil)
			for i := range limit {
				if status, body := l.send(fmt.Sprintf("routing-%d", i), "read_file"); status != http.StatusOK || strings.Contains(body, `"error"`) {
					t.Fatalf("listener client %d: %d %s", i, status, body)
				}
			}
			note := strings.Contains(l.logs.String(), "retained sessions can exhaust listener capacity")
			if note == principal {
				t.Fatalf("startup note=%t, principal=%t: %s", note, principal, l.logs.String())
			}

			cfg := adaptiveConfig()
			cfg.SessionProfiling.MaxSessions = limit
			_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "ordinary response")
			})
			original := p.sessionMgrPtr.Swap(sm)
			t.Cleanup(func() { p.sessionMgrPtr.Store(original) })
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.String()+"/control", nil)
			req.RemoteAddr = "198.51.100.7:12345"
			w := httptest.NewRecorder()
			p.handleForwardHTTP(w, req)
			want := http.StatusServiceUnavailable
			if principal {
				want = http.StatusOK
			}
			if w.Code != want {
				t.Fatalf("shared HTTP admission=%d, want %d: %s", w.Code, want, w.Body.String())
			}
			if !principal && !strings.Contains(w.Body.String(), "session capacity") {
				t.Fatalf("unexpected HTTP refusal: %s", w.Body.String())
			}
			before := l.hits.Load()
			if _, body := l.send("routing-0", "exec"); !strings.Contains(body, `"error"`) || l.hits.Load() != before {
				t.Fatal("shared-capacity check erased listener enforcement")
			}
		})
	}
}

// A clean store entry can be dropped under pressure before its listener recorder
// learns policy-relevant taint. The listener must honor that retained recorder.
func TestSessionEnforcementListenerOrphanRecorderProtected(t *testing.T) {
	for _, tc := range []struct {
		name               string
		pressure, rotation int
	}{
		{"store-pressure-then-registry-rotation", 60, 4200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, sm := startCapacityListener(t, 50, false, nil)
			const notification = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
			if status, body := l.sendBody("victim", notification); status != http.StatusOK {
				t.Fatalf("initial client: %d %s", status, body)
			}
			key := fmt.Sprintf("mcp-http-listener:%x", sha256.Sum256([]byte("victim")))
			sm.mu.RLock()
			original := sm.sessions[key]
			sm.mu.RUnlock()
			if original == nil {
				t.Fatal("positive control: clean client missing from store")
			}
			flood := func(prefix string, count int) {
				t.Helper()
				for i := range count {
					if status, body := l.sendBody(fmt.Sprintf("%s-%d", prefix, i), notification); status != http.StatusOK {
						t.Fatalf("%s notification %d: %d %s", prefix, i, status, body)
					}
				}
			}
			flood("pressure", tc.pressure)
			sm.mu.RLock()
			_, present := sm.sessions[key]
			sm.mu.RUnlock()
			if present {
				t.Fatal("pressure did not drop the clean store entry")
			}
			if status, body := l.send("victim", "read_file"); status != http.StatusOK || strings.Contains(body, `"error"`) {
				t.Fatalf("listener-held recorder control: %d %s", status, body)
			}
			if !original.RiskSnapshot().Contaminated {
				t.Fatal("listener did not taint its orphaned recorder")
			}
			assertDenied := func() {
				t.Helper()
				before := l.hits.Load()
				if status, body := l.send("victim", "exec"); status != http.StatusOK || !strings.Contains(body, `"error"`) || l.hits.Load() != before {
					t.Fatalf("client lost policy enforcement: %d upstream=%d %s", status, l.hits.Load()-before, body)
				}
			}
			assertDenied()
			flood("rotation", tc.rotation)
			assertDenied()
			t.Logf("clean store entry dropped; listener recorder enforced before and after %d session IDs (store=%d)", tc.rotation, sm.Len())
		})
	}
}
