// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
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
		<-done
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
	if status, body := l.send("overflow", "read_file"); status != http.StatusServiceUnavailable || l.hits.Load() != before || !strings.Contains(body, "session capacity") {
		t.Fatalf("protected registry capacity: %d upstream=%d %s", status, l.hits.Load()-before, body)
	}
	record.Store(false)
	if !strings.Contains(events.String(), `"event":"blocked"`) || !strings.Contains(events.String(), `"scanner":"mcp_protocol"`) {
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
