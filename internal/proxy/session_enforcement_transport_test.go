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
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestSessionEnforcementHTTPFlood(t *testing.T) {
	for _, transport := range []string{TransportFetch, TransportForward, TransportReverse} {
		t.Run(transport, func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
			cfg.Airlock.Enabled = false
			cfg.SessionProfiling.MaxSessions = 2
			cfg.AdaptiveEnforcement.Levels.Critical.BlockAll = ptrBool(true)
			var hits atomic.Int32
			rp, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				_, _ = io.WriteString(w, "ordinary control response")
			})
			send := func(ip string) *httptest.ResponseRecorder {
				target := upstream.String()
				if transport == TransportFetch {
					target = "http://proxy.example/fetch?url=" + url.QueryEscape(target)
				}
				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
				r.RemoteAddr = ip + ":12345"
				w := httptest.NewRecorder()
				switch transport {
				case TransportFetch:
					p.handleFetch(w, r)
				case TransportForward:
					p.handleForwardHTTP(w, r)
				case TransportReverse:
					rp.ServeHTTP(w, r)
				}
				return w
			}
			if w := send(airlockAdmissionClient); w.Code != http.StatusOK || hits.Load() != 1 {
				t.Fatalf("positive control: status=%d body=%s", w.Code, w.Body.String())
			}
			sm := p.sessionMgrPtr.Load()
			victim := sm.SessionByKey(airlockAdmissionClient)
			victim.mu.Lock()
			victim.globalSignalsAuthoritative = true
			victim.escalationLevel = 5
			victim.atBlockAll = true
			victim.lastEscalation = time.Now()
			victim.mu.Unlock()
			other := sm.GetOrCreate("protected-other")
			other.ObserveRisk(session.RiskObservation{Source: session.TaintSourceRef{Level: session.TaintExternalUntrusted}})
			for i := range 10 {
				w := send(fmt.Sprintf("192.0.2.%d", i+100))
				if w.Code != http.StatusServiceUnavailable || w.Header().Get(blockreason.HeaderLayer) != sessionCapacityLayer {
					t.Fatalf("flood admitted new key: status=%d body=%s", w.Code, w.Body.String())
				}
			}
			if w := send(airlockAdmissionClient); w.Code != http.StatusForbidden || hits.Load() != 1 {
				t.Fatalf("victim escaped after flood: status=%d upstream=%d body=%s", w.Code, hits.Load(), w.Body.String())
			}
			if sm.SessionByKey(airlockAdmissionClient) != victim || sm.Len() != cfg.SessionProfiling.MaxSessions {
				t.Fatal("flood lost operator lookup or store bound")
			}
			metric := `scanner="session_capacity"`
			if transport == TransportReverse {
				metric = `reason="session_capacity"`
			}
			if !scrapeMetric(t, p.metrics, metric) {
				t.Fatal("capacity refusals were not counted")
			}
		})
	}
}

func TestSessionEnforcementWebSocketFlood(t *testing.T) {
	cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
	cfg.Airlock.Enabled = false
	cfg.WebSocketProxy.Enabled = true
	cfg.SessionProfiling.MaxSessions = 1
	cfg.AdaptiveEnforcement.Levels.Critical.BlockAll = ptrBool(true)
	var hits atomic.Int32
	_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = wsutil.WriteServerMessage(conn, ws.OpText, []byte("ordinary control response"))
	})
	listener := httptest.NewServer(http.HandlerFunc(p.handleWebSocket))
	defer listener.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	send := func() (int, ws.OpCode, string) {
		t.Helper()
		target := "ws" + strings.TrimPrefix(upstream.String(), "http")
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, listener.URL+"/ws?url="+url.QueryEscape(target), nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBs"+"ZSBub25jZQ==")
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusSwitchingProtocols {
			body, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, 0, string(body)
		}
		header, err := ws.ReadHeader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		body := make([]byte, header.Length)
		if _, err := io.ReadFull(resp.Body, body); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, header.OpCode, string(body)
	}
	if status, op, body := send(); status != http.StatusSwitchingProtocols || op != ws.OpText || hits.Load() != 1 {
		t.Fatalf("positive control: status=%d op=%d body=%q", status, op, body)
	}
	sm := p.sessionMgrPtr.Load()
	victim := sm.SessionByKey(adaptiveSessionKeyLoopback)
	victim.mu.Lock()
	victim.globalSignalsAuthoritative = true
	victim.escalationLevel = 5
	victim.atBlockAll = true
	victim.lastEscalation = time.Now()
	victim.mu.Unlock()
	for i := range 10 {
		if sm.GetOrCreate(fmt.Sprintf("flood-%d", i)) != nil {
			t.Fatal("flood discarded victim")
		}
	}
	status, op, body := send()
	if (status != http.StatusForbidden && op != ws.OpClose) || hits.Load() != 1 {
		t.Fatalf("victim escaped: status=%d op=%d upstream=%d body=%q", status, op, hits.Load(), body)
	}
	// A second client has no admission state while the victim stays protected.
	other := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://proxy.example/ws?url="+url.QueryEscape("ws"+strings.TrimPrefix(upstream.String(), "http")), nil)
	other.RemoteAddr = "192.0.2.100:12345"
	other.Header.Set("Connection", "Upgrade")
	other.Header.Set("Upgrade", "websocket")
	other.Header.Set("Sec-WebSocket-Version", "13")
	other.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBs"+"ZSBub25jZQ==")
	// Required receipts put capacity refusal before the protocol upgrade.
	strict := p.CurrentConfig().Clone()
	strict.FlightRecorder.RequireReceipts = true
	p.cfgPtr.Store(strict)
	w := httptest.NewRecorder()
	p.handleWebSocket(w, other)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get(blockreason.HeaderLayer) != sessionCapacityLayer || hits.Load() != 1 {
		t.Fatalf("new WebSocket client: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestSessionEnforcementMCPListenerFloodAndActivity(t *testing.T) {
	for _, tainted := range []bool{false, true} {
		t.Run(fmt.Sprintf("taint=%t", tainted), func(t *testing.T) {
			cfg := adaptiveConfig()
			cfg.Taint.Enabled = tainted
			cfg.SessionProfiling.MaxSessions = 2
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			sm := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, nil)
			t.Cleanup(sm.Close)
			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ordinary result"}]}}`)
			}))
			defer upstream.Close()
			ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				done <- mcp.RunHTTPListenerProxy(ctx, ln, upstream.URL, io.Discard, mcp.MCPProxyOpts{
					Scanner: sc, Store: sm.AsStore(), AdaptiveCfg: &cfg.AdaptiveEnforcement, TaintCfg: &cfg.Taint,
					ListenerPrincipalResolver: func(r *http.Request) (mcp.ListenerPrincipal, error) {
						// Trusted authentication fixture, not a production header identity.
						return mcp.ListenerPrincipal{Provider: "test", Subject: r.Header.Get("X-Test-Subject")}, nil
					},
				})
			}()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			client := &http.Client{Timeout: 5 * time.Second}
			send := func(subject, tool string) (int, string) {
				t.Helper()
				body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`, tool)
				r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+ln.Addr().String()+"/", strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Mcp-Protocol-Version", "2026-07-28")
				r.Header.Set("Mcp-Method", "tools/call")
				r.Header.Set("Mcp-Name", tool)
				r.Header.Set("X-Test-Subject", subject)
				resp, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				out, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				return resp.StatusCode, string(out)
			}
			if status, body := send("victim", "read_file"); status != http.StatusOK || strings.Contains(body, `"error"`) || hits.Load() != 1 {
				t.Fatalf("positive control: status=%d body=%s", status, body)
			}
			snapshots := sm.Snapshot()
			if len(snapshots) != 1 {
				t.Fatalf("sessions=%+v", snapshots)
			}
			victim := sm.SessionByKey(snapshots[0].Key)
			// Committed listener calls must refresh the shared recorder, not only
			// the request-local baseline recorder.
			victim.mu.Lock()
			victim.lastActivity = time.Now().Add(-2 * time.Duration(cfg.SessionProfiling.SessionTTLMinutes) * time.Minute)
			victim.mu.Unlock()
			if status, body := send("victim", "read_file"); status != http.StatusOK || strings.Contains(body, `"error"`) {
				t.Fatalf("active read: %d %s", status, body)
			}
			sm.cleanup()
			if sm.SessionByKey(victim.key) != victim || victim.BaselineMetrics().ToolCalls != 0 {
				t.Fatal("active listener lost shared session activity")
			}
			if tainted {
				if !victim.RiskSnapshot().HasPolicyTaint() {
					t.Fatal("external result did not taint victim")
				}
			} else {
				victim.mu.Lock()
				victim.globalSignalsAuthoritative = true
				victim.escalationLevel = 5
				victim.atBlockAll = true
				victim.lastEscalation = time.Now()
				victim.mu.Unlock()
			}
			other := sm.GetOrCreate("protected-other")
			other.ObserveRisk(session.RiskObservation{Source: session.TaintSourceRef{Level: session.TaintExternalHostile}})
			before := hits.Load()
			for i := range 10 {
				status, body := send(fmt.Sprintf("flood-%d", i), "read_file")
				if status != http.StatusServiceUnavailable {
					t.Fatalf("flood admission: status=%d body=%s", status, body)
				}
			}
			if _, body := send("victim", "exec"); !strings.Contains(body, `"error"`) || hits.Load() != before {
				t.Fatalf("victim escaped: upstream=%d body=%s", hits.Load(), body)
			}
			if sm.SessionByKey(victim.key) != victim || sm.Len() != cfg.SessionProfiling.MaxSessions {
				t.Fatal("listener victim became orphaned or store exceeded cap")
			}
		})
	}
}
