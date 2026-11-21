// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"errors"
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

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

func TestV3RawHandshakeFailure(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("websocket/required=%t", required), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, TransportWS, required, nil)
			var hits atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(upstream.Close)
			target := "ws" + strings.TrimPrefix(upstream.URL, "http")
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ws?url="+target, nil)
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			req.Header.Set("Sec-WebSocket-Version", "13")
			// ResponseRecorder doesn't implement Hijacker.
			observer := httptest.NewRecorder()
			p.handleWebSocket(observer, req)
			if hits.Load() != 0 || observer.Code == http.StatusSwitchingProtocols {
				t.Fatalf("failed upgrade released an effect: status=%d hits=%d", observer.Code, hits.Load())
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			assertHandshakeOutcome(t, dir, boundaryUpstreamSend, "not_released")
		})
		t.Run(fmt.Sprintf("connect/required=%t", required), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, TransportConnect, required, nil)
			target, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = target.Close() })
			upstreamBytes := make(chan int, 1)
			go func() {
				conn, err := target.Accept()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				payload, _ := io.ReadAll(conn)
				upstreamBytes <- len(payload)
			}()
			client, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			t.Cleanup(func() { _ = client.Close() })
			conn := &v3BrokenHandshakeConn{Conn: client}
			w := &v3HandshakeHijacker{ResponseRecorder: httptest.NewRecorder(), conn: conn}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, target.Addr().String(), nil)
			p.handleConnect(w, req)
			select {
			case n := <-upstreamBytes:
				if n != 0 {
					t.Fatalf("relay sent %d bytes after failed CONNECT handshake", n)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("upstream observer did not finish")
			}
			if conn.writes != 1 {
				t.Fatalf("CONNECT write attempts = %d, want 1", conn.writes)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			assertHandshakeOutcome(t, dir, boundaryDownstreamDelivery, "attempt_unknown")
		})
	}
}

func assertHandshakeOutcome(t *testing.T, dir, boundary, outcome string) {
	t.Helper()
	var actionID string
	intents, outcomes := 0, 0
	for _, action := range readV3TransportActions(t, dir) {
		if action.EffectBoundary != boundary {
			continue
		}
		if action.Phase == "intent" {
			actionID = action.ActionID
			intents++
		}
		if action.Phase == "outcome" {
			if action.ActionID != actionID || action.OutcomeClass != outcome {
				t.Fatalf("unexpected outcome at %s: %+v", boundary, action)
			}
			outcomes++
		}
	}
	if intents != 1 || outcomes != 1 {
		t.Fatalf("%s has %d intents and %d outcomes, want one each", boundary, intents, outcomes)
	}
}

type v3BrokenHandshakeConn struct {
	net.Conn
	writes int
}

func (c *v3BrokenHandshakeConn) Write([]byte) (int, error) {
	c.writes++
	return 0, errors.New("handshake write failed")
}

type v3HandshakeHijacker struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w *v3HandshakeHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(strings.NewReader("example")), bufio.NewWriter(w.conn)), nil
}

func TestV3ReverseUpgradeRefusal(t *testing.T) {
	for _, required := range []bool{false, true} {
		for _, passThrough := range []bool{false, true} {
			t.Run(fmt.Sprintf("required=%t/pass_through=%t", required, passThrough), func(t *testing.T) {
				p, writer, dir, keys := newTestV3HTTPProxy(t, TransportReverse, required, nil)
				var upgrades atomic.Int64
				backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					conn, _, _, err := ws.UpgradeHTTP(r, w)
					if err == nil {
						upgrades.Add(1)
						_ = conn.Close()
					}
				}))
				t.Cleanup(backend.Close)
				target, err := url.Parse(backend.URL)
				if err != nil {
					t.Fatal(err)
				}
				reverse := NewReverseProxy(target, p.ConfigPtr(), p.ScannerPtr(), audit.NewNop(), metrics.New(), nil, nil, nil)
				reverse.SetOwnerProxy(p)
				if passThrough {
					// Exercise delivery when response scanning leaves the upgrade body intact.
					reverse.proxy.ModifyResponse = nil
				}
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				req.Header.Set("Sec-WebSocket-Version", "13")
				observer := httptest.NewRecorder()
				reverse.ServeHTTP(observer, req)
				if observer.Code != http.StatusBadGateway || upgrades.Load() != 1 {
					t.Fatalf("expected one upstream upgrade and a downstream gateway error, got %d/%d",
						upgrades.Load(), observer.Code)
				}
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
				result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
				if err != nil || result.Verdict != "VALID" {
					t.Fatalf("verification: %+v (%v)", result, err)
				}
				if passThrough {
					assertHandshakeOutcome(t, dir, boundaryDownstreamDelivery, "not_released")
					return
				}
				for _, action := range readV3TransportActions(t, dir) {
					if action.EffectBoundary == boundaryDownstreamDelivery {
						t.Fatalf("synthetic gateway error was associated with an upgrade: %+v", action)
					}
				}
			})
		}
	}
}
