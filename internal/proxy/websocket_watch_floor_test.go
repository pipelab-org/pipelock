// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestWatchWebSocketNegotiationFloor(t *testing.T) {
	for _, header := range []string{"Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
		t.Run(header, func(t *testing.T) {
			backend, closeBackend := wsEchoServer(t)
			defer closeBackend()
			addr, cleanup := setupWSProxy(t, func(cfg *config.Config) { cfg.WatchOnly = true })
			defer cleanup()
			value := "agent-stream"
			if header == "Sec-WebSocket-Extensions" {
				value = "permessage-deflate"
			}
			conn, err := dialWSConnWithHeader(addr, backend, http.Header{header: []string{value}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(testWSHello)); err != nil {
				t.Fatal(err)
			}
			if got, _, err := wsutil.ReadServerData(conn); err != nil || string(got) != testWSHello {
				t.Fatalf("benign frame: %q %v", got, err)
			}
			credential := "AKIA" + "IOSFODNN7" + testWSExample
			if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(credential)); err != nil {
				t.Fatal(err)
			}
			if got, _, err := wsutil.ReadServerData(conn); err == nil {
				t.Fatalf("negotiation bypass forwarded credential: %q", got)
			}
		})
	}
}

func TestWatchWebSocketAccessFloor(t *testing.T) {
	for _, reason := range []string{"disabled", "capacity", "receipts"} {
		t.Run(reason, func(t *testing.T) {
			backend, closeBackend := wsEchoServer(t)
			defer closeBackend()
			addr, cleanup := setupWSProxy(t, func(cfg *config.Config) {
				cfg.WatchOnly = true
				cfg.WebSocketProxy.Enabled = reason != "disabled"
				cfg.FlightRecorder.RequireReceipts = reason == "receipts"
			})
			defer cleanup()
			if reason == "capacity" {
				sem := getWSSemaphore(128)
				held := 0
				for sem.TryAcquire() {
					held++
				}
				defer func() {
					for range held {
						sem.Release()
					}
				}()
			}
			conn, err := dialWSConn(addr, backend)
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil {
				t.Fatalf("%s guard allowed watch-only handshake", reason)
			}
		})
	}
}

func TestWatchWebSocketHeaderAllowlist(t *testing.T) {
	cfg := config.Defaults()
	cfg.WatchOnly = true
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://proxy.example/ws", nil)
	req.Header.Set("Proxy-Authorization", "Basic proxy-only")
	req.Header.Set("X-Private-Header", "local-only")
	req.Header.Set("Cookie", "session=private")
	req.Header.Set("Authorization", "Bearer upstream")
	target, err := url.Parse("ws://api.vendor.example/socket")
	if err != nil {
		t.Fatal(err)
	}
	got := (&Proxy{}).buildWSForwardHeaders(req, target, cfg, nil)
	for _, name := range []string{"Proxy-Authorization", "X-Private-Header", "Cookie"} {
		if got.Get(name) != "" {
			t.Errorf("unexpected forwarded %s", name)
		}
	}
	if got.Get("Authorization") != "Bearer upstream" {
		t.Fatal("upstream authorization lost")
	}
}

func TestWatchWebSocketAdmittedConfig(t *testing.T) {
	for _, watch := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.WatchOnly = watch
		next := *cfg
		next.WatchOnly = !watch
		p := &Proxy{}
		p.cfgPtr.Store(&next)
		relay := &wsRelay{proxy: p, cfg: cfg}
		if relay.watchOnly() != watch {
			t.Fatalf("admitted watch=%v replaced by live mode", watch)
		}
	}
}

func TestWatchWebSocketOutboundInspectionFloor(t *testing.T) {
	for _, watch := range []bool{false, true} {
		for _, shape := range []string{"oversized", "fragmented", "invalid_utf8", "binary"} {
			t.Run(shape+map[bool]string{false: "/audit", true: "/watch"}[watch], func(t *testing.T) {
				backend, closeBackend := wsEchoServer(t)
				defer closeBackend()
				addr, cleanup := setupWSProxy(t, func(cfg *config.Config) {
					cfg.WatchOnly = watch
					off := false
					cfg.Enforce = &off
					cfg.WebSocketProxy.MaxMessageBytes = 64
					cfg.WebSocketProxy.AllowBinaryFrames = false
				})
				defer cleanup()
				conn := dialWS(t, addr, backend)
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				switch shape {
				case "oversized":
					_ = wsutil.WriteClientMessage(conn, ws.OpText, bytes.Repeat([]byte("padding "), 20))
				case "fragmented":
					writeMaskedClientFrame(t, conn, false, ws.OpText, []byte(strings.Repeat("a", 40)))
					writeMaskedClientFrame(t, conn, true, ws.OpContinuation, []byte(strings.Repeat("b", 40)))
				case "invalid_utf8":
					_ = wsutil.WriteClientMessage(conn, ws.OpText, []byte{0xff, 0xfe})
				case "binary":
					_ = wsutil.WriteClientMessage(conn, ws.OpBinary, []byte("uninspectable"))
				}
				if got, _, err := wsutil.ReadServerData(conn); err == nil {
					t.Fatalf("outbound inspection guard released %q", got)
				}
			})
		}
	}
}

func TestWatchWebSocketUnavailableScanner(t *testing.T) {
	backend, closeBackend := wsEchoServer(t)
	defer closeBackend()
	addr, p, cleanup := setupWSProxyDefaultWithProxy(t, func(cfg *config.Config) { cfg.WatchOnly = true })
	defer cleanup()
	p.scannerPtr.Load().Close()
	conn, err := dialWSConnWithHeader(addr, backend, http.Header{"Sec-WebSocket-Protocol": []string{"agent-stream"}})
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("unavailable scanner allowed watch-only connection")
	}
}

func TestWatchWebSocketMalformedNegotiationDoesNotDial(t *testing.T) {
	backend, handshakes, _, _ := websocketBoundaryBackend(t)
	addr, cleanup := setupWSProxy(t, func(cfg *config.Config) { cfg.WatchOnly = true })
	defer cleanup()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/ws?url=ws://"+backend, nil)
	req.RequestURI = ""
	req.Header.Set("Sec-WebSocket-Protocol", "agent-stream")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if handshakes.Load() != 0 {
		t.Fatalf("malformed client initiated %d upstream handshakes", handshakes.Load())
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", response.StatusCode)
	}
}
