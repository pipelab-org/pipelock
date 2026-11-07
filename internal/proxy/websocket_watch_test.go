// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

func TestWatchWebSocketResponseFrameLimit(t *testing.T) {
	for _, watch := range []bool{false, true} {
		t.Run(map[bool]string{false: "enforced", true: "watch"}[watch], func(t *testing.T) {
			payload := bytes.Repeat([]byte("ordinary message "), 12)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, _, _, err := ws.UpgradeHTTP(r, w)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_ = wsutil.WriteServerMessage(conn, ws.OpText, payload)
			}))
			defer backend.Close()
			addr, closeProxy := setupWSProxy(t, func(cfg *config.Config) { cfg.WatchOnly = watch; cfg.WebSocketProxy.MaxMessageBytes = 64 })
			defer closeProxy()
			conn := dialWS(t, addr, strings.TrimPrefix(backend.URL, "http://"))
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			got, _, err := wsutil.ReadServerData(conn)
			if watch {
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("response changed: %q %v", got, err)
				}
			} else if err == nil {
				t.Fatal("oversize response enforcement disappeared")
			}
		})
	}
}

func TestWatchWebSocketResponseFragmentsOverLimit(t *testing.T) {
	pieces := []string{"The quarterly report ", "is ready to be read ", "and contains ordinary prose."}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for i, piece := range pieces {
			opcode := ws.OpContinuation
			if i == 0 {
				opcode = ws.OpText
			}
			if err := ws.WriteFrame(conn, ws.NewFrame(opcode, i == len(pieces)-1, []byte(piece))); err != nil {
				return
			}
		}
	}))
	defer backend.Close()
	addr, closeProxy := setupWSProxy(t, func(cfg *config.Config) { cfg.WatchOnly = true; cfg.WebSocketProxy.MaxMessageBytes = 32 })
	defer closeProxy()
	conn := dialWS(t, addr, strings.TrimPrefix(backend.URL, "http://"))
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	got, _, err := wsutil.ReadServerData(conn)
	if err != nil || string(got) != strings.Join(pieces, "") {
		t.Fatalf("response fragment changed: %q %v", got, err)
	}
}

func TestWatchWebSocketCredentialFloor(t *testing.T) {
	backend, closeBackend := wsEchoServer(t)
	defer closeBackend()
	addr, closeProxy := setupWSProxy(t, func(cfg *config.Config) { cfg.WatchOnly = true })
	defer closeProxy()
	conn := dialWS(t, addr, backend)
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	credential := "AKIA" + "IOSFODNN7" + testWSExample
	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(credential)); err != nil {
		t.Fatal(err)
	}
	if got, _, err := wsutil.ReadServerData(conn); err == nil {
		t.Fatalf("credential released: %q", got)
	}
}

func TestWatchWebSocketResponseFinding(t *testing.T) {
	backend, closeBackend := wsInjectionServer(t)
	defer closeBackend()
	addr, closeProxy := setupWSProxy(t, func(cfg *config.Config) {
		cfg.WatchOnly = true
		cfg.ResponseScanning.Enabled = true
		cfg.ResponseScanning.Action = config.ActionStrip
	})
	defer closeProxy()
	conn := dialWS(t, addr, backend)
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(testWSHello)); err != nil {
		t.Fatal(err)
	}
	got, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(string(got)), "ignore") {
		t.Fatalf("response rewritten: %q", got)
	}
}

func TestWatchWebSocketKillSwitch(t *testing.T) {
	backend, closeBackend := wsEchoServer(t)
	defer closeBackend()
	addr, p, closeProxy := setupWSProxyDefaultWithProxy(t, func(cfg *config.Config) { cfg.WatchOnly = true })
	defer closeProxy()
	p.ks = killswitch.New(p.CurrentConfig())
	p.ks.SetAPI(true)
	conn, err := dialWSConn(addr, backend)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("kill switch allowed watch connection")
	}
}

func TestWatchWebSocketReloadDisposition(t *testing.T) {
	cfg := config.Defaults()
	p := &Proxy{}
	p.cfgPtr.Store(cfg)
	relay := &wsRelay{proxy: p, cfg: cfg}
	on := *cfg
	on.WatchOnly = true
	p.cfgPtr.Store(&on)
	if relay.watchOnly() || !relay.enforceEnabled() {
		t.Fatal("reload replaced admitted enforce mode")
	}
	nextRelay := &wsRelay{proxy: p, cfg: &on}
	if !nextRelay.watchOnly() || nextRelay.enforceEnabled() {
		t.Fatal("new admission did not use watch mode")
	}
	p.cfgPtr.Store(cfg)
	if !nextRelay.watchOnly() {
		t.Fatal("reload replaced admitted watch mode")
	}
}

func TestWatchWebSocketReloadDuringFragment(t *testing.T) {
	for _, initial := range []bool{false, true} {
		t.Run(map[bool]string{false: "enable", true: "disable"}[initial], func(t *testing.T) {
			backend, closeBackend := wsEchoServer(t)
			defer closeBackend()
			addr, p, closeProxy := setupWSProxyDefaultWithProxy(t, func(cfg *config.Config) {
				cfg.WatchOnly = initial
			})
			defer closeProxy()
			conn := dialWS(t, addr, backend)
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			writeMaskedClientFrame(t, conn, false, ws.OpText, []byte("ordinary "))
			// The ping reply proves the first fragment was consumed before reload.
			writeMaskedClientFrame(t, conn, true, ws.OpPing, []byte("checkpoint"))
			hdr, err := ws.ReadHeader(conn)
			if err != nil {
				t.Fatal(err)
			}
			if hdr.OpCode != ws.OpPong {
				t.Fatalf("expected pong, got %v", hdr.OpCode)
			}
			if _, err := io.CopyN(io.Discard, conn, hdr.Length); err != nil {
				t.Fatal(err)
			}
			next := *p.cfgPtr.Load()
			next.WatchOnly = !initial
			p.cfgPtr.Store(&next)
			writeMaskedClientFrame(t, conn, true, ws.OpContinuation, []byte("message"))
			got, _, err := wsutil.ReadServerData(conn)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "ordinary message" {
				t.Fatalf("fragment changed: %q", got)
			}
		})
	}
}

func TestWatchWebSocketIdleTimeoutObserved(t *testing.T) {
	backend, closeBackend := wsEchoServer(t)
	defer closeBackend()
	addr, closeProxy := setupWSProxy(t, func(cfg *config.Config) {
		cfg.WatchOnly = true
		cfg.WebSocketProxy.IdleTimeoutSeconds = 1
	})
	defer closeProxy()
	conn := dialWS(t, addr, backend)
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	_, err := ws.ReadHeader(conn)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("idle connection closed: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(testWSHello)); err != nil {
		t.Fatal(err)
	}
	got, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testWSHello {
		t.Fatalf("changed payload: %q", got)
	}
}

func TestWatchWebSocketClosePayloadPreserved(t *testing.T) {
	payload := ws.NewCloseFrameBody(ws.StatusGoingAway, "upstream maintenance")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = wsutil.WriteServerMessage(conn, ws.OpClose, payload)
	}))
	defer backend.Close()
	addr, closeProxy := setupWSProxy(t, func(cfg *config.Config) { cfg.WatchOnly = true })
	defer closeProxy()
	conn := dialWS(t, addr, strings.TrimPrefix(backend.URL, "http://"))
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	frame, err := ws.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Header.OpCode != ws.OpClose || !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("close changed: %#v", frame)
	}
}

func TestWatchWebSocketUninspectedFrameKill(t *testing.T) {
	cfg := config.Defaults()
	p := &Proxy{ks: killswitch.New(cfg)}
	relay := &wsRelay{proxy: p, cfg: cfg}
	reader := &watchFrameReader{Reader: strings.NewReader("ordinary message"), relay: relay}
	buf := make([]byte, 1)
	if n, err := reader.Read(buf); err != nil || n != 1 {
		t.Fatalf("before kill: n=%d err=%v", n, err)
	}
	p.ks.SetAPI(true)
	if n, err := reader.Read(buf); err == nil || n != 0 {
		t.Fatalf("kill released bytes: n=%d err=%v", n, err)
	}
}

func TestWatchWebSocketRequiredReceiptUnavailable(t *testing.T) {
	backend, closeBackend := wsEchoServer(t)
	defer closeBackend()
	addr, closeProxy := setupWSProxy(t, func(cfg *config.Config) {
		cfg.WatchOnly = true
		cfg.FlightRecorder.RequireReceipts = true
	})
	defer closeProxy()
	conn, err := dialWSConn(addr, backend)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("watch handshake succeeded without required receipt")
	}
}

func TestWatchWebSocketSubprotocolPreserved(t *testing.T) {
	testWebSocketSubprotocolPreserved(t, true)
}

func testWebSocketSubprotocolPreserved(t *testing.T, watch bool) {
	t.Helper()
	const protocol = "agent-stream"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := ws.HTTPUpgrader{Protocol: func(p string) bool { return p == protocol }}
		conn, _, _, err := upgrader.Upgrade(r, w)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		msg, op, err := wsutil.ReadClientData(conn)
		if err == nil {
			_ = wsutil.WriteServerMessage(conn, op, msg)
		}
	}))
	defer backend.Close()
	addr, closeProxy := setupWSProxy(t, func(cfg *config.Config) { cfg.WatchOnly = watch })
	defer closeProxy()
	dialer := ws.Dialer{Protocols: []string{protocol}, Timeout: 5 * time.Second}
	target := "ws" + strings.TrimPrefix(backend.URL, "http")
	conn, reader, handshake, err := dialer.Dial(t.Context(), "ws://"+addr+"/ws?url="+url.QueryEscape(target))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if reader != nil {
		ws.PutReader(reader)
	}
	if handshake.Protocol != protocol {
		t.Fatalf("subprotocol changed: %q", handshake.Protocol)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(testWSHello)); err != nil {
		t.Fatal(err)
	}
	got, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testWSHello {
		t.Fatalf("changed payload: %q", got)
	}
}
