// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
)

// A grace shorter than the relay's normal close handshake must still suffice
// for shutdown: both sockets close at the start, rather than waiting for the
// peer's close reply or its idle timeout. No run-context cancellation helps.
func TestWebSocketGateDrainClosesSockets(t *testing.T) {
	for _, library := range []bool{false, true} {
		t.Run(map[bool]string{false: "endpoint", true: "library_upgrade"}[library], func(t *testing.T) {
			upstreamAddr, stop := wsEchoServer(t)
			defer stop()
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
			cfg.ForwardProxy.Enabled = true
			cfg.WebSocketProxy.Enabled = true
			p := newTestProxyWithConfig(t, cfg)
			gate := &httpstream.Gate{}
			handler := p.Handler()
			if library {
				upstream, err := url.Parse("http://" + upstreamAddr)
				if err != nil {
					t.Fatal(err)
				}
				handler = httputil.NewSingleHostReverseProxy(upstream)
			}
			srv := httptest.NewServer(gate.Wrap(handler))
			defer srv.Close()
			target := "ws://" + upstreamAddr + "/stream"
			endpoint := "ws" + srv.URL[len("http"):] + "/ws?url=" + url.QueryEscape(target)
			if library {
				endpoint = "ws" + srv.URL[len("http"):] + "/stream"
			}
			dialer := ws.Dialer{}

			conn, _, _, err := dialer.Dial(t.Context(), endpoint)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := wsutil.WriteClientText(conn, []byte(testWSHello)); err != nil {
				t.Fatal(err)
			}
			if _, _, err := wsutil.ReadServerData(conn); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), relayCloseGrace/2)
			defer cancel()
			if err := httpstream.DrainServer(ctx, httpstream.GatedServer{Server: srv.Config, Gate: gate}); err != nil {
				t.Fatalf("WebSocket drain waited for peer close grace: %v", err)
			}
			if err := conn.SetReadDeadline(time.Now().Add(relayCloseGrace)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, conn); err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					t.Fatal("client socket left open")
				}
			}
		})
	}
}

// CONNECT's two copy directions cannot rely on a peer half-close or an idle
// timeout. Even a client stalled before its TLS ClientHello must be closed.
func TestConnectGateDrainClosesSockets(t *testing.T) {
	for _, sni := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw", true: "waiting_client_hello"}[sni], func(t *testing.T) {
			upstream, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = upstream.Close() }()
			closed := make(chan struct{})
			releaseUpstream := make(chan struct{})
			defer close(releaseUpstream)
			go func() {
				conn, err := upstream.Accept()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(io.Discard, conn)
				close(closed)
				// Keep the write half open after EOF. Shutdown must close
				// its upstream socket rather than rely on peer teardown.
				<-releaseUpstream
			}()
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
			cfg.ForwardProxy.Enabled = true
			cfg.ForwardProxy.SNIVerification = &sni
			p := newTestProxyWithConfig(t, cfg)
			gate := &httpstream.Gate{}
			srv := httptest.NewServer(gate.Wrap(p.Handler()))
			defer srv.Close()
			conn := dialTest(t, srv.Listener.Addr().String())
			if _, err := io.WriteString(conn, "CONNECT "+upstream.Addr().String()+" HTTP/1.1\r\nHost: "+upstream.Addr().String()+"\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close(); _ = resp.Body.Close() })
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("CONNECT = %d", resp.StatusCode)
			}
			ctx, cancel := context.WithTimeout(t.Context(), drainTestGrace)
			defer cancel()
			if err := httpstream.DrainServer(ctx, httpstream.GatedServer{Server: srv.Config, Gate: gate}); err != nil {
				t.Fatalf("CONNECT drain = %v", err)
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("upstream socket left open")
			}
		})
	}
}

// A listener cannot hold the next listener's tunnels open while it drains.
// The first handler only finishes after the second listener's socket closes.
func TestShutdownClosesAllAgentHijacksBeforeJoining(t *testing.T) {
	p := newTestProxy(t)
	p.shutdownGrace = drainTestGrace
	secondClosed := make(chan struct{})
	for i := range 2 {
		entered := make(chan struct{})
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer func() { _ = conn.Close() }()
			close(entered)
			_, _ = conn.Read(make([]byte, 1))
			if i == 1 {
				close(secondClosed)
			} else {
				<-secondClosed
			}
		}))
		p.RegisterAgentServer(srv.Config)
		srv.Start()
		defer srv.Close()
		conn := dialTest(t, srv.Listener.Addr().String())
		if _, err := io.WriteString(conn, "GET /tunnel HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("no hijack")
		}
	}
	if err := p.ShutdownAgentServers(); err != nil {
		t.Fatalf("listeners were drained before all hijacks closed: %v", err)
	}
}

// Observe entry into the real TCP Read after the relay armed its deadline.
// This makes cancellation interrupt an established read rather than letting
// the next loop's context check hide a missing socket-close callback.
type hijackReadObserver struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *hijackReadObserver) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Read(p)
}

func TestWebSocketShutdownInterruptsBlockedReads(t *testing.T) {
	upstreamAddr, stopUpstream := wsEchoServer(t)
	defer stopUpstream()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.WebSocketProxy.Enabled = true
	p := newTestProxyWithConfig(t, cfg)
	clientRead, upstreamRead, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	gate := &httpstream.Gate{}
	srv := httptest.NewServer(gate.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		client, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			t.Errorf("client upgrade: %v", err)
			return
		}
		defer func() { _ = client.Close() }()
		upstream, _, _, err := ws.DefaultDialer.Dial(r.Context(), "ws://"+upstreamAddr+"/stream")
		if err != nil {
			t.Errorf("upstream upgrade: %v", err)
			return
		}
		defer func() { _ = upstream.Close() }()
		relay := &wsRelay{
			clientConn:   &hijackReadObserver{Conn: client, entered: clientRead},
			upstreamConn: &hijackReadObserver{Conn: upstream, entered: upstreamRead},
			cfg:          p.cfgPtr.Load(), proxy: p, scanner: p.ScannerPtr().Load(),
			maxMsg:    cfg.WebSocketProxy.MaxMessageBytes,
			targetURL: "ws://" + upstreamAddr + "/stream", hostname: "127.0.0.1", path: "/stream",
		}
		_ = relay.run(r.Context())
	})))
	defer srv.Close()
	conn, _, _, err := ws.DefaultDialer.Dial(t.Context(), "ws"+srv.URL[len("http"):]+"/stream")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("relay did not stop")
		}
	})
	for _, read := range []<-chan struct{}{clientRead, upstreamRead} {
		select {
		case <-read:
		case <-time.After(5 * time.Second):
			t.Fatal("relay did not enter socket read")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), relayCloseGrace/2)
	defer cancel()
	if err := httpstream.DrainServer(ctx, httpstream.GatedServer{Server: srv.Config, Gate: gate}); err != nil {
		t.Fatalf("shutdown waited for relay close grace: %v", err)
	}
}
