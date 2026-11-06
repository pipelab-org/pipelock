// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const drainTestGrace = 300 * time.Millisecond

func dialTest(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestRegisterAgentServerPreservesDefaultHandler(t *testing.T) {
	p := newTestProxy(t)
	srv := httptest.NewUnstartedServer(nil)
	p.RegisterAgentServer(srv.Config)
	srv.Start()
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/shutdown-drain-default-handler", nil)
	if err != nil {
		t.Fatalf("default handler request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("default handler request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("default handler status = %d, want 404", resp.StatusCode)
	}
}

// start and ShutdownAgentServers drain through the gate: an idle connection on
// the main or an agent listener leaves a clean stop, so the runtime seals.
func TestStartIgnoresConnectionsWithoutRequest(t *testing.T) {
	p := newTestProxy(t)
	p.shutdownGrace = drainTestGrace

	agentSrv := &http.Server{ReadHeaderTimeout: 30 * time.Second, Handler: http.NotFoundHandler()}
	p.RegisterAgentServer(agentSrv)
	agentLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen agent: %v", err)
	}
	go func() { _ = agentSrv.Serve(agentLn) }()
	mainLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen main: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	returned := make(chan error, 1)
	go func() { returned <- p.StartWithListener(ctx, mainLn) }()

	for _, addr := range []string{mainLn.Addr().String(), agentLn.Addr().String()} {
		dialTest(t, addr)
		partial := dialTest(t, addr)
		if _, err := io.WriteString(partial, "GET /health HTTP/1.1\r\nHost: x\r\n"); err != nil {
			t.Fatal(err)
		}
		// Serve accepts in order, so a later request answered on a second
		// connection proves the silent one was accepted.
		waitServed(t, addr)
	}

	cancel()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatalf("StartWithListener = %v, want a clean stop", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("StartWithListener did not return after cancel")
	}
}

func waitServed(t *testing.T, addr string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	testwait.For(t, 10*time.Second, func() bool {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/health", nil)
		if err != nil {
			return false
		}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return true
	}, "%s never answered", addr)
}

func TestStartReportsHeldHandlerDrain(t *testing.T) {
	defer scanner.SetCloseDrainTimeoutForTest(50 * time.Millisecond)()
	for _, listener := range []string{"main", "agent"} {
		t.Run(listener, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.ForwardProxy.Enabled = true
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "drain-warning-probe", Regex: "drain-warning-probe", Severity: config.SeverityLow, Action: config.ActionWarn})
			p := newTestProxyWithConfig(t, cfg)
			p.shutdownGrace = drainTestGrace
			entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			p.ScannerPtr().Load().SetDLPWarnHook(func(context.Context, string, string) { close(entered); <-release })
			ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			if listener == "agent" {
				agentLn, listenErr := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
				if listenErr != nil {
					t.Fatal(listenErr)
				}
				srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release })}
				p.RegisterAgentServer(srv)
				t.Cleanup(func() { _ = srv.Close() })
				go func() { _ = srv.Serve(agentLn) }()
				addr = agentLn.Addr().String()
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- p.StartWithListener(ctx, ln) }()
			conn := dialTest(t, addr)
			if _, err := io.WriteString(conn, "GET http://api.vendor.example/?value=drain-warning-probe HTTP/1.1\r\nHost: api.vendor.example\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			go func() { _, _ = io.Copy(io.Discard, conn); close(finished) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("handler did not enter hold")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, ErrShutdownIncomplete) || !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("held handler drain = %v, want incomplete deadline", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("held handler drain did not stop")
			}
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Error("force-close did not stop client")
			}
			unblock()
		})
	}
}
