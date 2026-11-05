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
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const drainTestGrace = 300 * time.Millisecond

// gatedTestServer serves handler behind a gate on a loopback listener and
// reports every connection state change on states.
func gatedTestServer(t *testing.T, handler http.Handler) (gatedServer, string, <-chan http.ConnState, <-chan error) {
	t.Helper()
	gate := &handlerGate{}
	states := make(chan http.ConnState, 64)
	srv := &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
		Handler:           gate.wrap(handler),
		ConnState: func(_ net.Conn, st http.ConnState) {
			select {
			case states <- st:
			default:
			}
		},
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return gatedServer{srv: srv, gate: gate}, ln.Addr().String(), states, served
}

func waitConnState(t *testing.T, states <-chan http.ConnState, want http.ConnState) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case st := <-states:
			if st == want {
				return
			}
		case <-deadline:
			t.Fatalf("server never saw a connection in state %v", want)
		}
	}
}

func dialTest(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// A connection that never delivered a request reached no handler and owes no
// outcome receipt. net/http still counts it as active past the grace period,
// so it must not make the drain report incomplete.
func TestDrainServerIgnoresConnectionsWithoutRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		send  string
		state http.ConnState
	}{
		// Both stay in StateNew, which Shutdown counts as active until the
		// connection is five seconds old (Go issue 22682).
		{name: "no_bytes", state: http.StateNew},
		{name: "partial_header", send: "GET /health HTTP/1.1\r\nHost: x\r\n", state: http.StateNew},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			gs, addr, states, served := gatedTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				calls.Add(1)
			}))
			conn := dialTest(t, addr)
			if tc.send != "" {
				if _, err := io.WriteString(conn, tc.send); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
			waitConnState(t, states, tc.state)

			ctx, cancel := context.WithTimeout(context.Background(), drainTestGrace)
			defer cancel()
			if err := drainServer(ctx, gs); err != nil {
				t.Fatalf("drainServer = %v, want a complete drain", err)
			}
			if err := <-served; !errors.Is(err, http.ErrServerClosed) {
				t.Fatalf("Serve = %v, want ErrServerClosed", err)
			}
			// The straggler is closed rather than left to deliver a request,
			// and a request it might still send is never handled.
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadAll(conn); err != nil {
				t.Fatalf("straggler connection was not closed: %v", err)
			}
			if n := calls.Load(); n != 0 {
				t.Fatalf("handler ran %d times, want 0", n)
			}
		})
	}
}

// A handler still running when the grace period ends may still owe its
// outcome receipt, so the drain stays incomplete.
func TestDrainServerReportsRunningHandler(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	gs, addr, _, _ := gatedTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	}))
	defer close(release)

	held := dialTest(t, addr)
	if _, err := io.WriteString(held, "GET /hold HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), drainTestGrace)
	defer cancel()
	if err := drainServer(ctx, gs); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drainServer = %v, want the deadline reported", err)
	}
	if running := gs.gate.close(); running != 1 {
		t.Fatalf("gate reports %d running handlers, want 1", running)
	}
}

// Once closed, the gate refuses a handler that was dispatched before shutdown
// began but had not started, so the running count it reported stays final.
func TestHandlerGateRefusesAfterClose(t *testing.T) {
	gate := &handlerGate{}
	var calls atomic.Int32
	h := gate.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)

	h.ServeHTTP(httptest.NewRecorder(), req)
	if running := gate.close(); running != 0 {
		t.Fatalf("gate reports %d running handlers after the handler returned, want 0", running)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Connection") != "close" {
		t.Fatalf("refused request: status %d, Connection %q; want 503 and close", rec.Code, rec.Header().Get("Connection"))
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("handler ran %d times, want 1", n)
	}
	if running := gate.close(); running != 0 {
		t.Fatalf("refused request left %d running handlers, want 0", running)
	}
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
