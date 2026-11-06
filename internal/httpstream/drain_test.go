// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package httpstream

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
func gatedTestServer(t *testing.T, handler http.Handler) (GatedServer, string, <-chan http.ConnState, <-chan error) {
	t.Helper()
	gate := &Gate{}
	states := make(chan http.ConnState, 64)
	srv := &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
		Handler:           gate.Wrap(handler),
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
	return GatedServer{Server: srv, Gate: gate}, ln.Addr().String(), states, served
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
			if err := DrainServer(ctx, gs); err != nil {
				t.Fatalf("DrainServer = %v, want a complete drain", err)
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
	if err := DrainServer(ctx, gs); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DrainServer = %v, want the deadline reported", err)
	}
	if running, _ := gs.Gate.close(); running != 1 {
		t.Fatalf("gate reports %d running handlers, want 1", running)
	}
}

// Once closed, the gate refuses a handler that was dispatched before shutdown
// began but had not started, so the running count it reported stays final.
func TestHandlerGateRefusesAfterClose(t *testing.T) {
	gate := &Gate{}
	var calls atomic.Int32
	h := gate.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)

	h.ServeHTTP(httptest.NewRecorder(), req)
	if running, _ := gate.close(); running != 0 {
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
	if running, _ := gate.close(); running != 0 {
		t.Fatalf("refused request left %d running handlers, want 0", running)
	}
}

// Shutdown can report success after the handler returns while its child still
// owes receipts. Admission must close, and the child must join within grace.
func TestDrainServerJoinsChildWork(t *testing.T) {
	for _, pending := range []bool{true, false} {
		t.Run(map[bool]string{true: "pending", false: "finished"}[pending], func(t *testing.T) {
			var workCtx context.Context
			var finish func()
			gs, _, _, _ := gatedTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				workCtx = r.Context()
				var admitted bool
				finish, admitted = Begin(workCtx)
				if !admitted {
					t.Error("child refused before close")
				}
			}))
			gs.Server.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
			if !pending {
				finish()
			} else {
				defer finish()
			}
			ctx, cancel := context.WithTimeout(t.Context(), drainTestGrace)
			defer cancel()
			err := DrainServer(ctx, gs)
			if pending && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("pending child drain = %v, want deadline", err)
			}
			if !pending && err != nil {
				t.Fatalf("finished child drain = %v", err)
			}
			if done, ok := Begin(workCtx); ok {
				done()
				t.Fatal("child admitted after gate close")
			}
		})
	}
}

func TestDrainServerWaitsForChildCompletion(t *testing.T) {
	gate := &Gate{}
	started, finish := make(chan func(), 1), make(chan struct{})
	handler := gate.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leave, ok := Begin(r.Context())
		if !ok {
			t.Error("child refused")
		}
		started <- leave
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	leave := <-started
	gs := GatedServer{Server: &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}, Gate: gate}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- DrainServer(ctx, gs); close(finish) }()
	testwait.For(t, time.Second, func() bool {
		gate.mu.Lock()
		defer gate.mu.Unlock()
		return gate.closed
	}, "gate admission to close")
	select {
	case err := <-done:
		t.Fatalf("drain returned before child completion: %v", err)
	default:
	}
	leave()
	if err := <-done; err != nil {
		t.Fatalf("completed child drain = %v", err)
	}
	<-finish
	if done, ok := Begin(t.Context()); !ok {
		t.Fatal("ungated work refused")
	} else {
		done()
	}
}

func TestDrainServerPreservesCancellation(t *testing.T) {
	gs, addr, states, _ := gatedTestServer(t, http.NotFoundHandler())
	dialTest(t, addr)
	waitConnState(t, states, http.StateNew)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := DrainServer(ctx, gs); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled drain = %v", err)
	}
}
