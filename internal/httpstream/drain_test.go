// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
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
	if handlers, _, _ := gs.Gate.close(); handlers != 1 {
		t.Fatalf("gate reports %d running handlers, want 1", handlers)
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
	if handlers, _, _ := gate.close(); handlers != 0 {
		t.Fatalf("gate reports %d running handlers after the handler returned, want 0", handlers)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Connection") != "close" {
		t.Fatalf("refused request: status %d, Connection %q; want 503 and close", rec.Code, rec.Header().Get("Connection"))
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("handler ran %d times, want 1", n)
	}
	if handlers, _, _ := gate.close(); handlers != 0 {
		t.Fatalf("refused request left %d running handlers, want 0", handlers)
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

// Shutdown closes a tracked tunnel and joins its deferred completion. A
// handler that ignores cancellation must instead exhaust the same grace.
func TestDrainServerHijackedHandlers(t *testing.T) {
	for _, ignoresClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "closes", true: "ignores_close"}[ignoresClose], func(t *testing.T) {
			hijacked, closed, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			gs, addr, _, _ := gatedTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				defer close(finished)
				conn, _, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Errorf("hijack: %v", err)
					return
				}
				defer func() { _ = conn.Close() }()
				close(hijacked)
				_, _ = conn.Read(make([]byte, 1))
				close(closed)
				if ignoresClose {
					<-release
				}
			}))
			t.Cleanup(func() {
				close(release)
				select {
				case <-finished:
				case <-time.After(5 * time.Second):
					t.Error("handler did not stop")
				}
			})
			tunnel := dialTest(t, addr)
			if _, err := io.WriteString(tunnel, "GET /tunnel HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-hijacked:
			case <-time.After(5 * time.Second):
				t.Fatal("no hijack")
			}
			ctx, cancel := context.WithTimeout(t.Context(), drainTestGrace)
			defer cancel()
			err := DrainServer(ctx, gs)
			if ignoresClose && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("held hijacked drain = %v, want deadline", err)
			}
			if !ignoresClose && err != nil {
				t.Fatalf("closed hijacked drain = %v", err)
			}
			select {
			case <-closed:
			default:
				t.Error("shutdown did not close hijacked socket")
			}
			if !ignoresClose {
				select {
				case <-finished:
				default:
					t.Error("drain returned before handler completion")
				}
			}
		})
	}
}

func TestHijackContextLifecycle(t *testing.T) {
	ctx, cancel := hijackContext(t.Context())
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("ungated cancel did not propagate")
	}
	gate := &Gate{}
	var early context.Context
	var stop context.CancelFunc
	h := gate.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		early, stop = hijackContext(r.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	defer stop()
	gate.StopHijacks()
	select {
	case <-early.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("early hijack outlived shutdown")
	}
	gate.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		late, finish := hijackContext(r.Context())
		defer finish()
		if !errors.Is(late.Err(), context.Canceled) {
			t.Error("late hijack survived shutdown")
		}
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	fresh := &Gate{}
	fresh.StopHijacks()
	fresh.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		late, finish := hijackContext(r.Context())
		defer finish()
		if !errors.Is(late.Err(), context.Canceled) {
			t.Error("first hijack survived shutdown")
		}
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
}

type failedHijackWriter struct{ *httptest.ResponseRecorder }

func (failedHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, http.ErrNotSupported
}

type failedFlushWriter struct{ failedHijackWriter }

func (failedFlushWriter) FlushError() error { return io.ErrClosedPipe }

func TestGateHijackWriterFailureAndInterfaces(t *testing.T) {
	for _, failFlush := range []bool{false, true} {
		t.Run(map[bool]string{false: "flush", true: "flush_error"}[failFlush], func(t *testing.T) {
			gate := &Gate{}
			var wantFlush error
			if failFlush {
				wantFlush = io.ErrClosedPipe
			}
			h := gate.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if _, _, err := http.NewResponseController(w).Hijack(); !errors.Is(err, http.ErrNotSupported) {
					t.Errorf("hijack error = %v", err)
				}
				if err := http.NewResponseController(w).Flush(); !errors.Is(err, wantFlush) {
					t.Errorf("Flush = %v, want %v", err, wantFlush)
				}
				if err := http.NewResponseController(w).SetWriteDeadline(time.Now()); !errors.Is(err, http.ErrNotSupported) {
					t.Errorf("unwrapped deadline error = %v", err)
				}
			}))
			w := failedHijackWriter{httptest.NewRecorder()}
			var writer http.ResponseWriter = w
			if failFlush {
				writer = failedFlushWriter{w}
			}
			h.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
			if w.Flushed == failFlush {
				t.Errorf("flushed = %t, want %t", w.Flushed, !failFlush)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if err := DrainServer(ctx, GatedServer{Server: &http.Server{ReadHeaderTimeout: time.Second}, Gate: gate}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGateHijackRacingShutdown(t *testing.T) {
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	gs, addr, _, _ := gatedTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		defer close(finished)
		close(entered)
		<-release
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Read(make([]byte, 1))
	}))
	conn := dialTest(t, addr)
	if _, err := io.WriteString(conn, "GET /tunnel HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	gs.Gate.StopHijacks()
	close(release)
	ctx, cancel := context.WithTimeout(t.Context(), drainTestGrace)
	defer cancel()
	if err := DrainServer(ctx, gs); err != nil {
		t.Fatalf("late hijack survived shutdown: %v", err)
	}
	select {
	case <-finished:
	default:
		t.Error("drain returned before late hijack finished")
	}
}

// A drain that gave up force-closes its connections, so retrying Shutdown on
// the same server succeeds while the abandoned handler may still owe its
// receipt. Every later drain must stay incomplete.
func TestDrainServerRetryAfterFailureStaysIncomplete(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	gs, addr, _, _ := gatedTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		defer close(finished)
		close(entered)
		<-release
	}))
	held := dialTest(t, addr)
	if _, err := io.WriteString(held, "GET /hold HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	<-entered

	first, cancel := context.WithTimeout(context.Background(), drainTestGrace)
	defer cancel()
	if err := DrainServer(first, gs); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first drain = %v, want the deadline reported", err)
	}
	// The abandoned handler finishes after the failed drain. Only the recorded
	// failure can keep the retry from reporting the run complete.
	close(release)
	<-finished
	retry, cancelRetry := context.WithTimeout(context.Background(), drainTestGrace)
	defer cancelRetry()
	if err := DrainServer(retry, gs); !errors.Is(err, ErrEarlierDrainIncomplete) {
		t.Fatalf("retry drain = %v, want ErrEarlierDrainIncomplete", err)
	}
}

// unwrapOnlyWriter hides Hijack behind Unwrap, like the reverse proxy's
// write-progress deadline writer.
type unwrapOnlyWriter struct{ w http.ResponseWriter }

func (u unwrapOnlyWriter) Header() http.Header         { return u.w.Header() }
func (u unwrapOnlyWriter) Write(b []byte) (int, error) { return u.w.Write(b) }
func (u unwrapOnlyWriter) WriteHeader(code int)        { u.w.WriteHeader(code) }
func (u unwrapOnlyWriter) Unwrap() http.ResponseWriter { return u.w }

func TestGateTracksHijackBehindUnwrap(t *testing.T) {
	hijacked, closed := make(chan struct{}), make(chan struct{})
	gate := &Gate{}
	inner := gate.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		close(hijacked)
		_, _ = conn.Read(make([]byte, 1))
		close(closed)
	}))
	srv := &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inner.ServeHTTP(unwrapOnlyWriter{w}, r)
		}),
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	tunnel := dialTest(t, ln.Addr().String())
	if _, err := io.WriteString(tunnel, "GET /upgrade HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hijacked:
	case <-time.After(5 * time.Second):
		t.Fatal("no hijack")
	}
	ctx, cancel := context.WithTimeout(t.Context(), drainTestGrace)
	defer cancel()
	if err := DrainServer(ctx, GatedServer{Server: srv, Gate: gate}); err != nil {
		t.Fatalf("drain of an unwrapped hijack = %v", err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("shutdown did not close the hijack behind Unwrap")
	}
}

func TestDrainServersStopsEveryListenerBeforeWaiting(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseOnce)
	held, heldAddr, _, _ := gatedTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	}))
	idle, idleAddr, _, _ := gatedTestServer(t, http.NotFoundHandler())
	conn := dialTest(t, heldAddr)
	if _, err := io.WriteString(conn, "GET /held HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler not entered")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan []error, 1)
	go func() { done <- DrainServers(ctx, []GatedServer{held, idle}) }()
	testwait.For(t, 3*time.Second, func() bool {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", idleAddr)
		if err != nil {
			return true
		}
		_ = c.Close()
		return false
	}, "second listener kept accepting while the first drained")
	releaseOnce()
	if errs := <-done; errs[0] != nil || errs[1] != nil {
		t.Fatalf("drain errors = %v", errs)
	}
}
