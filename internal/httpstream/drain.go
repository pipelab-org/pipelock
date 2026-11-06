// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
)

// Gate counts handlers and their asynchronous receipt-producing work. Its zero
// value is ready to use. Closing admission and observing work share one lock.
//
// Handlers and child work are counted apart so unread connections can be
// forgiven without losing receipt-producing work. Hijacked handlers remain
// counted until ServeHTTP returns, including its deferred outcome receipts.
type Gate struct {
	mu          sync.Mutex
	closed      bool
	failed      bool // an earlier drain of this server did not complete
	handlers    int
	children    int
	idle        chan struct{}
	draining    bool
	hijackCtx   context.Context
	stopHijacks context.CancelFunc
}

type gateContextKey struct{}

// Wrap fences the outermost handler and makes its gate available to child work.
// A nil handler retains net/http.Server's DefaultServeMux behavior.
func (g *Gate) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.enterHandler() {
			w.Header().Set("Connection", "close")
			http.Error(w, "proxy shutting down", http.StatusServiceUnavailable)
			return
		}
		defer g.leaveHandler()
		handler := next
		if handler == nil {
			handler = http.DefaultServeMux
		}
		ctx := context.WithValue(r.Context(), gateContextKey{}, g)
		if hijacker, ok := w.(http.Hijacker); ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			defer cancel()
			tracked := &hijackWriter{ResponseWriter: w, hijacker: hijacker, ctx: ctx, cancel: cancel}
			defer tracked.finish()
			w = tracked
			if flusher, ok := tracked.ResponseWriter.(http.Flusher); ok {
				w = struct {
					*hijackWriter
					http.Flusher
				}{tracked, flusher}
			}
		}
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// hijackWriter tracks both direct and library-initiated protocol switches.
// Unwrap retains ResponseController access to the underlying writer's methods.
// Cancellation starts before Hijack, so a switch racing shutdown cannot escape.
type hijackWriter struct {
	http.ResponseWriter
	hijacker     http.Hijacker
	ctx          context.Context
	cancel       context.CancelFunc
	lifetime     context.Context
	stopLifetime context.CancelFunc
	stopCancel   func() bool
	stopClose    func() bool
}

func (w *hijackWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *hijackWriter) FlushError() error {
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.lifetime == nil {
		w.lifetime, w.stopLifetime = hijackContext(w.ctx)
		w.stopCancel = context.AfterFunc(w.lifetime, w.cancel)
	}
	conn, buffered, err := w.hijacker.Hijack()
	if err == nil {
		w.stopClose = context.AfterFunc(w.lifetime, func() { _ = conn.Close() })
	}
	return conn, buffered, err
}

func (w *hijackWriter) finish() {
	if w.stopClose != nil {
		w.stopClose()
	}
	if w.stopCancel != nil {
		w.stopCancel()
	}
	if w.stopLifetime != nil {
		w.stopLifetime()
	}
}

// Begin registers work before starting it. The returned function must run after
// its last possible receipt emission. A closed gate refuses registration; the
// caller must then start no work. Without a server gate, Begin is a no-op.
func Begin(ctx context.Context) (finish func(), admitted bool) {
	g, _ := ctx.Value(gateContextKey{}).(*Gate)
	if g == nil {
		return func() {}, true
	}
	if !g.enterChild() {
		return nil, false
	}
	return g.leaveChild, true
}

func (g *Gate) enterHandler() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.handlers++
	return true
}

func (g *Gate) leaveHandler() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.handlers--
	if g.handlers+g.children == 0 && g.idle != nil {
		close(g.idle)
	}
}

func (g *Gate) enterChild() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.children++
	return true
}

func (g *Gate) leaveChild() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.children--
	if g.handlers+g.children == 0 && g.idle != nil {
		close(g.idle)
	}
}

// close stops admission and reports the handlers and child work still running,
// with a channel that closes once all work finishes.
func (g *Gate) close() (handlers, children int, idle <-chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	if g.handlers+g.children != 0 && g.idle == nil {
		g.idle = make(chan struct{})
	}
	return g.handlers, g.children, g.idle
}

// hijackContext derives a lifetime canceled when this listener starts draining.
// Call before hijacking, close both sockets on cancellation, and cancel the
// returned context when the handler returns. Without a gate it follows ctx.
func hijackContext(ctx context.Context) (context.Context, context.CancelFunc) {
	lifetime, cancel := context.WithCancel(ctx)
	g, _ := ctx.Value(gateContextKey{}).(*Gate)
	if g == nil {
		return lifetime, cancel
	}
	g.mu.Lock()
	if g.draining {
		g.mu.Unlock()
		cancel()
		return lifetime, cancel
	}
	if g.hijackCtx == nil {
		g.hijackCtx, g.stopHijacks = context.WithCancel(context.Background())
	}
	stop := context.AfterFunc(g.hijackCtx, cancel)
	g.mu.Unlock()
	return lifetime, func() { stop(); cancel() }
}

// StopHijacks cancels existing and future hijack lifetimes. Call it on every
// listener before joining any one of them when listeners share a grace period.
func (g *Gate) StopHijacks() {
	g.mu.Lock()
	g.draining = true
	cancel := g.stopHijacks
	g.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// GatedServer pairs a server with the gate wrapping its outermost handler.
type GatedServer struct {
	Server *http.Server
	Gate   *Gate
}

// DrainServer joins handlers and registered child work within ctx. net/http
// keeps unread and partial-header connections in StateNew for five seconds
// (Go issue 22682). A deadline with no receipt-producing work is therefore a
// complete drain: close the stragglers after fencing any late handler entry.
// Hijack lifetimes are canceled before Shutdown; all handlers and registered
// child work must finish within ctx. Running work or any other
// shutdown error remains incomplete. Failed graceful shutdowns force-close
// connections, but never claim the outstanding work ended.
func DrainServer(ctx context.Context, gs GatedServer) error {
	gs.Gate.StopHijacks()
	return gs.Gate.settle(drainOnce(ctx, gs))
}

// ErrEarlierDrainIncomplete reports that an earlier drain of the same server
// gave up with work still running. A failed drain force-closes connections, so
// a later Shutdown can succeed while that work still owes receipts.
var ErrEarlierDrainIncomplete = errors.New("an earlier drain of this listener did not complete")

// settle records a failed drain and keeps every later drain of the same server
// incomplete, so a retry cannot report a run complete that an earlier attempt
// could not finish.
func (g *Gate) settle(err error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		g.failed = true
		return err
	}
	if g.failed {
		return ErrEarlierDrainIncomplete
	}
	return nil
}

func drainOnce(ctx context.Context, gs GatedServer) error {
	err := gs.Server.Shutdown(ctx)
	handlers, children, idle := gs.Gate.close()
	if err == nil && handlers+children != 0 {
		select {
		case <-idle:
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	if err != nil {
		_ = gs.Server.Close()
		if handlers == 0 && children == 0 && errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
	}
	return err
}
