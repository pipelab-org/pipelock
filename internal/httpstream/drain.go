// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"context"
	"errors"
	"net/http"
	"sync"
)

// Gate counts handlers and their asynchronous receipt-producing work. Its zero
// value is ready to use. Closing admission and observing work share one lock.
//
// Handlers and child work are counted apart. Shutdown already waits for every
// handler net/http still tracks, so after it succeeds the only handlers left
// are hijacked ones (CONNECT tunnels, WebSocket relays), which have their own
// drain contract; child work registered through Begin is what remains to join.
type Gate struct {
	mu        sync.Mutex
	closed    bool
	failed    bool // an earlier drain of this server did not complete
	handlers  int
	children  int
	childIdle chan struct{}
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
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), gateContextKey{}, g)))
	})
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
}

func (g *Gate) enterChild() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	if g.children == 0 {
		g.childIdle = make(chan struct{})
	}
	g.children++
	return true
}

func (g *Gate) leaveChild() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.children--
	if g.children == 0 {
		close(g.childIdle)
	}
}

// close stops admission and reports the handlers and child work still running,
// with a channel that closes once the child work finishes.
func (g *Gate) close() (handlers, children int, childIdle <-chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return g.handlers, g.children, g.childIdle
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
// After Shutdown succeeds, registered child work must still finish within ctx;
// hijacked handlers are not waited on (see Gate). Running work or any other
// shutdown error remains incomplete. Failed graceful shutdowns force-close
// connections, but never claim the outstanding work ended.
func DrainServer(ctx context.Context, gs GatedServer) error {
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
	handlers, children, childIdle := gs.Gate.close()
	if err == nil && children != 0 {
		select {
		case <-childIdle:
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
