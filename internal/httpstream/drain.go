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
type Gate struct {
	mu      sync.Mutex
	closed  bool
	running int
	idle    chan struct{}
}

type gateContextKey struct{}

// Wrap fences the outermost handler and makes its gate available to child work.
// A nil handler retains net/http.Server's DefaultServeMux behavior.
func (g *Gate) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.enter() {
			w.Header().Set("Connection", "close")
			http.Error(w, "proxy shutting down", http.StatusServiceUnavailable)
			return
		}
		defer g.leave()
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
	if !g.enter() {
		return nil, false
	}
	return g.leave, true
}

func (g *Gate) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	if g.running == 0 {
		g.idle = make(chan struct{})
	}
	g.running++
	return true
}

func (g *Gate) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.running--
	if g.running == 0 {
		close(g.idle)
	}
}

func (g *Gate) close() (int, <-chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return g.running, g.idle
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
// Running work or any other shutdown error remains incomplete. Failed graceful
// shutdowns force-close connections, but never claim the outstanding work ended.
func DrainServer(ctx context.Context, gs GatedServer) error {
	err := gs.Server.Shutdown(ctx)
	running, idle := gs.Gate.close()
	if err == nil && running != 0 {
		select {
		case <-idle:
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	if err != nil {
		_ = gs.Server.Close()
		if running == 0 && errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
	}
	return err
}
