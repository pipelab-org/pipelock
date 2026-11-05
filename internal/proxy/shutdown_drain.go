// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// defaultShutdownGrace bounds how long a graceful shutdown waits for running
// handlers before the run is reported incomplete.
const defaultShutdownGrace = 5 * time.Second

// handlerGate counts the handlers a server is running. Once closed it turns
// away every request that reaches the handler afterwards, so the count it
// reports at close is final.
type handlerGate struct {
	mu      sync.Mutex
	closed  bool
	running int
}

func (g *handlerGate) wrap(next http.Handler) http.Handler {
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
		handler.ServeHTTP(w, r)
	})
}

func (g *handlerGate) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.running++
	return true
}

func (g *handlerGate) leave() {
	g.mu.Lock()
	g.running--
	g.mu.Unlock()
}

// close stops admitting handlers and returns how many are still running.
func (g *handlerGate) close() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return g.running
}

// gatedServer is a server whose handler is wrapped by gate.
type gatedServer struct {
	srv  *http.Server
	gate *handlerGate
}

// drainServer gracefully shuts srv down within ctx and reports whether any
// handler may still owe an outcome receipt.
//
// Shutdown also waits for connections that have not delivered a complete
// request: net/http keeps a connection in StateNew until its first request's
// headers are read, and counts it as active until it is five seconds old (Go
// issue 22682), as long as the grace period. Such a connection reached no
// handler and owes no receipt, yet it made Shutdown report a deadline. When the
// deadline passes with no handler running, those connections are closed and the
// drain counts as complete. Closing the gate at that moment refuses a handler
// that was dispatched before shutdown began but had not yet started, so the
// count stays final. A running handler, or any other Shutdown failure, still
// reports an incomplete drain.
func drainServer(ctx context.Context, gs gatedServer) error {
	err := gs.srv.Shutdown(ctx)
	if err == nil {
		return nil
	}
	if gs.gate.close() == 0 && errors.Is(err, context.DeadlineExceeded) {
		_ = gs.srv.Close()
		return nil
	}
	return err
}

func (p *Proxy) shutdownGraceOrDefault() time.Duration {
	if p.shutdownGrace > 0 {
		return p.shutdownGrace
	}
	return defaultShutdownGrace
}
