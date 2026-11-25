// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// receiptProducerStops is the set of proxy drains for one test.
// A handler appends the terminal receipt outcome after it flushes the
// response, so closing the recorder at the client's next line races that
// append. Draining the server first waits until those handlers return.
type receiptProducerStops struct {
	mu      sync.Mutex
	stops   []func()
	done    bool
	cleanup bool
}

var proxyReceiptProducers sync.Map // *testing.T -> *receiptProducerStops

// registerProxyReceiptProducerStop remembers a drain that receipt readers run
// before they close the recorder. The drain also runs from test cleanup, so a
// test that never reads receipts still stops its server.
func registerProxyReceiptProducerStop(t *testing.T, stop func()) {
	t.Helper()
	if stop == nil {
		return
	}
	v, _ := proxyReceiptProducers.LoadOrStore(t, &receiptProducerStops{})
	set := v.(*receiptProducerStops)
	set.mu.Lock()
	if !set.cleanup {
		set.cleanup = true
		t.Cleanup(func() {
			drainProxyReceiptProducers(t)
			proxyReceiptProducers.Delete(t)
		})
	}
	if set.done {
		set.mu.Unlock()
		stop()
		return
	}
	set.stops = append(set.stops, stop)
	set.mu.Unlock()
}

// drainProxyReceiptProducers runs each registered drain once. A second call,
// including the cleanup after a reader already drained, does nothing. It does
// not fail the test on its own: a server that does not stop is reported by the
// drain, and a missing receipt still fails the caller's assertions.
func drainProxyReceiptProducers(t *testing.T) {
	t.Helper()
	v, ok := proxyReceiptProducers.Load(t)
	if !ok {
		return
	}
	set := v.(*receiptProducerStops)
	set.mu.Lock()
	if set.done {
		set.mu.Unlock()
		return
	}
	stops := set.stops
	set.stops = nil
	set.done = true
	set.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}

// closeTestReceiptRecorder stops registered receipt producers, then closes the
// recorder. Close stays free to finish repairs that only land then.
func closeTestReceiptRecorder(t *testing.T, rec *recorder.Recorder) {
	t.Helper()
	drainProxyReceiptProducers(t)
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
}

// registerHTTPServerDrain waits for an httptest server's handlers to return.
// httptest.Server.Close closes connections without waiting for the handler's
// deferred outcome receipt.
func registerHTTPServerDrain(t *testing.T, srv *httptest.Server) {
	t.Helper()
	if srv == nil || srv.Config == nil {
		return
	}
	var once sync.Once
	registerProxyReceiptProducerStop(t, func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(5*time.Second))
			defer cancel()
			if err := srv.Config.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("shutdown receipt server: %v", err)
			}
		})
	})
}

// startTestProxyServer serves handler until the returned stop runs. Stop
// cancels the base context and waits for http.Server.Shutdown, which returns
// only after in-flight HTTP handlers return. Serve itself returns as soon as
// the listener closes, so waiting on it would still race the outcome receipt.
// Hijacked connections are not covered by Shutdown.
func startTestProxyServer(t *testing.T, ln net.Listener, handler http.Handler) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve(ln)
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), testwait.Deadline(5*time.Second))
			defer shutdownCancel()
			if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("shutdown proxy: %v", err)
			}
			select {
			case <-serveDone:
			case <-time.After(testwait.Deadline(2 * time.Second)):
				_ = ln.Close()
				t.Errorf("proxy serve did not return")
			}
		})
	}
	registerProxyReceiptProducerStop(t, stop)
	return stop
}
