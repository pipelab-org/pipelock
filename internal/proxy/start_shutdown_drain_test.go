// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// serveUntilShutdown must not return until in-flight handlers have finished.
// The runtime seals the transcript root and closes the receipt recorder as
// soon as start returns, so an earlier return loses the outcome receipt that a
// handler writes after its response has already reached the client.
func TestServeUntilShutdownWaitsForInFlightHandlers(t *testing.T) {
	t.Run("context_cancelled", func(t *testing.T) {
		testServeUntilShutdownWaitsForInFlightHandlers(t, true)
	})
	t.Run("listener_failed", func(t *testing.T) {
		testServeUntilShutdownWaitsForInFlightHandlers(t, false)
	})
}

func testServeUntilShutdownWaitsForInFlightHandlers(t *testing.T, cancelContext bool) {
	t.Helper()
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	// Like an outcome receipt, the work after the response ignores request
	// cancellation, so only Shutdown's drain can wait for it.
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "response sent")
			w.(http.Flusher).Flush()
			close(entered)
			<-release
			close(finished)
		}),
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	returned := make(chan error, 1)
	go func() {
		returned <- serveUntilShutdown(ctx, func() error { return srv.Serve(ln) }, func() error {
			shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			return srv.Shutdown(shutdownCtx)
		})
	}()
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
	})

	go func() {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/", nil)
		if reqErr != nil {
			return
		}
		if resp, doErr := http.DefaultClient.Do(req); doErr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("request never reached the handler")
	}

	wantServeErr := http.ErrServerClosed
	if cancelContext {
		cancel()
	} else {
		wantServeErr = net.ErrClosed
		_ = ln.Close()
	}
	// The listener must stop accepting before checking that the drain waits.
	testwait.For(t, 10*time.Second, func() bool {
		conn, dialErr := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(context.Background(), "tcp", addr)
		if dialErr != nil {
			return true
		}
		_ = conn.Close()
		return false
	}, "shutdown to close the listener")
	select {
	case err := <-returned:
		t.Fatalf("serveUntilShutdown returned (%v) while a handler was still in flight", err)
	case <-time.After(500 * time.Millisecond):
	}

	released = true
	close(release)
	select {
	case err := <-returned:
		if !errors.Is(err, wantServeErr) {
			t.Fatalf("serveUntilShutdown = %v, want %v", err, wantServeErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilShutdown did not return after the handler drained")
	}
	select {
	case <-finished:
	default:
		t.Fatal("serveUntilShutdown returned before the handler finished")
	}
}

func TestServeUntilShutdownServeFailureDrainsWithoutCancel(t *testing.T) {
	want := errors.New("bind failed")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	shutdownCalled := false
	returned := make(chan error, 1)
	go func() {
		returned <- serveUntilShutdown(ctx, func() error { return want }, func() error {
			shutdownCalled = true
			return nil
		})
	}()
	select {
	case err := <-returned:
		if !errors.Is(err, want) {
			t.Fatalf("serveUntilShutdown = %v, want %v", err, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilShutdown blocked after serve failed")
	}
	if !shutdownCalled {
		t.Fatal("serve failure did not drain handlers")
	}
}

func TestServeUntilShutdownCancelWithNothingInFlight(t *testing.T) {
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.NotFoundHandler()}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	shutdowns := 0
	returned := make(chan error, 1)
	go func() {
		returned <- serveUntilShutdown(ctx, func() error { return srv.Serve(ln) }, func() error {
			shutdowns++
			return srv.Shutdown(context.Background())
		})
	}()
	cancel()
	select {
	case err := <-returned:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("serveUntilShutdown = %v, want ErrServerClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilShutdown did not return after cancel")
	}
	if shutdowns != 1 {
		t.Fatalf("shutdown ran %d times, want 1", shutdowns)
	}
}

func TestServeUntilShutdownPreservesDrainFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	serveErr := errors.New("listener failed")
	for _, want := range []error{http.ErrServerClosed, serveErr} {
		t.Run(want.Error(), func(t *testing.T) {
			shutdownStarted := make(chan struct{})
			err := serveUntilShutdown(ctx, func() error {
				<-shutdownStarted
				return want
			}, func() error {
				close(shutdownStarted)
				return context.DeadlineExceeded
			})
			for _, cause := range []error{want, ErrShutdownIncomplete, context.DeadlineExceeded} {
				if !errors.Is(err, cause) {
					t.Errorf("serveUntilShutdown = %v, want cause %v", err, cause)
				}
			}
		})
	}
}
