// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Serve returning on cancellation must not end the call before shutdown
// finishes, and a shutdown failure must surface as ErrShutdownIncomplete.
func TestServeUntilShutdown(t *testing.T) {
	shutdownErr := errors.New("drain failed")
	for _, tc := range []struct {
		name      string
		cancel    bool
		serveErr  error
		shutErr   error
		wantIncpl bool
	}{
		{name: "cancel_clean", cancel: true, serveErr: http.ErrServerClosed},
		{name: "cancel_drain_failed", cancel: true, serveErr: http.ErrServerClosed, shutErr: shutdownErr, wantIncpl: true},
		{name: "serve_error_drains_without_cancel", serveErr: errors.New("listener failed")},
		{name: "clean_serve_drain_failed", shutErr: shutdownErr, wantIncpl: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			serving := make(chan struct{})
			stop := make(chan struct{})
			shutdownRan := false
			done := make(chan error, 1)
			go func() {
				done <- ServeUntilShutdown(ctx, func() error {
					close(serving)
					if tc.cancel {
						<-stop
					}
					return tc.serveErr
				}, func() error {
					shutdownRan = true
					if tc.cancel {
						close(stop)
					}
					return tc.shutErr
				})
			}()
			<-serving
			if tc.cancel {
				cancel()
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("ServeUntilShutdown did not return")
			}
			if !shutdownRan {
				t.Fatal("shutdown did not run")
			}
			if got := errors.Is(err, ErrShutdownIncomplete); got != tc.wantIncpl {
				t.Fatalf("err = %v, incomplete=%v want %v", err, got, tc.wantIncpl)
			}
			if tc.serveErr != nil && !errors.Is(err, tc.serveErr) {
				t.Fatalf("err = %v, want serve error %v kept", err, tc.serveErr)
			}
			if tc.shutErr != nil && !errors.Is(err, tc.shutErr) {
				t.Fatalf("err = %v, want shutdown cause %v kept", err, tc.shutErr)
			}
		})
	}
}

// A nil handler keeps net/http's DefaultServeMux behavior through the gate.
func TestGateWrapNilHandlerUsesDefaultServeMux(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Gate{}).Wrap(nil).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/httpstream-gate-nil-handler", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 from DefaultServeMux", rec.Code)
	}
}
