// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/httpstream"
)

// A downstream copier can close the pipe and return while onComplete still
// owes receipt work. Shutdown sees no HTTP handler; the registered scan must
// keep that drain incomplete until its callback actually finishes.
func TestReverseSSECompletionDrain(t *testing.T) {
	for _, pending := range []bool{true, false} {
		t.Run(map[bool]string{true: "pending", false: "finished"}[pending], func(t *testing.T) {
			callback, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
				select {
				case <-finished:
				case <-time.After(5 * time.Second):
					t.Error("completion did not stop")
				}
			}()
			gate := &httpstream.Gate{}
			sc := ssetestScanner(t)
			h := gate.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				resp := &http.Response{Body: io.NopCloser(strings.NewReader(""))}
				body := HijackResponseForSSE(r.Context(), resp, sc, SSEDispatchOptions{}, func(error) {
					defer close(finished)
					close(callback)
					<-release
				})
				_ = body.Close()
			}))
			// The callback channel proves receipt completion started after the
			// handler returned; DrainServer must join the remaining work.
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
			select {
			case <-callback:
			case <-time.After(5 * time.Second):
				t.Fatal("completion did not start")
			}
			if !pending {
				close(release)
			}
			ctx, cancel := context.WithTimeout(t.Context(), drainTestGrace)
			defer cancel()
			err := httpstream.DrainServer(ctx, httpstream.GatedServer{Server: &http.Server{Handler: h, ReadHeaderTimeout: time.Second}, Gate: gate})
			if pending && !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("pending SSE completion drain = %v, want deadline", err)
			}
			if !pending && err != nil {
				t.Errorf("finished SSE completion drain = %v", err)
			}
			if pending {
				close(release)
			}
			// Drain a second time with a fresh deadline to prove completion releases
			// the gate, including when the previous drain fenced admission.
			joined, joinCancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer joinCancel()
			if err := httpstream.DrainServer(joined, httpstream.GatedServer{Server: &http.Server{Handler: h, ReadHeaderTimeout: time.Second}, Gate: gate}); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestSSERefusesWorkAfterDrain(t *testing.T) {
	gate := &httpstream.Gate{}
	var requestCtx context.Context
	h := gate.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { requestCtx = r.Context() }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if err := httpstream.DrainServer(t.Context(), httpstream.GatedServer{Server: &http.Server{Handler: h, ReadHeaderTimeout: time.Second}, Gate: gate}); err != nil {
		t.Fatal(err)
	}
	called := make(chan struct{}, 1)
	body := HijackResponseForSSE(requestCtx, &http.Response{Body: io.NopCloser(strings.NewReader(""))}, ssetestScanner(t), SSEDispatchOptions{}, func(error) { called <- struct{}{} })
	defer func() { _ = body.Close() }()
	if _, err := io.ReadAll(body); !errors.Is(err, httpstream.ErrShutdownIncomplete) {
		t.Fatalf("closed gate scan = %v", err)
	}
	select {
	case <-called:
		t.Fatal("refused work called receipt completion")
	default:
	}
}
