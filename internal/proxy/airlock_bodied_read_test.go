// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestClassifyRequestActionBodiedReadIsWrite(t *testing.T) {
	trailer := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", http.NoBody)
	trailer.Trailer = http.Header{"X-Exfil": nil}
	for _, tc := range []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"bodyless_get", httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", http.NoBody), true},
		{"bodyless_head", httptest.NewRequestWithContext(t.Context(), http.MethodHead, "http://x.example/", http.NoBody), true},
		{"bodied_get", httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", strings.NewReader("notes")), false},
		{"bodied_head", httptest.NewRequestWithContext(t.Context(), http.MethodHead, "http://x.example/", strings.NewReader("notes")), false},
		{"bodied_options", httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "http://x.example/", strings.NewReader("notes")), false},
		{"trailer_get", trailer, false},
		{"post", httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://x.example/", strings.NewReader("notes")), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, transport := range []string{TransportForward, TransportReverse} {
				if got, _ := ClassifyRequestAction(config.AirlockTierHard, tc.r, transport, false); got != tc.want {
					t.Fatalf("%s hard tier allowed=%v want %v", transport, got, tc.want)
				}
			}
			if got, _ := ClassifyRequestAction(config.AirlockTierHard, tc.r, TransportConnect, true); got != tc.want {
				t.Fatalf("intercepted CONNECT hard tier allowed=%v want %v", got, tc.want)
			}
			if got, _ := ClassifyRequestAction(config.AirlockTierSoft, tc.r, TransportForward, false); !got {
				t.Fatal("soft tier must stay observe-only")
			}
		})
	}
}

func TestClassifyRequestActionNilRequestFailsClosed(t *testing.T) {
	if allowed, _ := ClassifyRequestAction(config.AirlockTierHard, nil, TransportForward, false); allowed {
		t.Fatal("nil request admitted under hard tier")
	}
}

// A hard-tier quarantine admits reads only; a GET that carries a body must
// not reach the upstream through an intercepted tunnel.
func TestInterceptAirlockHardTierRefusesBodiedGET(t *testing.T) {
	// Taint off so only the airlock decides: the first response would
	// otherwise record untrusted exposure and taint would refuse the write.
	_, _, rec, target, ic := newTaintInterceptFixture(t, func(cfg *config.Config) { cfg.Taint.Enabled = false })
	ic.Recorder = rec
	_, _, _ = rec.AirlockForScope(adaptiveScopeForHost(interceptTaintHost)).SetTier(config.AirlockTierHard)
	var upstreamCalls int
	handler := newInterceptHandler(ic, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		upstreamCalls++
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	}))
	do := func(body io.Reader) int {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, body))
		return w.Code
	}
	if code := do(http.NoBody); code != http.StatusOK || upstreamCalls != 1 {
		t.Fatalf("bodyless GET under hard tier status=%d calls=%d", code, upstreamCalls)
	}
	if code := do(strings.NewReader("notes from the session")); code != http.StatusForbidden || upstreamCalls != 1 {
		t.Fatalf("bodied GET under hard tier status=%d calls=%d, want forbidden without upstream", code, upstreamCalls)
	}
}
