// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// isLoopbackPortProbe reports whether r has the shape of a local port
// scanner's probe: a queryless GET /. Tests that assert an upstream was never
// contacted ignore it. Every other request still counts, so a forwarding
// regression can't hide behind it.
func isLoopbackPortProbe(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == "/" && r.URL.RawQuery == "" && !r.URL.ForceQuery
}

// ignoreLoopbackPortProbes answers loopback port probes with 404 and passes
// every other request to next.
func ignoreLoopbackPortProbes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLoopbackPortProbe(r) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func TestIgnoreLoopbackPortProbes(t *testing.T) {
	cases := []struct {
		method, target string
		ignored        bool
	}{
		{http.MethodGet, "/", true},
		{http.MethodGet, "/?", false},
		{http.MethodGet, "/?q=1", false},
		{http.MethodGet, "/pkg", false},
		{http.MethodPost, "/", false},
		{http.MethodHead, "/", false},
	}
	for _, tc := range cases {
		served := false
		handler := ignoreLoopbackPortProbes(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			served = true
		}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), tc.method, tc.target, nil))
		if served == tc.ignored {
			t.Errorf("%s %s: served=%v, want ignored=%v", tc.method, tc.target, served, tc.ignored)
		}
		if tc.ignored && rec.Code != http.StatusNotFound {
			t.Errorf("%s %s: status=%d, want 404", tc.method, tc.target, rec.Code)
		}
	}
}
