// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigControlAuthenticationAndInput(t *testing.T) {
	for _, tc := range []struct {
		name, method, token, query, body string
		status                           int
		configured                       bool
	}{
		{"accepted", http.MethodPost, testSessionAPIToken, "", "", http.StatusOK, true},
		{"missing", http.MethodPost, "", "", "", http.StatusUnauthorized, true},
		{"wrong", http.MethodPost, "wrong", "", "", http.StatusUnauthorized, true},
		{"query path", http.MethodPost, testSessionAPIToken, "?path=/other", "", http.StatusBadRequest, true},
		{"body path", http.MethodPost, testSessionAPIToken, "", `{"path":"/other"}`, http.StatusBadRequest, true},
		{"method", http.MethodGet, testSessionAPIToken, "", "", http.StatusMethodNotAllowed, true},
		{"unavailable", http.MethodPost, testSessionAPIToken, "", "", http.StatusServiceUnavailable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestSessionAPIHandler(t, nil)
			calls := 0
			if tc.configured {
				h.SetConfigControl(nil, func() ReloadOutcome { calls++; return ReloadOutcome{Verdict: ReloadAccepted} })
			}
			req := httptest.NewRequestWithContext(t.Context(), tc.method, "/api/v1/config/reload"+tc.query, strings.NewReader(tc.body))
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			h.HandleConfigReload(w, req)
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if (calls == 1) != (tc.status == http.StatusOK) {
				t.Fatalf("calls=%d", calls)
			}
		})
	}
}

func TestConfigControlRotatedCredential(t *testing.T) {
	h := newTestSessionAPIHandler(t, nil)
	h.SetConfigControl(func() ReloadOutcome { return ReloadOutcome{InstanceID: "daemon"} }, nil)
	rotated := "rotated-" + testSessionAPIToken
	h.SetAPIToken(rotated)
	for _, tc := range []struct {
		token  string
		status int
	}{{testSessionAPIToken, http.StatusUnauthorized}, {rotated, http.StatusOK}, {"", http.StatusUnauthorized}} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/config/status", nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		h.HandleConfigStatus(w, req)
		if w.Code != tc.status {
			t.Fatalf("status=%d want=%d", w.Code, tc.status)
		}
	}
	h.SetAPIToken("")
	w := httptest.NewRecorder()
	h.HandleConfigStatus(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/config/status", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled=%d", w.Code)
	}
}
