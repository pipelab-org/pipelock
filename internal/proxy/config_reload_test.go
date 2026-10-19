// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
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

func TestConfigControlDuringUncertainActivation(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, token string
		apiExempt, separate       bool
		status, calls             int
	}{
		{"status", http.MethodGet, "/api/v1/config/status", testSessionAPIToken, true, false, http.StatusOK, 1},
		{"reload", http.MethodPost, "/api/v1/config/reload", testSessionAPIToken, true, false, http.StatusOK, 1},
		{"missing token", http.MethodPost, "/api/v1/config/reload", "", true, false, http.StatusUnauthorized, 0},
		{"wrong token", http.MethodGet, "/api/v1/config/status", "wrong", true, false, http.StatusUnauthorized, 0},
		{"disabled exemption", http.MethodGet, "/api/v1/config/status", testSessionAPIToken, false, false, http.StatusServiceUnavailable, 0},
		{"separate listener", http.MethodPost, "/api/v1/config/reload", testSessionAPIToken, true, true, http.StatusServiceUnavailable, 0},
		{"ordinary traffic", http.MethodGet, "/fetch?url=https://api.vendor.example/", testSessionAPIToken, true, false, http.StatusServiceUnavailable, 0},
		{"destination path", http.MethodGet, "https://api.vendor.example/api/v1/config/status", testSessionAPIToken, true, false, http.StatusForbidden, 0},
		{"connect", http.MethodConnect, "https://api.vendor.example/api/v1/config/status", testSessionAPIToken, true, false, http.StatusServiceUnavailable, 0},
		{"encoded path", http.MethodGet, "/api/v1/config/%73tatus", testSessionAPIToken, true, false, http.StatusServiceUnavailable, 0},
		{"path suffix", http.MethodGet, "/api/v1/config/status/extra", testSessionAPIToken, true, false, http.StatusServiceUnavailable, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.KillSwitch.APIToken = testSessionAPIToken
			cfg.KillSwitch.APIExempt = &tc.apiExempt
			if tc.separate {
				cfg.KillSwitch.APIListen = "127.0.0.1:0"
			}
			ks := killswitch.New(cfg)
			ks.SetSeparateAPIPort(tc.separate)
			ks.SetConductorApplyFailure(true, "activation uncertain")
			p, err := New(cfg, audit.NewNop(), nil, metrics.New(), WithKillSwitch(ks))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			calls := 0
			callback := func() ReloadOutcome { calls++; return ReloadOutcome{Verdict: ReloadAccepted} }
			p.SessionAPI().SetConfigControl(callback, callback)
			req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			p.buildHandler(p.buildMux()).ServeHTTP(w, req)
			if w.Code != tc.status || calls != tc.calls {
				t.Fatalf("status=%d want=%d calls=%d want=%d body=%s", w.Code, tc.status, calls, tc.calls, w.Body.String())
			}
			if !ks.ConductorApplyFailure() {
				t.Fatal("config control cleared uncertainty")
			}
		})
	}
}
