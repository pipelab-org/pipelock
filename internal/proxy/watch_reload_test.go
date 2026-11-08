// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const watchReloadTarget = "https://api.vendor.example/resource"

func TestWatchOnlyAdminAuthenticationSurvivesReload(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.KillSwitch.APIToken = testSessionAPIToken
	sc := scanner.MustNew(cfg)
	ks := killswitch.New(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithKillSwitch(ks), WithKillSwitchAPI(killswitch.NewAPIHandler(ks)))
	if err != nil {
		sc.Close()
		t.Fatal(err)
	}
	defer p.Close()
	var calls atomic.Int32
	p.SessionAPI().SetConfigControl(func() ReloadOutcome { calls.Add(1); return ReloadOutcome{Verdict: ReloadAccepted} }, func() ReloadOutcome { calls.Add(1); return ReloadOutcome{Verdict: ReloadAccepted} })
	handler := p.buildHandler(p.buildMux())
	for _, enabled := range []bool{true, false, true} {
		next := p.cfgPtr.Load().Clone()
		next.WatchOnly = enabled
		if !p.Reload(next, scanner.MustNew(next)) {
			t.Fatal("reload rejected")
		}
		for _, tc := range []struct{ path, method string }{
			{"/api/v1/config/status", http.MethodGet},
			{"/api/v1/config/reload", http.MethodPost},
			{"/api/v1/killswitch/status", http.MethodGet},
		} {
			for _, token := range []string{"", "wrong", testSessionAPIToken} {
				before := calls.Load()
				req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil)
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				want := http.StatusUnauthorized
				if token == testSessionAPIToken {
					want = http.StatusOK
				}
				if w.Code != want {
					t.Fatalf("watch=%t path=%s auth=%t status=%d want=%d body=%s", enabled, tc.path, token == testSessionAPIToken, w.Code, want, w.Body)
				}
				if token != testSessionAPIToken && calls.Load() != before {
					t.Fatal("unauthenticated request invoked admin callback")
				}
			}
		}
	}
}
