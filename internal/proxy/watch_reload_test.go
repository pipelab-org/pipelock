// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const watchReloadTarget = "https://api.vendor.example/resource"

func TestWatchOnlyExistingInterceptReload(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.Blocklist = []string{"api.vendor.example"}
	sc := scanner.MustNew(cfg)
	release, ok := sc.BeginUse()
	if !ok {
		t.Fatal("scanner lease unavailable")
	}
	path := filepath.Join(t.TempDir(), "watch.jsonl")
	logger, err := audit.New("json", "file", path, true, true)
	if err != nil {
		release()
		sc.Close()
		t.Fatal(err)
	}
	defer logger.Close()
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		release()
		sc.Close()
		t.Fatal(err)
	}
	defer p.Close()
	defer release()
	var hits atomic.Int32
	upstream := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		hits.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("unchanged")), Request: r}, nil
	})
	handler := newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: logger, Metrics: m, Proxy: p}, upstream)
	for _, step := range []struct {
		name          string
		watch, reload bool
		status        int
	}{
		{"initial", false, false, http.StatusForbidden},
		{"enable", true, true, http.StatusOK},
		{"unchanged enabled", true, true, http.StatusOK},
		{"disable", false, true, http.StatusForbidden},
		{"unchanged disabled", false, true, http.StatusForbidden},
	} {
		t.Run(step.name, func(t *testing.T) {
			if step.reload {
				next := p.cfgPtr.Load().Clone()
				next.WatchOnly = step.watch
				if !p.Reload(next, scanner.MustNew(next)) {
					t.Fatal("mode reload rejected")
				}
			}
			before := hits.Load()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, watchReloadTarget, nil))
			if w.Code != step.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, step.status, w.Body)
			}
			if (hits.Load() > before) != step.watch {
				t.Fatal("upstream dispatch disagrees with effective watch mode")
			}
			if step.watch && w.Body.String() != "unchanged" {
				t.Fatal("observation altered response")
			}
			stats := httptest.NewRecorder()
			m.StatsHandler().ServeHTTP(stats, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))
			var body struct {
				WatchOnly bool `json:"watch_only"`
			}
			if err := json.Unmarshal(stats.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.WatchOnly != step.watch {
				t.Fatal("status did not track applied reload")
			}
		})
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var changes []bool
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	for decoder.More() {
		var event struct {
			Event     string `json:"event"`
			WatchOnly bool   `json:"watch_only"`
		}
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Event == "watch_only_mode" {
			changes = append(changes, event.WatchOnly)
		}
	}
	if len(changes) != 2 || !changes[0] || changes[1] {
		t.Fatalf("expected loud enable/disable only, got %v", changes)
	}
}

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

func TestWatchOnlyInterceptRetainsAuthorityBoundary(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.Internal, cfg.WatchOnly = nil, enabled
		sc := scanner.MustNew(cfg)
		p, err := New(cfg, audit.NewNop(), sc, metrics.New())
		if err != nil {
			sc.Close()
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		var hits atomic.Int32
		upstream := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			hits.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("origin response")), Request: r}, nil
		})
		handler := newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: p.metrics, Proxy: p}, upstream)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, watchReloadTarget, nil)
		req.Host = "other.vendor.example"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || hits.Load() != 0 {
			t.Fatalf("watch=%t crossed CONNECT authority boundary: status=%d upstream=%d", enabled, w.Code, hits.Load())
		}
	}
}

// The in-process MCP listener fences its observations to the proxy's mode
// generation: it advances only when the mode changes, and a session retained
// across the change rejects a signal admitted under the previous generation.
func TestWatchOnlyGenerationFencesRetainedSessions(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SessionProfiling.Enabled = true
	cfg.AdaptiveEnforcement = *watchAdaptiveConfig()
	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		sc.Close()
		t.Fatal(err)
	}
	defer p.Close()
	scope := adaptiveScopeForHost("api.vendor.example")
	held := p.sessionMgrPtr.Load().GetOrCreate("held")
	admitted := p.WatchOnlyGeneration()
	if changed := p.Reload(p.cfgPtr.Load().Clone(), scanner.MustNew(cfg)); !changed || p.WatchOnlyGeneration() != admitted {
		t.Fatalf("an unchanged mode advanced the generation: %d -> %d (reload=%v)", admitted, p.WatchOnlyGeneration(), changed)
	}
	next := p.cfgPtr.Load().Clone()
	next.WatchOnly = true
	if !p.Reload(next, scanner.MustNew(next)) || p.WatchOnlyGeneration() == admitted {
		t.Fatalf("a mode change did not advance the generation (%d)", p.WatchOnlyGeneration())
	}
	held.ObserveWatchOnlySignalAt(admitted, scope, session.SignalBlock, watchAdaptiveConfig(), decide.EscalationParams{})
	if held.watchAdaptive != nil && held.watchAdaptive.ScopedThreatScore(scope) != 0 {
		t.Fatal("a signal from the previous mode generation scored the next trial")
	}
	held.ObserveWatchOnlySignalAt(p.WatchOnlyGeneration(), scope, session.SignalBlock, watchAdaptiveConfig(), decide.EscalationParams{})
	if held.watchAdaptive == nil || held.watchAdaptive.ScopedThreatScore(scope) == 0 {
		t.Fatal("a current-generation signal was not scored")
	}
}
