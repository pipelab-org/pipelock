// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestAgentListenerNeverServesMetrics(t *testing.T) {
	for _, address := range []string{"", "127.0.0.1:9091"} {
		for _, active := range []bool{false, true} {
			t.Run(fmt.Sprintf("address=%s/kill=%t", address, active), func(t *testing.T) {
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.MetricsListen = address
				cfg.KillSwitch.Enabled = active
				exempt := true
				cfg.KillSwitch.MetricsExempt = &exempt
				sc := scanner.MustNew(cfg)
				defer sc.Close()
				p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithKillSwitch(killswitch.New(cfg)))
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				for _, reload := range []bool{false, true} {
					if reload {
						// An unrelated reload must not register routes or reset the kill switch.
						candidate := cfg.Clone()
						explain := true
						candidate.ExplainBlocks = &explain
						if !p.Reload(candidate, sc) {
							t.Fatal("unrelated reload rejected")
						}
					}
					for _, path := range []string{"/health", "/metrics", "/stats"} {
						rec := httptest.NewRecorder()
						p.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
						want := http.StatusNotFound
						if path == "/health" {
							want = http.StatusOK
						}
						if path == "/stats" && active {
							want = http.StatusServiceUnavailable
						}
						if rec.Code != want {
							t.Fatalf("%s = %d, want %d: %s", path, rec.Code, want, rec.Body.String())
						}
					}
				}
			})
		}
	}
}
