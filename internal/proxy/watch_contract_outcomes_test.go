// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contententropy"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestWatchA2AObservationOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		result               mcp.A2AScanResult
		fallback, action     string
		enforced, incomplete bool
	}{
		{name: "policy default", result: mcp.A2AScanResult{Reason: "policy finding"}, action: config.ActionBlock},
		{name: "fallback action", result: mcp.A2AScanResult{Reason: "policy finding"}, fallback: config.ActionWarn, action: config.ActionWarn},
		{name: "resolved action", result: mcp.A2AScanResult{Reason: "policy finding", Action: config.ActionStrip}, fallback: config.ActionWarn, action: config.ActionStrip},
		{name: "content entropy", result: mcp.A2AScanResult{EntropyFinding: &contententropy.Finding{}}, fallback: config.ActionWarn, action: config.ActionWarn},
		{name: "injection", result: mcp.A2AScanResult{InjectFindings: []scanner.ResponseMatch{{PatternName: "test injection"}}}, fallback: config.ActionStrip, action: config.ActionStrip},
		{name: "incomplete", result: mcp.A2AScanResult{InspectionIncomplete: true}, fallback: config.ActionWarn, action: config.ActionBlock, enforced: true, incomplete: true},
		{name: "scanner failure", result: mcp.A2AScanResult{ScanError: "scanner failed"}, fallback: config.ActionWarn, action: config.ActionBlock, enforced: true, incomplete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			result := observeWatchA2A(tc.result, "a2a", tc.fallback, func(layer, reason, action string, n int64, enforced bool) {
				calls++
				if layer != "a2a" || reason == "" || action != tc.action || n != 0 || enforced != tc.enforced {
					t.Fatalf("observation=%q %q %q %d %t", layer, reason, action, n, enforced)
				}
			})
			if calls != 1 || result.Core != tc.enforced || (result.Uninspected != "") != tc.incomplete {
				t.Fatalf("calls=%d result=%+v", calls, result)
			}
		})
	}
}

type watchAccountingBudget struct {
	admission        error
	checks, requests int
	bytes            int64
	domain           string
}

func (b *watchAccountingBudget) CheckAdmission(domain string) error {
	b.checks++
	b.domain = domain
	return b.admission
}

func (b *watchAccountingBudget) RecordRequest(domain string, _ int64) error {
	b.requests++
	b.domain = domain
	return nil
}
func (b *watchAccountingBudget) RecordBytes(n int64) error { b.bytes += n; return nil }
func (*watchAccountingBudget) RemainingBytes() int64       { return 0 }

func TestWatchHTTPBudgetAdmissionStillAccounts(t *testing.T) {
	for _, exceeded := range []bool{false, true} {
		t.Run(map[bool]string{false: "within budget", true: "exceeded budget"}[exceeded], func(t *testing.T) {
			cfg := config.Defaults()
			cfg.WatchOnly = true
			cfg.Internal = nil
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			budget := &watchAccountingBudget{}
			if exceeded {
				budget.admission = errors.New("request budget exhausted")
			}
			payload := "complete response"
			w := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example/data", nil)
			serveWatchHTTP(w, req, watchHTTPOptions{Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New(), Transport: TransportForward, Budget: budget, MaxResponseBytes: 1024, Upstream: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader(payload)), Request: r}, nil
			})})
			if w.Code != http.StatusOK || w.Body.String() != payload || budget.checks != 1 || budget.requests != 1 || budget.bytes != int64(len(payload)) || budget.domain != "api.vendor.example" {
				t.Fatalf("status=%d body=%q budget=%+v", w.Code, w.Body.String(), budget)
			}
		})
	}
}

func TestWatchEvidenceTrailerDeclarations(t *testing.T) {
	h := http.Header{"x-pipelock-receipt": {"forged"}, "X-Vendor-Trace": {"retained"}, "Trailer": {"X-Pipelock-Receipt, X-Vendor-One, , x-pipelock-other", "X-Vendor-Two"}}
	stripWatchEvidenceHeaders(h)
	want := http.Header{"X-Vendor-Trace": {"retained"}, "Trailer": {"X-Vendor-One", "X-Vendor-Two"}}
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("headers=%v want=%v", h, want)
	}
	stripWatchEvidenceHeaders(h)
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("second pass changed trailers: %v", h)
	}
}

func TestWatchHTTPResponseObservationActions(t *testing.T) {
	for _, action := range []string{config.ActionAllow, config.ActionWarn, config.ActionStrip, config.ActionBlock, config.ActionAsk, "uninspected"} {
		for _, exemption := range []string{"none", "adaptive", "response", "disabled"} {
			t.Run(action+"/"+exemption, func(t *testing.T) {
				cfg := config.Defaults()
				cfg.WatchOnly = true
				cfg.AdaptiveEnforcement.Enabled = true
				cfg.AdaptiveEnforcement.EscalationThreshold = session.SignalPoints[session.SignalBlock]
				switch exemption {
				case "adaptive":
					cfg.AdaptiveEnforcement.ExemptDomains = []string{"api.vendor.example"}
				case "response":
					cfg.ResponseScanning.ExemptDomains = []string{"api.vendor.example"}
				case "disabled":
					cfg.AdaptiveEnforcement.Enabled = false
				}
				rec := &SessionState{}
				var finding atomic.Bool
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/data", nil)
				o := watchHTTPOptions{Config: cfg, Logger: audit.NewNop(), Metrics: metrics.New(), Transport: TransportForward}
				o.responseObserver(req, rec, &finding)("response", action)
				if finding.Load() != (action != config.ActionAllow) {
					t.Fatalf("finding=%t for %s", finding.Load(), action)
				}
				signal, scored := map[string]session.SignalType{config.ActionWarn: session.SignalWarning, config.ActionStrip: session.SignalStrip, config.ActionBlock: session.SignalBlock, config.ActionAsk: session.SignalBlock}[action]
				if exemption != "none" {
					scored = false
				}
				if scored {
					if rec.watchAdaptive == nil || rec.watchAdaptive.ScopedThreatScore(adaptiveScopeForHost(req.URL.Hostname())) != session.SignalPoints[signal] {
						t.Fatalf("missing shadow score for %s", action)
					}
				} else if rec.watchAdaptive != nil {
					t.Fatal("excluded action was scored")
				}
				if rec.ThreatScore() != 0 || rec.EscalationLevel() != 0 {
					t.Fatal("response observation changed enforcement")
				}
			})
		}
	}
}
