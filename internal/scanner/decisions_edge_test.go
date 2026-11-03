// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// lateCancelContext reports no error for its first okCalls Err calls and
// cancellation on every later call, so a test can place the cancellation at a
// chosen Err site (entry check, SSRF stage, final check) without a timing race.
type lateCancelContext struct {
	context.Context
	okCalls int32
	calls   atomic.Int32
}

func (c *lateCancelContext) Err() error {
	if c.calls.Add(1) <= c.okCalls {
		return nil
	}
	return context.Canceled
}

func decisionEdgeScanner(t *testing.T, mutate func(*config.Config)) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 0
	if mutate != nil {
		mutate(cfg)
	}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc
}

func TestURLDecisionsWebSocketScheme(t *testing.T) {
	t.Parallel()
	sc := decisionEdgeScanner(t, nil)
	result := sc.ScanWebSocket(t.Context(), "https://api.vendor.example/socket")
	if result.Allowed || result.Scanner != ScannerScheme {
		t.Fatalf("expected a scheme refusal: %+v", result)
	}
	if got := result.Decisions.checks[urlScheme]; got != DecisionFired|DecisionBlocked {
		t.Fatalf("scheme=%v, want fired and blocked", got)
	}
	for i := urlScheme + 1; i < urlCheckCount; i++ {
		if got := result.Decisions.checks[i]; got != DecisionNotEvaluated {
			t.Errorf("later check %d=%v, want not evaluated", i, got)
		}
	}
	if got := result.Decisions.checks[urlParser]; got != DecisionAllowed {
		t.Errorf("parser=%v, want allowed", got)
	}
}

func TestURLDecisionsFinalContextCheck(t *testing.T) {
	t.Parallel()
	sc := decisionEdgeScanner(t, nil)
	// Err calls: scan entry, SSRF stage, final check.
	result := sc.Scan(&lateCancelContext{Context: t.Context(), okCalls: 2}, "https://api.vendor.example/items")
	if result.Allowed || result.Scanner != ScannerContext || result.Reason != "request context cancelled" {
		t.Fatalf("expected the final context refusal: %+v", result)
	}
	if got := result.Decisions.checks[urlContext]; got != DecisionFired|DecisionBlocked {
		t.Fatalf("context=%v, want fired and blocked", got)
	}
	// Every check ran and allowed before the late cancellation.
	for i := urlLength; i < urlCheckCount; i++ {
		if got := result.Decisions.checks[i]; got != DecisionAllowed {
			t.Errorf("check %d=%v, want allowed", i, got)
		}
	}
}

// A client abort that lands in the SSRF stage is the context's refusal. It must
// not be counted as an SSRF finding: that would inflate the ssrf block count
// with ordinary disconnects.
func TestURLDecisionsSSRFStageCancellation(t *testing.T) {
	t.Parallel()
	sc := decisionEdgeScanner(t, nil)
	result := sc.Scan(&lateCancelContext{Context: t.Context(), okCalls: 1}, "https://api.vendor.example/items")
	if result.Allowed || result.Scanner != ScannerContext {
		t.Fatalf("expected the SSRF-stage context refusal: %+v", result)
	}
	if got := result.Decisions.checks[urlContext]; got != DecisionFired|DecisionBlocked {
		t.Fatalf("context=%v, want fired and blocked", got)
	}
	for i := urlLength; i < urlSSRF; i++ {
		if got := result.Decisions.checks[i]; got != DecisionAllowed {
			t.Errorf("check %d=%v, want allowed", i, got)
		}
	}
	for i := urlSSRF; i < urlCheckCount; i++ {
		if got := result.Decisions.checks[i]; got != DecisionNotEvaluated {
			t.Errorf("check %d=%v, want not evaluated", i, got)
		}
	}
}

func TestURLDecisionsDNSParamExclusionRelief(t *testing.T) {
	t.Parallel()
	target := "https://resolver.vendor.example/dns-query?dns=" +
		base64.RawURLEncoding.EncodeToString(dnsQueryWire(t, []string{decisionTestOpaque, "example", "test"}))
	control := decisionEdgeScanner(t, nil).Scan(t.Context(), target)
	if control.Allowed || control.Scanner != ScannerEntropy {
		t.Fatalf("control must be an entropy refusal: %+v", control)
	}
	if got := control.Decisions.checks[urlEntropy]; got != DecisionFired|DecisionBlocked {
		t.Fatalf("control entropy=%v, want fired and blocked", got)
	}
	sc := decisionEdgeScanner(t, func(cfg *config.Config) {
		cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{
			Host: "resolver.vendor.example", Path: "/dns-query", Param: "dns",
		}}
	})
	result := sc.Scan(t.Context(), target)
	if !result.Allowed {
		t.Fatalf("exclusion must release the finding: %+v", result)
	}
	if got, want := result.Decisions.checks[urlEntropy], DecisionAllowed|DecisionFired|DecisionRelieved; got != want {
		t.Fatalf("entropy=%v, want %v", got, want)
	}
}
