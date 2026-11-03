// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const decisionOpaque = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6uX9"

// decisionGoogleKey matches the shipped Google API Key pattern, whose audience
// is compiled in. Built at runtime so no credential literal sits in source.
var decisionGoogleKey = "AI" + "za" + "Sy9fK2qLmR7xWvT4bNcZ8pH3jD6gE1uYo0A"

func decisionScanner(t *testing.T) *scanner.Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 0
	cfg.DLP.Patterns = append(cfg.DLP.Patterns,
		config.DLPPattern{Name: "Decision warning", Regex: "decision_warning", Severity: config.SeverityHigh, Action: config.ActionWarn},
	)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc
}

func TestURLDecisionOutcomes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		target string
		allow  bool
		check  string
		// not evaluated, allowed, fired, blocked, relieved.
		want   [decisionOutcomeCount]float64
		issuer bool
	}{
		{"clean", "https://api.vendor.example/items", true, scanner.ScannerEntropy, [decisionOutcomeCount]float64{0, 1, 0, 0, 0}, false},
		// decisionScanner clears cfg.Internal, which disables the SSRF check, so
		// this row covers only the disabled path. TestURLDecisionSSRFEnabled covers
		// the enabled check.
		{"ssrf", "https://api.vendor.example/items", true, scanner.ScannerSSRF, [decisionOutcomeCount]float64{0, 1, 0, 0, 0}, false},
		{"early block", "ftp://api.vendor.example/items", false, scanner.ScannerScheme, [decisionOutcomeCount]float64{0, 0, 1, 1, 0}, false},
		{"not evaluated", "ftp://api.vendor.example/items", false, scanner.ScannerEntropy, [decisionOutcomeCount]float64{1, 0, 0, 0, 0}, false},
		{"warning", "https://api.vendor.example/decision_warning", true, scanner.ScannerDLP, [decisionOutcomeCount]float64{0, 1, 1, 0, 0}, false},
		{"entropy block", "https://api.vendor.example/items?cursor=" + decisionOpaque, false, scanner.ScannerEntropy, [decisionOutcomeCount]float64{0, 0, 1, 1, 0}, false},
		{"issuer relief", "https://api.vendor.example/items?cursor=" + decisionOpaque, true, scanner.ScannerEntropy, [decisionOutcomeCount]float64{0, 1, 1, 0, 1}, true},
		{"audience relief", "https://maps.googleapis.com/maps/api/js?key=" + decisionGoogleKey, true, scanner.ScannerDLP, [decisionOutcomeCount]float64{0, 1, 1, 0, 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sc := decisionScanner(t)
			ctx := t.Context()
			if tc.issuer {
				ctx = scanner.WithIssuerQueryAllowance(ctx, func(key, value string) bool {
					return key == "cursor" && value == decisionOpaque
				})
			}
			result := sc.Scan(ctx, tc.target)
			if result.Allowed != tc.allow {
				t.Fatalf("allowed=%v, want %v: %s", result.Allowed, tc.allow, result.Reason)
			}
			m := New()
			m.RecordURLDecisions("fetch", result.Decisions)
			for i, want := range tc.want {
				if got := testutil.ToFloat64(m.urlDecisions[urlDecisionKey{"fetch", tc.check}][i]); got != want {
					t.Errorf("outcome %d = %v, want %v", i, got, want)
				}
			}
		})
	}
}

func TestURLDecisionLabelsBounded(t *testing.T) {
	t.Parallel()
	const canary = "decisionCanaryPrivateRequestData"
	sc := decisionScanner(t)
	m := New()
	for _, target := range []string{
		"https://" + canary + ".vendor.example/" + canary + "?cursor=" + canary,
		"ftp://" + canary + ".vendor.example/",
		"https://api.vendor.example/%xx?cursor=" + canary,
	} {
		result := sc.Scan(t.Context(), target)
		m.RecordURLDecisions("fetch", result.Decisions)
		m.RecordURLDecisions(canary, result.Decisions)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	m.PrometheusHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), canary) {
		t.Fatal("request canary reached metrics output")
	}
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "pipelock_url_check_decisions_total" {
			continue
		}
		if got, want := len(family.Metric), 17*5*6; got != want {
			t.Fatalf("series = %d, want %d", got, want)
		}
		for _, metric := range family.Metric {
			if len(metric.Label) != 4 {
				t.Fatalf("labels = %d, want 4", len(metric.Label))
			}
			for _, label := range metric.Label {
				if label.GetName() == "part" && label.GetValue() != "url" && label.GetValue() != "url_query" {
					t.Fatalf("unexpected request part %q", label.GetValue())
				}
			}
		}
	}
}

func TestURLDecisionRecordingConcurrent(t *testing.T) {
	result := decisionScanner(t).Scan(t.Context(), "https://api.vendor.example/items")
	m := New()
	var wg sync.WaitGroup
	const workers = 8
	for range workers {
		wg.Go(func() { m.RecordURLDecisions("fetch", result.Decisions) })
	}
	wg.Wait()
	if got := testutil.ToFloat64(m.urlDecisions[urlDecisionKey{"fetch", scanner.ScannerEntropy}][1]); got != workers {
		t.Fatalf("allowed=%v, want %d", got, workers)
	}
	if got := testing.AllocsPerRun(10, func() { m.RecordURLDecisions("fetch", result.Decisions) }); got != 0 {
		t.Fatalf("recording allocations=%v, want 0", got)
	}
}

func TestURLDecisionNoScan(t *testing.T) {
	t.Parallel()
	var nilMetrics *Metrics
	nilMetrics.RecordURLDecisions("fetch", scanner.URLDecisions{})
	emptyMetrics := &Metrics{}
	emptyMetrics.RecordURLDecisions("fetch", decisionScanner(t).Scan(t.Context(), "ftp://api.vendor.example").Decisions)
	m := New()
	m.RecordURLDecisions("fetch", scanner.URLDecisions{})
	var nilContext context.Context
	result := decisionScanner(t).Scan(nilContext, "https://api.vendor.example/items")
	m.RecordURLDecisions("fetch", result.Decisions)
	if got := testutil.ToFloat64(m.urlDecisions[urlDecisionKey{"fetch", scanner.ScannerContext}][3]); got != 1 {
		t.Fatalf("context blocks=%v, want 1", got)
	}
	if got := testutil.ToFloat64(m.urlDecisions[urlDecisionKey{"fetch", scanner.ScannerLength}][0]); got != 1 {
		t.Fatalf("length not evaluated=%v, want 1", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result = decisionScanner(t).Scan(ctx, "https://api.vendor.example/items")
	m.RecordURLDecisions("fetch", result.Decisions)
	if got := testutil.ToFloat64(m.urlDecisions[urlDecisionKey{"fetch", scanner.ScannerContext}][3]); got != 2 {
		t.Fatalf("context blocks=%v, want 2", got)
	}
}

// The registered series and the scanner trace name their checks in two
// separate lists. A label present in only one of them is silently dropped at
// record time, so compare the two sets directly.
func TestURLDecisionRegistrationMatchesTrace(t *testing.T) {
	t.Parallel()
	result := decisionScanner(t).Scan(t.Context(), "https://api.vendor.example/items")
	traced := map[[2]string]bool{}
	result.Decisions.Range(func(check, part string, _ scanner.Decision) {
		traced[[2]string{check, part}] = true
	})
	if len(traced) == 0 {
		t.Fatal("scan produced no decision trace")
	}
	families, err := New().Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	registered := map[[2]string]bool{}
	for _, family := range families {
		if family.GetName() != "pipelock_url_check_decisions_total" {
			continue
		}
		for _, metric := range family.Metric {
			var check, part string
			for _, label := range metric.Label {
				switch label.GetName() {
				case "check":
					check = label.GetValue()
				case "part":
					part = label.GetValue()
				}
			}
			registered[[2]string{check, part}] = true
		}
	}
	for pair := range traced {
		if !registered[pair] {
			t.Errorf("traced check %q part %q has no registered series", pair[0], pair[1])
		}
	}
	for pair := range registered {
		if !traced[pair] {
			t.Errorf("registered check %q part %q is never traced", pair[0], pair[1])
		}
	}
}

// Every series exists from registry creation, before any scan is recorded,
// so a scrape never has to infer a missing check from an absent series.
func TestURLDecisionSeriesCreatedAtStartup(t *testing.T) {
	t.Parallel()
	families, err := New().Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "pipelock_url_check_decisions_total" {
			continue
		}
		if got, want := len(family.Metric), 17*5*6; got != want {
			t.Fatalf("series at startup = %d, want %d", got, want)
		}
		outcomes := map[string]bool{}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "outcome" {
					outcomes[label.GetValue()] = true
				}
			}
		}
		for _, want := range []string{"not_evaluated", "allowed", "fired", "blocked", "relieved"} {
			if !outcomes[want] {
				t.Errorf("outcome label %q missing at startup", want)
			}
		}
		return
	}
	t.Fatal("pipelock_url_check_decisions_total not registered at startup")
}

// With internal ranges configured, the SSRF check evaluates literal IP
// destinations without DNS. The operator range here is outside the core SSRF
// floor, so the configured check is the one that decides.
func TestURLDecisionSSRFEnabled(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Internal = []string{"198.51.100.0/24"}
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 0
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		name   string
		target string
		allow  bool
		// not evaluated, allowed, fired, blocked, relieved.
		want [decisionOutcomeCount]float64
	}{
		{"outside internal ranges", "https://203.0.113.10/items", true, [decisionOutcomeCount]float64{0, 1, 0, 0, 0}},
		{"inside internal range", "https://198.51.100.10/items", false, [decisionOutcomeCount]float64{0, 0, 1, 1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := sc.Scan(t.Context(), tc.target)
			if result.Allowed != tc.allow {
				t.Fatalf("allowed=%v, want %v: %s (%s)", result.Allowed, tc.allow, result.Reason, result.Scanner)
			}
			if !tc.allow && result.Scanner != scanner.ScannerSSRF {
				t.Fatalf("refused by %q, want the configured SSRF check", result.Scanner)
			}
			m := New()
			m.RecordURLDecisions("fetch", result.Decisions)
			for i, want := range tc.want {
				if got := testutil.ToFloat64(m.urlDecisions[urlDecisionKey{"fetch", scanner.ScannerSSRF}][i]); got != want {
					t.Errorf("outcome %d = %v, want %v", i, got, want)
				}
			}
		})
	}
}
