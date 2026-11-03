// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const decisionTestOpaque = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6uX9"

func TestURLDecisionsShortCircuit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		target string
		check  int
		setup  func(*config.Config)
		prime  func(*Scanner)
	}{
		{"length", "https://api.vendor.example/items", urlLength, func(c *config.Config) { c.FetchProxy.Monitoring.MaxURLLength = 1 }, nil},
		{"parser", "https://api.vendor.example/%xx", urlParser, nil, nil},
		{"destination", "https:///items", urlParser, nil, nil},
		{"scheme", "ftp://api.vendor.example/items", urlScheme, nil, nil},
		{"CRLF", "https://api.vendor.example/%0d%0a", urlCRLF, nil, nil},
		{"traversal", "https://api.vendor.example/../items", urlTraversal, nil, nil},
		{"allowlist", "https://api.vendor.example/items", urlAllowlist, func(c *config.Config) { c.Mode = config.ModeStrict; c.APIAllowlist = []string{"other.vendor.example"} }, nil},
		{"blocklist", "https://api.vendor.example/items", urlBlocklist, func(c *config.Config) { c.FetchProxy.Monitoring.Blocklist = []string{"api.vendor.example"} }, nil},
		{"core SSRF", "https://127.0.0.1/items", urlCoreSSRF, nil, nil},
		{"core DLP", "https://api.vendor.example/?key=AKIA" + strings.Repeat("B", 16), urlCoreDLP, nil, nil},
		{"DLP", "https://api.vendor.example/decision_block", urlDLP, func(c *config.Config) {
			c.DLP.Patterns = []config.DLPPattern{{Name: "Decision block", Regex: "decision_block", Severity: config.SeverityHigh}}
		}, nil},
		{"entropy", "https://api.vendor.example/" + decisionTestOpaque, urlEntropy, nil, nil},
		{"subdomain", "https://" + decisionTestOpaque + ".vendor.example/", urlSubdomainEntropy, nil, nil},
		{"nested", "https://api.vendor.example/?next=https://127.0.0.1/", urlNested, nil, nil},
		{"rate", "https://api.vendor.example/items", urlRateLimit, func(c *config.Config) { c.FetchProxy.Monitoring.MaxReqPerMinute = 1 }, func(s *Scanner) { s.Scan(t.Context(), "https://api.vendor.example/items") }},
		{"budget", "https://api.vendor.example/items", urlDataBudget, func(c *config.Config) { c.FetchProxy.Monitoring.MaxDataPerMinute = 1 }, func(s *Scanner) { s.RecordRequest("api.vendor.example", 2) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
			cfg.FetchProxy.Monitoring.MaxDataPerMinute = 0
			if tc.setup != nil {
				tc.setup(cfg)
			}
			sc := MustNew(cfg)
			t.Cleanup(sc.Close)
			if tc.prime != nil {
				tc.prime(sc)
			}
			result := sc.Scan(t.Context(), tc.target)
			if result.Allowed {
				t.Fatalf("expected a block for %s", tc.name)
			}
			if got := result.Decisions.checks[tc.check]; got != DecisionFired|DecisionBlocked {
				t.Fatalf("check %d outcome=%v, want fired and blocked; result=%+v", tc.check, got, result)
			}
			for i := tc.check + 1; i < urlCheckCount; i++ {
				// Destination validation follows the scheme check under the parser label.
				if tc.name == "destination" && i == urlScheme {
					continue
				}
				if got := result.Decisions.checks[i]; got != DecisionNotEvaluated {
					t.Errorf("later check %d=%v, want not evaluated", i, got)
				}
			}
		})
	}
}

func TestURLDecisionsIssuerRelief(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		target string
	}{
		{name: "query", target: "https://api.vendor.example/items?cursor=" + decisionTestOpaque},
		{name: "ambiguous query", target: "https://api.vendor.example/items?cursor=" + decisionTestOpaque + ";page=1"},
		{name: "path", target: "https://api.vendor.example/" + decisionTestOpaque},
		{name: "segment", target: "https://api.vendor.example/items/" + decisionTestOpaque},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			sc := MustNew(cfg)
			t.Cleanup(sc.Close)
			ctx := t.Context()
			switch tc.name {
			case "query", "ambiguous query":
				ctx = WithIssuerQueryAllowance(ctx, func(key, value string) bool { return key == "cursor" && value == decisionTestOpaque })
			case "path":
				ctx = WithIssuerPathAllowance(ctx, func(path string) bool { return path == "/"+decisionTestOpaque })
			case "segment":
				ctx = WithIssuerSegmentAllowance(ctx, func(segment string) bool { return segment == decisionTestOpaque })
			}
			before := sc.Scan(t.Context(), tc.target)
			if before.Allowed || before.Scanner != ScannerEntropy {
				t.Fatalf("control=%+v", before)
			}
			after := sc.Scan(ctx, tc.target)
			if !after.Allowed {
				t.Fatalf("relieved scan=%+v", after)
			}
			want := DecisionAllowed | DecisionFired | DecisionRelieved
			if got := after.Decisions.checks[urlEntropy]; got != want {
				t.Fatalf("entropy=%v, want %v", got, want)
			}
			data, err := json.Marshal(after)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "Decisions") || strings.Contains(string(data), "relief") {
				t.Fatalf("private trace serialized: %s", data)
			}
		})
	}
}

func TestURLDecisionsRange(t *testing.T) {
	t.Parallel()
	var empty URLDecisions
	empty.Range(func(_, _ string, _ Decision) { t.Fatal("zero trace emitted a check") })
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name: "Decision warning", Regex: "decision_warning", Action: config.ActionWarn, Severity: config.SeverityHigh,
	})
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	result := sc.Scan(t.Context(), "https://api.vendor.example/decision_warning")
	if !result.Allowed || len(result.WarnMatches) == 0 {
		t.Fatalf("warning changed enforcement or lost metadata: %+v", result)
	}
	seen := make(map[string]bool)
	result.Decisions.Range(func(check, part string, outcome Decision) {
		if seen[check] {
			t.Fatalf("duplicate check %q", check)
		}
		seen[check] = true
		wantPart := "url"
		if check == DecisionCheckNestedDestination {
			wantPart = "url_query"
		}
		if part != wantPart {
			t.Errorf("check=%s part=%s, want %s", check, part, wantPart)
		}
		wantOutcome := DecisionAllowed
		if check == ScannerDLP {
			wantOutcome |= DecisionFired
		}
		if outcome != wantOutcome {
			t.Errorf("check=%s outcome=%v, want %v", check, outcome, wantOutcome)
		}
	})
	if len(seen) != urlCheckCount {
		t.Fatalf("checks=%d, want %d", len(seen), urlCheckCount)
	}
}
