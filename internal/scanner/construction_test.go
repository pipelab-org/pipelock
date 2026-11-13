// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func constructionConfig(custom bool) *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	if custom {
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
			Name:     "Custom construction pattern",
			Regex:    `\bfixture_[A-Z0-9]{20}\b`,
			Severity: config.SeverityHigh,
		})
	}
	return cfg
}

// Compiled syntax is shared across scanners; the rules and their metadata are
// not. Each scanner sees exactly the patterns of its own configuration.
func TestScannerConstructionPolicyIsolation(t *testing.T) {
	cfg := constructionConfig(false)
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Custom marker", Regex: `marker_old`, Severity: config.SeverityHigh}}
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "Custom response", Regex: `response_old`}}
	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	cfg.DLP.Patterns[0].Regex = `marker_new`
	cfg.ResponseScanning.Patterns[0].Regex = `response_new`
	second, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	cfg.DLP.Patterns = nil
	cfg.ResponseScanning.Patterns = nil
	third, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	for i, s := range []*Scanner{first, second, third} {
		for j, text := range []string{"marker_old", "marker_new"} {
			if got := s.ScanTextForDLP(t.Context(), text); got.Clean != (i != j) {
				t.Fatalf("scanner %d, %q: %+v", i, text, got)
			}
		}
		for j, text := range []string{"response_old", "response_new"} {
			matches := matchPatternsAgainst(s.responsePatterns, text)
			if (len(matches) > 0) != (i == j) {
				t.Fatalf("scanner %d, %q: %+v", i, text, matches)
			}
		}
	}
}

func TestScannerConstructionCompileErrors(t *testing.T) {
	for _, response := range []bool{false, true} {
		cfg := constructionConfig(true)
		warm, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		warm.Close()
		if response {
			cfg.ResponseScanning.Enabled = true
			cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "Invalid response", Regex: "["}}
		} else {
			cfg.DLP.Patterns[len(cfg.DLP.Patterns)-1].Regex = "["
		}
		for range 2 {
			if s, err := New(cfg); err == nil || s != nil {
				if s != nil {
					s.Close()
				}
				t.Fatalf("invalid expression accepted: scanner=%v, err=%v", s, err)
			}
		}
	}
}

func TestScannerConstructionAllocationWork(t *testing.T) {
	for _, custom := range []bool{false, true} {
		cfg := constructionConfig(custom)
		allocations := testing.AllocsPerRun(1, func() {
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
		})
		// The uncached constructor performs over half a million allocations.
		// This work-unit ceiling leaves headroom for scanner-local policy.
		if allocations > 100_000 {
			t.Errorf("custom=%v: construction allocated %.0f objects, want <=100000", custom, allocations)
		}
	}
}

func TestScannerConstructionMetadataIsolation(t *testing.T) {
	cfg := constructionConfig(false)
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Custom marker", Regex: `marker_shared`, Severity: config.SeverityHigh}}
	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	cfg.DLP.Patterns[0].Name = "Renamed marker"
	cfg.DLP.Patterns[0].Severity = config.SeverityLow
	cfg.DLP.Patterns[0].Action = config.ActionWarn
	second, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	before := first.ScanTextForDLP(t.Context(), "marker_shared")
	after := second.ScanTextForDLP(t.Context(), "marker_shared")
	if before.Clean || len(before.Matches) != 1 || before.Matches[0].PatternName != "Custom marker" || before.Matches[0].Severity != config.SeverityHigh || before.Matches[0].Warn {
		t.Fatalf("old metadata changed: %+v", before)
	}
	// A warn-only match is informational: the scan stays clean.
	if !after.Clean || len(after.InformationalMatches) != 1 || after.InformationalMatches[0].PatternName != "Renamed marker" || after.InformationalMatches[0].Severity != config.SeverityLow || !after.InformationalMatches[0].Warn {
		t.Fatalf("new metadata not applied: %+v", after)
	}
}

// A pattern removed from configuration leaves the shared compile cache once
// later builds stop using it, while built-in expressions stay shared.
func TestScannerConstructionDropsRemovedExpressions(t *testing.T) {
	cfg := constructionConfig(false)
	cfg.DLP.Patterns = append(append([]config.DLPPattern(nil), cfg.DLP.Patterns...), config.DLPPattern{
		Name: "Removed marker", Regex: "REMOVEDLITERAL[0-9]{8}", Severity: config.SeverityHigh,
	})
	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	shared := first.dlpPatterns[0].re
	first.Close()
	if !regexpCacheContains("REMOVEDLITERAL") {
		t.Fatal("live configuration was absent from the compile cache")
	}
	for range scannerRegexpIdleBuilds + 1 {
		s, err := New(constructionConfig(false))
		if err != nil {
			t.Fatal(err)
		}
		if s.dlpPatterns[0].re != shared {
			t.Fatal("built-in expression was recompiled")
		}
		s.Close()
	}
	if regexpCacheContains("REMOVEDLITERAL") {
		t.Fatal("removed configuration remained in the compile cache")
	}
}

func regexpCacheContains(fragment string) bool {
	scannerRegexpCache.mu.Lock()
	defer scannerRegexpCache.mu.Unlock()
	for expression := range scannerRegexpCache.expressions {
		if strings.Contains(expression, fragment) {
			return true
		}
	}
	return false
}
