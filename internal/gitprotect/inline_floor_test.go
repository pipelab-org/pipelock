// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package gitprotect

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestScanDiffInlineCoreFloor(t *testing.T) {
	key := "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"
	for _, rule := range []string{"AWS Access ID", "aws access id", "Custom Secret", "Prompt Injection"} {
		for _, marker := range []string{"# pipelock:ignore", "// pipelock:ignore " + strings.ToUpper(rule)} {
			t.Run(rule+"/"+marker, func(t *testing.T) {
				patterns := CompileDLPPatterns([]config.DLPPattern{{Name: rule, Regex: config.AWSAccessIDRegex, Severity: config.SeverityCritical}})
				diff := "diff --git a/fixture b/fixture\n--- a/fixture\n+++ b/fixture\n@@ -0,0 +1 @@\n+value=" + key + " " + marker + "\n"
				result, err := ScanDiff(diff, patterns)
				if err != nil {
					t.Fatal(err)
				}
				wantKept := 1
				if rule == "Custom Secret" {
					wantKept = 0
				}
				if len(result.Findings) != wantKept || len(result.Suppressed) != 1-wantKept {
					t.Fatalf("kept=%d suppressed=%d, want %d/%d", len(result.Findings), len(result.Suppressed), wantKept, 1-wantKept)
				}
				if wantKept == 1 && (result.Findings[0].Pattern != rule || strings.Contains(result.Findings[0].Content, key)) {
					t.Fatalf("pattern name or redaction changed: %+v", result.Findings[0])
				}
			})
		}
	}
}

func TestScanDiffInlineDefaultPatternNames(t *testing.T) {
	patterns := CompileDLPPatterns(config.Defaults().DLP.Patterns)
	key := "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"
	providerKey := "sk-" + "ant-api03-" + strings.Repeat("a", 93) + "AA"
	diff := "diff --git a/fixture b/fixture\n--- a/fixture\n+++ b/fixture\n@@ -0,0 +1,2 @@\n+value=" + key + " # pipelock:ignore\n+value=" + providerKey + " # pipelock:ignore\n"
	result, err := ScanDiff(diff, patterns)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Pattern != "AWS Access ID" || len(result.Suppressed) != 1 || result.Suppressed[0].Pattern != "Anthropic API Key" {
		t.Fatalf("unexpected pattern classification: %+v", result)
	}
}

func TestInlineSuppressPatternParity(t *testing.T) {
	if suppressRe.String() != InlineSuppressPattern {
		t.Fatal("diff suppression expression differs from shared pattern")
	}
}

// TestWithCoreDLPFloor: every core floor pattern reaches the git scanner,
// including core-only patterns absent from the configured list, without
// duplicating a configured copy.
func TestWithCoreDLPFloor(t *testing.T) {
	core := config.CoreDLPPatterns()
	got := config.WithCoreDLPFloor(nil)
	if len(got) != len(core) {
		t.Fatalf("config.WithCoreDLPFloor(nil) = %d patterns, want %d", len(got), len(core))
	}
	again := config.WithCoreDLPFloor(got)
	if len(again) != len(core) {
		t.Fatalf("core patterns duplicated: %d, want %d", len(again), len(core))
	}
	weakened := []config.DLPPattern{{Name: core[0].Name, Regex: `never-matches-anything`, Severity: config.SeverityLow}}
	if out := config.WithCoreDLPFloor(weakened); len(out) != len(core)+1 {
		t.Fatalf("a configured pattern reusing a core name replaced the core expression: %d patterns", len(out))
	}
	gcp := "{\"type\": \"service_" + "account\"}"
	diff := "diff --git a/k.json b/k.json\n--- a/k.json\n+++ b/k.json\n@@ -0,0 +1 @@\n+" + gcp + "\n"
	result, err := ScanDiff(diff, CompileDLPPatterns(config.WithCoreDLPFloor(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Pattern != "GCP Service Account Key" {
		t.Fatalf("core-only pattern not applied: %+v", result.Findings)
	}
}

func TestWithCoreDLPFloorPreservesValidation(t *testing.T) {
	core := config.CoreDLPPatterns()[0]
	configured := core
	configured.Validator = config.ValidatorLuhn
	// A configured checksum must not become a prerequisite for the independent floor.
	patterns := config.WithCoreDLPFloor([]config.DLPPattern{configured})
	for _, p := range patterns {
		if p.Name == core.Name && p.Regex == core.Regex && p.Validator == core.Validator {
			return
		}
	}
	t.Fatal("configured validator replaced the immutable core detector")
}
