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
