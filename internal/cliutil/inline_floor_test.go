// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/gitprotect"
	"github.com/luckyPipewrench/pipelock/internal/projectscan"
)

func TestInlineSuppressionCoreFloor(t *testing.T) {
	for _, rule := range []string{"AWS Access ID", "aws access id", "Prompt Injection", "prompt injection", "GCP Service Account Key", "Custom Secret"} {
		for _, marker := range []string{"# pipelock:ignore", "// pipelock:ignore " + strings.ToUpper(rule)} {
			t.Run(rule+"/"+marker, func(t *testing.T) {
				file := filepath.Join(t.TempDir(), "fixture.txt")
				if err := os.WriteFile(file, []byte("value=fixture "+marker+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				wantSuppressed := rule == "Custom Secret"
				entries := []config.SuppressEntry{{Rule: rule, Path: file}}
				if got := CheckInlineSuppression(file, 1, rule); got.Suppressed != wantSuppressed {
					t.Errorf("inline=%+v, want suppressed=%v", got, wantSuppressed)
				}
				if got := CheckFinding(file, 1, rule, entries); got.Suppressed != wantSuppressed {
					t.Errorf("pipeline=%+v, want suppressed=%v", got, wantSuppressed)
				}
				kept, suppressed, reasons := SuppressGitFindings([]gitprotect.Finding{{File: file, Line: 1, Pattern: rule}}, entries)
				wantKept := 1
				if wantSuppressed {
					wantKept = 0
				}
				if len(kept) != wantKept || len(suppressed) != 1-wantKept || len(reasons) != 1-wantKept {
					t.Errorf("git kept=%d suppressed=%d reasons=%d", len(kept), len(suppressed), len(reasons))
				}
				pk, ps, pr := SuppressProjectFindings([]projectscan.Finding{{File: filepath.Base(file), Line: 1, Pattern: rule}}, entries, filepath.Dir(file))
				if len(pk) != wantKept || len(ps) != 1-wantKept || len(pr) != 1-wantKept {
					t.Errorf("project kept=%d suppressed=%d reasons=%d", len(pk), len(ps), len(pr))
				}
			})
		}
	}
}

func TestInlineSuppressPatternParity(t *testing.T) {
	if SuppressRe.String() != gitprotect.InlineSuppressPattern {
		t.Fatal("source suppression expression differs from diff pattern")
	}
}
