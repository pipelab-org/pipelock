// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestReassemblyPolicyPartialWarning(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = nil
	for _, pattern := range config.DefaultDLPPatterns() {
		if pattern.Name == "AWS Access ID" {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, pattern)
		}
	}
	if len(cfg.DLP.Patterns) != 1 {
		t.Fatal("AWS control absent")
	}
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	body := strings.Repeat("30", 1<<22) + strings.Repeat("!0", 80)
	decision := scanCombined(t.Context(), sc, body, "tool result", directionInbound)
	if decision.Decision == DecisionBlock || len(decision.warnings) != 1 || !strings.Contains(decision.warnings[0], scanner.PartialEncodedContentPattern) || strings.Contains(decision.warnings[0], "card run") {
		t.Fatal("partial inbound warning blocked or mislabeled", decision)
	}
}
