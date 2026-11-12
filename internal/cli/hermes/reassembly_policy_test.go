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

// Content past a decoder limit is warned about, never blocked, on the Hermes
// inbound surface; a chain inside the limits adds no warning.
func TestInboundDecodeLimitWarning(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	pastLimit := "token &" + strings.Repeat("amp;", 40) + "#65; end"
	decision := scanCombined(t.Context(), sc, pastLimit, "inbound gateway dispatch", directionInbound)
	if decision.Decision == DecisionBlock || len(decision.warnings) != 1 || !strings.Contains(decision.warnings[0], scanner.PartialEncodedContentPattern) {
		t.Fatal("decode-limit inbound content blocked or not warned", decision)
	}
	outbound := scanCombined(t.Context(), sc, pastLimit, "tool call", directionOutbound)
	if outbound.Decision != DecisionBlock || !strings.Contains(outbound.Reason, scanner.UninspectableEncodedContentPattern) {
		t.Fatal("decode-limit outbound content was not refused", outbound)
	}
	within := scanCombined(t.Context(), sc, "token &amp;amp;#65; end", "tool result", directionInbound)
	if within.Decision == DecisionBlock || len(within.warnings) != 0 {
		t.Fatal("warning fired inside the decode limits", within)
	}
}
