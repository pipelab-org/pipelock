//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const cardPatternName = "Credit Card Number"

func cardBaseConfig(t *testing.T) (*config.Config, config.DLPPattern) {
	t.Helper()
	base := config.Defaults()
	var builtIn config.DLPPattern
	found := false
	for _, p := range base.DLP.Patterns {
		if p.Name == cardPatternName && p.BuiltInCreditCard {
			builtIn, found = p, true
		}
	}
	if !found {
		t.Fatal("defaults carry no built-in credit card pattern")
	}
	return base, builtIn
}

func cardMarkers(cfg *config.Config) (genuine, bundled int) {
	for _, p := range cfg.DLP.Patterns {
		if p.Name != cardPatternName || !p.BuiltInCreditCard {
			continue
		}
		if p.Bundle == "" {
			genuine++
		} else {
			bundled++
		}
	}
	return genuine, bundled
}

func TestMergeAgentProfileCardProvenance(t *testing.T) {
	falseVal := false

	t.Run("empty profile keeps genuine built-in only", func(t *testing.T) {
		base, builtIn := cardBaseConfig(t)
		bundleCopy := builtIn
		bundleCopy.BuiltInCreditCard = false
		bundleCopy.Bundle = "vendor-rules"
		base.DLP.Patterns = append(base.DLP.Patterns, bundleCopy)

		merged, err := MergeAgentProfile(base, &config.AgentProfile{})
		if err != nil {
			t.Fatal(err)
		}
		genuine, bundled := cardMarkers(merged)
		if genuine != 1 || bundled != 0 {
			t.Fatalf("markers genuine=%d bundled=%d, want 1 and 0", genuine, bundled)
		}
		for _, p := range merged.DLP.Patterns {
			if p.Name == cardPatternName && !p.BuiltInCreditCard && p.Bundle != "vendor-rules" {
				t.Fatal("bundle provenance was lost in the merge")
			}
		}
	})

	t.Run("nil profile keeps genuine built-in", func(t *testing.T) {
		base, _ := cardBaseConfig(t)
		merged, err := MergeAgentProfile(base, nil)
		if err != nil {
			t.Fatal(err)
		}
		if genuine, _ := cardMarkers(merged); genuine != 1 {
			t.Fatalf("genuine markers = %d, want 1", genuine)
		}
	})

	t.Run("profile include_defaults false strips exact shipped copy", func(t *testing.T) {
		base, builtIn := cardBaseConfig(t)
		profileCopy := builtIn
		profileCopy.BuiltInCreditCard = false
		merged, err := MergeAgentProfile(base, &config.AgentProfile{DLP: &config.AgentDLP{
			IncludeDefaults: &falseVal,
			Patterns:        []config.DLPPattern{profileCopy},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if genuine, bundled := cardMarkers(merged); genuine != 0 || bundled != 0 {
			t.Fatalf("markers genuine=%d bundled=%d, want none after opt-out", genuine, bundled)
		}
	})

	t.Run("profile keeping defaults may supply exact shipped copy", func(t *testing.T) {
		base, builtIn := cardBaseConfig(t)
		profileCopy := builtIn
		profileCopy.BuiltInCreditCard = false
		merged, err := MergeAgentProfile(base, &config.AgentProfile{DLP: &config.AgentDLP{
			Patterns: []config.DLPPattern{profileCopy},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if genuine, _ := cardMarkers(merged); genuine != 1 {
			t.Fatalf("genuine markers = %d, want 1", genuine)
		}
	})

	t.Run("modified profile copy is not built-in", func(t *testing.T) {
		base, builtIn := cardBaseConfig(t)
		custom := builtIn
		custom.BuiltInCreditCard = true
		custom.Severity = config.SeverityHigh
		merged, err := MergeAgentProfile(base, &config.AgentProfile{DLP: &config.AgentDLP{
			Patterns: []config.DLPPattern{custom},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if genuine, _ := cardMarkers(merged); genuine != 0 {
			t.Fatalf("genuine markers = %d, want 0 for a modified copy", genuine)
		}
	})
}
