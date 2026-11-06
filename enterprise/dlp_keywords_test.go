//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestDLPKeywordsAgentProfile(t *testing.T) {
	cfg := testConfig()
	rule := config.DLPPattern{Name: "account", Regex: `[0-9]{16}`, Keywords: []string{"account"}, KeywordWindow: new(50)}
	profile := config.AgentProfile{DLP: &config.AgentDLP{IncludeDefaults: new(false), Patterns: []config.DLPPattern{rule}}}
	cfg.Agents = map[string]config.AgentProfile{"operator": profile}
	if err := ValidateAgents(cfg); err != nil {
		t.Fatal(err)
	}
	merged, err := MergeAgentProfile(cfg, &profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMergedAgent("operator", merged); err != nil {
		t.Fatal(err)
	}
	merged.DLP.Patterns[0].Keywords[0] = "customer"
	*merged.DLP.Patterns[0].KeywordWindow = 30
	if profile.DLP.Patterns[0].Keywords[0] != "account" || *profile.DLP.Patterns[0].KeywordWindow != 50 {
		t.Fatal("merge shared mutable keyword state")
	}
	sc, err := scanner.New(merged)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	for _, m := range sc.ScanTextForDLP(t.Context(), "3333333333333333").Matches {
		if m.PatternName == rule.Name {
			t.Fatal("effective agent gate was inert")
		}
	}
	bad := profile
	bad.DLP = &config.AgentDLP{Patterns: []config.DLPPattern{{Name: "bad", Regex: `[0-9]+`, Keywords: []string{"ab"}}}}
	cfg.Agents["operator"] = bad
	if err := ValidateAgents(cfg); err == nil {
		t.Fatal("agent profile accepted invalid keywords")
	}
}
