//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"strings"
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

func TestDLPKeywordsAgentReloadCoverage(t *testing.T) {
	previous := config.MergeAgentProfileFunc
	config.MergeAgentProfileFunc = MergeAgentProfile
	t.Cleanup(func() { config.MergeAgentProfileFunc = previous })
	for _, tc := range []struct {
		name                    string
		inherited, remove, want bool
	}{
		{name: "profile only", want: true},
		{name: "override inherited", inherited: true, want: true},
		{name: "remove override restores global", inherited: true, remove: true},
		{name: "remove profile loses pattern", remove: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := testConfig()
			rule := config.DLPPattern{Name: "account", Regex: `[0-9]{16}`, Severity: config.SeverityHigh}
			old.DLP.Patterns = nil
			if tc.inherited {
				old.DLP.Patterns = []config.DLPPattern{rule}
			}
			old.Agents = map[string]config.AgentProfile{"operator": {DLP: &config.AgentDLP{Patterns: []config.DLPPattern{rule}}}}
			next := old.Clone()
			if tc.remove {
				delete(next.Agents, "operator")
			} else {
				next.Agents["operator"].DLP.Patterns[0].Keywords = []string{"account"}
			}
			found := false
			for _, w := range config.ValidateReload(old, next) {
				if w.Field == "agents.operator.dlp.patterns" {
					found = true
					if w.Disposition == config.ReloadWarningDispositionAdvisory {
						t.Fatal("coverage reduction was advisory")
					}
				}
			}
			if found != tc.want {
				t.Fatalf("agent coverage warning=%v want=%v", found, tc.want)
			}
			if warnings := config.ValidateReload(next, next.Clone()); len(warnings) != 0 {
				t.Fatalf("unchanged policy warned: %+v", warnings)
			}
		})
	}
}

func TestDLPKeywordsAgentStartupAdvisory(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{"operator": {DLP: &config.AgentDLP{Patterns: []config.DLPPattern{{Name: "account", Regex: `[0-9]{16}`, Severity: config.SeverityHigh, Keywords: []string{"account"}}}}}}
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if w.Field == "agents.operator.dlp.patterns[0].keywords" && strings.Contains(w.Message, "without nearby labels") {
			return
		}
	}
	t.Fatalf("agent keyword advisory missing: %+v", warnings)
}
