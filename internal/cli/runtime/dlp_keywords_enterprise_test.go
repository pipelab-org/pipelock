//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordsAgentReloadRestrictions(t *testing.T) {
	previous := config.MergeAgentProfileFunc
	config.MergeAgentProfileFunc = enterprise.MergeAgentProfile
	t.Cleanup(func() { config.MergeAgentProfileFunc = previous })
	for _, tc := range []struct {
		name, mode       string
		receipts, reject bool
	}{
		{"balanced", config.ModeBalanced, false, false},
		{"strict", config.ModeStrict, false, true},
		{"required receipts", config.ModeBalanced, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := config.Defaults()
			old.Mode = tc.mode
			old.FlightRecorder.RequireReceipts = tc.receipts
			old.Agents = map[string]config.AgentProfile{"operator": {DLP: &config.AgentDLP{Patterns: []config.DLPPattern{{Name: "account", Regex: `[0-9]{16}`, Severity: config.SeverityHigh}}}}}
			if control := reloadDowngradeRejectReason(old, old.Clone(), config.ValidateReload(old, old.Clone())); control != "" {
				t.Fatalf("unchanged config rejected: %q", control)
			}
			next := old.Clone()
			next.Agents["operator"].DLP.Patterns[0].Keywords = []string{"account"}
			warnings := config.ValidateReload(old, next)
			narrowed := false
			for _, w := range warnings {
				narrowed = narrowed || strings.Contains(w.Message, "keywords narrowed")
			}
			if !narrowed {
				t.Fatalf("keyword narrowing not reported: %+v", warnings)
			}
			if reason := reloadDowngradeRejectReason(old, next, warnings); (reason != "") != tc.reject {
				t.Fatalf("rejection=%q want=%v", reason, tc.reject)
			}
		})
	}
}
