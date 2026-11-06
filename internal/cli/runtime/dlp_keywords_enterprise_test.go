//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
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
			next := old.Clone()
			next.Agents["operator"].DLP.Patterns[0].Keywords = []string{"account"}
			if reason := reloadDowngradeRejectReason(old, next, config.ValidateReload(old, next)); (reason != "") != tc.reject {
				t.Fatalf("rejection=%q want=%v", reason, tc.reject)
			}
		})
	}
}
