// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestCredentialExpansionIncomplete(t *testing.T) {
	suffix := "entials"
	for range maxParamNesting + 1 {
		suffix = "${x:-" + suffix + "}"
	}
	target := "~/.aws/cred" + suffix
	for _, tt := range []struct{ name, tool, key, value, rule string }{
		{"shell read", "bash", "command", "cat " + target, ruleSensitiveFileRead},
		{"file read", "read_file", "path", target, ruleSensitiveFileRead},
		{"file write", "write_file", "path", target, fileMutationRuleName},
		{"patch target", "apply_patch", "patch", "*** Begin Patch\n*** Update File: " + target + "\n@@\n-old\n+new\n*** End Patch", fileMutationRuleName},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var rules []config.ToolPolicyRule
			for _, r := range DefaultToolPolicyRules() {
				if r.Name == tt.rule {
					rules = append(rules, r)
				}
			}
			for _, action := range []string{config.ActionWarn, config.ActionBlock} {
				pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, OnIncompleteCheck: action, Rules: rules})
				got := toolCallVerdict(t, pc, tt.tool, map[string]any{tt.key: tt.value})
				if !got.Matched || got.Action != action || !slices.Contains(got.IncompleteRules, tt.rule) {
					t.Errorf("incomplete=%s: %+v", action, got)
				}
				if tt.tool == "bash" {
					got = pc.CheckToolCall(tt.tool, []string{tt.value})
					if !got.Matched || got.Action != action || !slices.Contains(got.IncompleteRules, tt.rule) {
						t.Errorf("direct incomplete=%s: %+v", action, got)
					}
				}
			}
		})
	}
}
