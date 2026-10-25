// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// toolPolicyYAML returns a config with one tool rule and, unless value is
// empty, the given on_incomplete_check line.
func toolPolicyYAML(value string) []byte {
	var b strings.Builder
	b.WriteString("mcp_tool_policy:\n  enabled: true\n  action: warn\n")
	if value != "" {
		b.WriteString("  on_incomplete_check: " + value + "\n")
	}
	b.WriteString("  rules:\n    - name: \"x\"\n      tool_pattern: '^bash$'\n      arg_pattern: 'rm'\n")
	return []byte(b.String())
}

func TestOnIncompleteCheck_Validate(t *testing.T) {
	tests := []struct {
		value string
		ok    bool
	}{
		{"", true},
		{ActionWarn, true},
		{ActionBlock, true},
		{"ask", false},
		{ActionRedirect, false},
		{"Block", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			cfg, err := LoadBytes(toolPolicyYAML(tt.value))
			if tt.ok {
				if err != nil {
					t.Fatalf("load: %v", err)
				}
				if cfg.MCPToolPolicy.OnIncompleteCheck != tt.value {
					t.Fatalf("OnIncompleteCheck = %q, want %q", cfg.MCPToolPolicy.OnIncompleteCheck, tt.value)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "on_incomplete_check") {
				t.Fatalf("load error = %v, want an on_incomplete_check error", err)
			}
		})
	}
}

func TestOnIncompleteCheck_CanonicalHash(t *testing.T) {
	hash := func(value string) string {
		t.Helper()
		cfg, err := LoadBytes(toolPolicyYAML(value))
		if err != nil {
			t.Fatalf("load %q: %v", value, err)
		}
		return cfg.CanonicalPolicyHash()
	}
	omitted, warn, block := hash(""), hash(ActionWarn), hash(ActionBlock)
	if omitted != warn {
		t.Fatal("omitted and warn hash differently")
	}
	if block == warn {
		t.Fatal("block hashes the same as warn")
	}
}

func TestOnIncompleteCheck_ReloadDowngradeWarning(t *testing.T) {
	tests := []struct {
		old, updated string
		warn         bool
	}{
		{ActionBlock, "", true},
		{ActionBlock, ActionWarn, true},
		{"", ActionBlock, false},
		{"", ActionWarn, false},
		{ActionBlock, ActionBlock, false},
	}
	for _, tt := range tests {
		t.Run(tt.old+"->"+tt.updated, func(t *testing.T) {
			old := &Config{MCPToolPolicy: MCPToolPolicy{Enabled: true, Action: ActionWarn, OnIncompleteCheck: tt.old}}
			updated := &Config{MCPToolPolicy: MCPToolPolicy{Enabled: true, Action: ActionWarn, OnIncompleteCheck: tt.updated}}
			var warnings []ReloadWarning
			appendActionDowngradeWarnings(&warnings, old, updated)
			found := false
			for _, w := range warnings {
				if w.Field == "mcp_tool_policy.on_incomplete_check" {
					found = true
				}
			}
			if found != tt.warn {
				t.Fatalf("downgrade warning = %v, want %v (%#v)", found, tt.warn, warnings)
			}
		})
	}
}
