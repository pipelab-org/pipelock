// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMCPSectionsRoundTripThroughYAML(t *testing.T) {
	rules := []ToolPolicyRule{{Name: "deny", ToolPattern: "^denied$", Action: ActionBlock}}
	for _, tc := range []struct {
		name           string
		edit           func(*Config)
		wantEnabled    bool // after RuntimeMCPProxy resolution, all three sections
		wantDisabledIn bool // input section stays disabled (policy-with-rules case)
	}{
		{name: "unset defaults", edit: func(*Config) {}, wantEnabled: true},
		{name: "explicit disable", edit: func(c *Config) {
			c.MCPInputScanning.Action = ActionWarn
			c.MCPToolScanning.Action = ActionWarn
			c.MCPToolPolicy.Action = ActionWarn
		}},
		{name: "disabled policy with rules", edit: func(c *Config) {
			c.MCPToolPolicy.Rules = rules
		}, wantEnabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			tc.edit(cfg)
			data, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadBytes(data)
			if err != nil {
				t.Fatal(err)
			}
			resolved, _ := loaded.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})
			policyWant := tc.wantEnabled && len(cfg.MCPToolPolicy.Rules) == 0
			if resolved.MCPInputScanning.Enabled != tc.wantEnabled || resolved.MCPToolScanning.Enabled != tc.wantEnabled || resolved.MCPToolPolicy.Enabled != policyWant {
				t.Fatalf("round trip changed MCP intent: input=%t tool=%t policy=%t", resolved.MCPInputScanning.Enabled, resolved.MCPToolScanning.Enabled, resolved.MCPToolPolicy.Enabled)
			}
		})
	}
}

func TestMCPSectionMarshalKeepsEnabledTrueAndOtherKeys(t *testing.T) {
	cfg := Defaults()
	cfg.MCPInputScanning.Enabled = true
	cfg.MCPInputScanning.Action = ActionBlock
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Input map[string]any `yaml:"mcp_input_scanning"`
		Tool  map[string]any `yaml:"mcp_tool_scanning"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Input["enabled"] != true || raw.Input["action"] != ActionBlock {
		t.Fatalf("enabled section lost keys: %v", raw.Input)
	}
	if _, present := raw.Tool["enabled"]; present {
		t.Fatal("unset tool scanning wrote an explicit enabled key")
	}
	if _, present := raw.Tool["detect_drift"]; !present || !strings.Contains(string(data), "quarantine_dir") {
		t.Fatal("unset section dropped unrelated keys")
	}
}
