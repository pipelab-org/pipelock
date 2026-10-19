//go:build enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Elastic-2.0

package enterprise

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMergeAgentProfileMCPExplicitDisable(t *testing.T) {
	for _, tc := range []struct {
		name, body           string
		profile              *config.AgentProfile
		wantBase, wantPolicy bool
	}{
		{name: "omitted", wantBase: true, wantPolicy: true},
		{name: "disabled base", body: "mcp_input_scanning: {enabled: false}\nmcp_tool_scanning: {enabled: false}\nmcp_tool_policy: {enabled: false}\n"},
		{name: "disabled profile", profile: &config.AgentProfile{MCPToolPolicy: &config.MCPToolPolicy{Enabled: false}}, wantBase: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.LoadPolicyBundleBytes([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			base, _ := cfg.ResolveRuntime(config.RuntimeResolveOpts{Mode: config.RuntimeMCPProxy})
			merged, err := MergeAgentProfile(base, tc.profile)
			if err != nil {
				t.Fatal(err)
			}
			if merged.MCPInputScanning.Enabled != tc.wantBase || merged.MCPToolScanning.Enabled != tc.wantBase || merged.MCPToolPolicy.Enabled != tc.wantPolicy {
				t.Fatal("YAML copy or profile override lost effective MCP state")
			}
			if !tc.wantBase {
				again, _ := merged.ResolveRuntime(config.RuntimeResolveOpts{Mode: config.RuntimeMCPProxy})
				if again.MCPInputScanning.Enabled || again.MCPToolScanning.Enabled || again.MCPToolPolicy.Enabled {
					t.Fatal("disabled base did not survive YAML copy and resolution")
				}
			}
			if base.MCPToolPolicy.Enabled != tc.wantBase {
				t.Fatal("profile mutated base")
			}
		})
	}
}
