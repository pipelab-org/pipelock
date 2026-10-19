// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDoctorMCPEffectiveModes(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		configured bool
	}{
		{name: "omitted", configured: true},
		{name: "empty", body: "mcp_input_scanning: {}\nmcp_tool_scanning: null\nmcp_tool_policy: {enabled: null}\n", configured: true},
		{name: "disabled", body: "mcp_input_scanning: {enabled: false}\nmcp_tool_scanning: {enabled: false}\nmcp_tool_policy: {enabled: false}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.LoadBytes([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			before := cfg.CanonicalPolicyHash()
			check := checkDoctorMCPWrapperFeatures(cfg)
			if check.Configured != tc.configured || check.Reachable || check.Enforcing {
				t.Fatalf("configuration was confused with proof: %+v", check)
			}
			if cfg.CanonicalPolicyHash() != before {
				t.Fatal("doctor mutated loaded configuration")
			}
			for _, mode := range []string{"MCP proxy:", "MCP listener:", "MCP scan:", "forward proxy without MCP listener: no MCP scanning", "topology, reachability, and enforcement are unproven"} {
				if !strings.Contains(check.Detail, mode) {
					t.Fatalf("missing mode/proof qualifier %q: %s", mode, check.Detail)
				}
			}
			if tc.configured {
				if !strings.Contains(check.Detail, "MCP proxy: mcp_input_scanning, mcp_tool_scanning, mcp_tool_policy") || !strings.Contains(check.Detail, "MCP scan: mcp_tool_scanning;") {
					t.Fatalf("wrong effective controls: %s", check.Detail)
				}
			} else if !strings.Contains(check.Detail, "MCP proxy: disabled; MCP listener: disabled; MCP scan: disabled;") {
				t.Fatalf("wrong disabled modes: %s", check.Detail)
			}
		})
	}
}
