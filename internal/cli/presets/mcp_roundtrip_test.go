// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package presets

import (
	"reflect"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// A preset written to disk is loaded again by the operator. Explicit MCP
// settings and runtime defaults must retain the same intent.
func TestPresetYAMLPreservesMCPRuntimeIntent(t *testing.T) {
	for _, info := range List() {
		t.Run(info.Name, func(t *testing.T) {
			data, err := YAML(info.Name)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := config.LoadBytes(data)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := loaded.ResolveRuntime(config.RuntimeResolveOpts{Mode: config.RuntimeMCPProxy})
			parsed, err := Config(info.Name)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := parsed.ResolveRuntime(config.RuntimeResolveOpts{Mode: config.RuntimeMCPProxy})
			if before.MCPInputScanning.Enabled != want.MCPInputScanning.Enabled ||
				before.MCPToolScanning.Enabled != want.MCPToolScanning.Enabled ||
				before.MCPToolPolicy.Enabled != want.MCPToolPolicy.Enabled ||
				before.MCPInputScanning.Action != want.MCPInputScanning.Action ||
				before.MCPToolScanning.Action != want.MCPToolScanning.Action ||
				before.MCPToolPolicy.Action != want.MCPToolPolicy.Action ||
				!reflect.DeepEqual(before.MCPToolPolicy.Rules, want.MCPToolPolicy.Rules) ||
				before.Taint.Policy != want.Taint.Policy ||
				!reflect.DeepEqual(before.ToolChainDetection, want.ToolChainDetection) {
				t.Fatal("preset YAML changed MCP runtime intent")
			}
		})
	}
}
