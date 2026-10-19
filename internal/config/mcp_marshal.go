// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "gopkg.in/yaml.v3"

// The loader reads an explicit `enabled: false` in an MCP scanning section as
// an operator opt-out (see applySecurityDefaults), so a section that is still
// unset in memory (Enabled false and Action empty, the zero value
// applyMCPAutoEnable treats as unconfigured) must not be written back as
// `enabled: false`. Marshaling would otherwise turn the runtime default into a
// permanent disable when the generated file is loaded again: presets, init,
// sidecar and project-scan output all marshal an unresolved Config.

// MarshalYAML omits the unset `enabled: false` so the file round-trips as
// unconfigured.
func (s MCPInputScanning) MarshalYAML() (any, error) {
	type plain MCPInputScanning
	return marshalOmittingUnsetEnabled(plain(s), !s.Enabled && s.Action == "")
}

// MarshalYAML omits the unset `enabled: false` so the file round-trips as
// unconfigured.
func (s MCPToolScanning) MarshalYAML() (any, error) {
	type plain MCPToolScanning
	return marshalOmittingUnsetEnabled(plain(s), !s.Enabled && s.Action == "")
}

// MarshalYAML omits the unset `enabled: false` so the file round-trips as
// unconfigured. Tool policy is unset only without rules, matching
// applyMCPAutoEnable.
func (s MCPToolPolicy) MarshalYAML() (any, error) {
	type plain MCPToolPolicy
	return marshalOmittingUnsetEnabled(plain(s), !s.Enabled && s.Action == "" && len(s.Rules) == 0)
}

func marshalOmittingUnsetEnabled(section any, unset bool) (any, error) {
	var node yaml.Node
	if err := node.Encode(section); err != nil {
		return nil, err
	}
	if !unset || node.Kind != yaml.MappingNode {
		return &node, nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == "enabled" {
			node.Content = append(node.Content[:i], node.Content[i+2:]...)
			break
		}
	}
	return &node, nil
}
