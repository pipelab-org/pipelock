// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const disabledMCPSections = "mcp_input_scanning: {enabled: false}\nmcp_tool_scanning: {enabled: false}\nmcp_tool_policy: {enabled: false}\n"

func TestResolveRuntimeMCPYAMLIntent(t *testing.T) {
	for _, tc := range []struct {
		name, section  string
		unset, enabled bool
	}{
		{name: "omitted", unset: true},
		{name: "empty section", section: "{}", unset: true},
		{name: "null section", section: "null", unset: true},
		{name: "null enabled", section: "{enabled: null}", unset: true},
		{name: "blank enabled", section: "{enabled: }", unset: true},
		{name: "false", section: "{enabled: false}"},
		{name: "false empty action", section: `{enabled: false, action: ""}`},
		{name: "false null action", section: "{enabled: false, action: null}"},
		{name: "false warn", section: "{enabled: false, action: warn}"},
		{name: "false block", section: "{enabled: false, action: block}"},
		{name: "action only", section: "{action: warn}"},
		{name: "true", section: "{enabled: true}", enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "mode: " + ModeBalanced + "\n"
			if tc.section != "" {
				for _, section := range []string{"mcp_input_scanning", "mcp_tool_scanning", "mcp_tool_policy"} {
					value := tc.section
					if tc.enabled && section == "mcp_tool_policy" {
						value = "{enabled: true, rules: [{name: deny, tool_pattern: '^denied$'}]}"
					}
					body += section + ": " + value + "\n"
				}
			}
			cfg, err := LoadBytes([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			rawHash, loadedHash := cfg.Hash(), cfg.CanonicalPolicyHash()
			if rawHash != fmt.Sprintf("%x", sha256.Sum256([]byte(body))) {
				t.Fatal("raw hash no longer describes original YAML bytes")
			}
			for _, mode := range []RuntimeMode{RuntimeForward, RuntimeForwardWithMCPListener, RuntimeMCPProxy, RuntimeMCPScan} {
				t.Run(fmt.Sprint(mode), func(t *testing.T) {
					opts := RuntimeResolveOpts{Mode: mode, DefaultToolPolicyRules: func() []ToolPolicyRule {
						return []ToolPolicyRule{{Name: "deny", ToolPattern: "^denied$", Action: ActionBlock}}
					}}
					resolved, info := cfg.Clone().ResolveRuntime(opts)
					mcp := mode == RuntimeMCPProxy || mode == RuntimeForwardWithMCPListener
					wantInput := tc.enabled || tc.unset && mcp
					wantTool := tc.enabled || tc.unset && mode != RuntimeForward
					if resolved.MCPInputScanning.Enabled != wantInput || resolved.MCPToolScanning.Enabled != wantTool || resolved.MCPToolPolicy.Enabled != wantInput {
						t.Fatalf("enabled input/tool/policy = %t/%t/%t, want %t/%t/%t", resolved.MCPInputScanning.Enabled, resolved.MCPToolScanning.Enabled, resolved.MCPToolPolicy.Enabled, wantInput, wantTool, wantInput)
					}
					if info.MCPInputScanningAutoEnabled != (tc.unset && mcp) || info.MCPToolScanningAutoEnabled != (tc.unset && mode != RuntimeForward) || info.MCPToolPolicyAutoEnabled != (tc.unset && mcp) {
						t.Fatalf("unexpected auto-enable decisions: %+v", info)
					}
					if tc.unset && mcp && (resolved.MCPInputScanning.Action != ActionBlock || len(resolved.MCPToolPolicy.Rules) != 1) {
						t.Fatal("omission lost input block or default policy rules")
					}
					if !tc.unset {
						wantAction := ActionWarn
						if strings.Contains(tc.section, ActionBlock) {
							wantAction = ActionBlock
						}
						if resolved.MCPInputScanning.Action != wantAction || resolved.MCPToolScanning.Action != wantAction || resolved.MCPToolPolicy.Action != wantAction {
							t.Fatal("explicit configuration lost its action")
						}
					}
					again, againInfo := resolved.ResolveRuntime(opts)
					if again.CanonicalPolicyHash() != resolved.CanonicalPolicyHash() || againInfo.MCPInputScanningAutoEnabled || againInfo.MCPToolScanningAutoEnabled || againInfo.MCPToolPolicyAutoEnabled {
						t.Fatal("resolution is not idempotent")
					}
					if cfg.Hash() != rawHash || resolved.Hash() != rawHash || cfg.CanonicalPolicyHash() != loadedHash {
						t.Fatal("resolution changed original identity")
					}
				})
			}
		})
	}
}

func TestMCPExplicitDisableSharedLoadersAndIdentity(t *testing.T) {
	body := []byte("mcp_input_scanning: &off {enabled: false}\nmcp_tool_scanning: {<<: *off}\nmcp_tool_policy: *off\n")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	explicit, err := LoadBytes([]byte(strings.ReplaceAll(string(body), "enabled: false", "enabled: false, action: warn")))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		load func() (*Config, error)
	}{
		{"file", func() (*Config, error) { return Load(path) }},
		{"bytes", func() (*Config, error) { return LoadBytes(body) }},
		{"rules", func() (*Config, error) { return LoadForRules(path) }},
		{"inspection", func() (*Config, error) { return LoadForInspection(path) }},
		{"bundle", func() (*Config, error) { return LoadPolicyBundleBytes(body) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.load()
			if err != nil {
				t.Fatal(err)
			}
			resolved, _ := cfg.Clone().ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})
			assertMCPDisabled(t, resolved)
			if cfg.Hash() == explicit.Hash() || cfg.Clone().CanonicalPolicyHash() != cfg.CanonicalPolicyHash() {
				t.Fatal("normalization must preserve raw identity and clone canonical identity")
			}
			// Bundle preservation must carry the normalized state, rather than infer
			// intent from the new bundle's unrelated raw bytes.
			bundle, err := LoadPolicyBundleBytes([]byte("mode: balanced\n"))
			if err != nil {
				t.Fatal(err)
			}
			if err := PreserveConductorBundleLocalRuntimeState(bundle, resolved, "mode: balanced\n"); err != nil {
				t.Fatal(err)
			}
			preserved, _ := bundle.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeForwardWithMCPListener})
			assertMCPDisabled(t, preserved)
			if !reflect.DeepEqual(preserved.MCPInputScanning, resolved.MCPInputScanning) {
				t.Fatal("input options changed during preservation")
			}
		})
	}
	implicit, err := LoadBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	if implicit.CanonicalPolicyHash() != explicit.CanonicalPolicyHash() {
		t.Fatal("implicit and explicit warn have different canonical identities")
	}
	omitted, err := LoadBytes([]byte("mode: balanced\n"))
	if err != nil {
		t.Fatal(err)
	}
	on, _ := omitted.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})
	off, _ := explicit.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})
	if on.CanonicalPolicyHash() == off.CanonicalPolicyHash() {
		t.Fatal("effective enabled and disabled policy identities collided")
	}
}

func assertMCPDisabled(t *testing.T, cfg *Config) {
	t.Helper()
	if cfg.MCPInputScanning.Enabled || cfg.MCPToolScanning.Enabled || cfg.MCPToolPolicy.Enabled {
		t.Fatal("explicitly disabled MCP section was enabled")
	}
	if cfg.MCPInputScanning.Action != ActionWarn || cfg.MCPToolScanning.Action != ActionWarn || cfg.MCPToolPolicy.Action != ActionWarn {
		t.Fatal("disabled action default was not retained")
	}
}

func TestMCPYAMLValidationPreserved(t *testing.T) {
	for _, section := range []string{"mcp_input_scanning", "mcp_tool_scanning", "mcp_tool_policy"} {
		t.Run(section, func(t *testing.T) {
			rules := ""
			if section == "mcp_tool_policy" {
				rules = ", rules: [{name: deny, tool_pattern: '^denied$'}]"
			}
			if _, err := LoadBytes([]byte(section + ": {enabled: true, action: invalid" + rules + "}\n")); err == nil || !strings.Contains(err.Error(), "action") {
				t.Fatalf("invalid action error = %v", err)
			}
		})
	}
	if _, err := LoadBytes([]byte("mcp_tool_policy: {enabled: true}\n")); err == nil || !strings.Contains(err.Error(), "has no rules") {
		t.Fatalf("missing rules error = %v", err)
	}
}

func TestMCPExplicitDisableFileReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reload.yaml")
	r := NewReloader(path)
	defer r.Close()
	for _, tc := range []struct {
		name, body string
		disabled   bool
	}{
		{"initial", disabledMCPSections, true},
		{"unchanged", disabledMCPSections, true},
		{"unrelated", disabledMCPSections + "logging: {format: json}\n", true},
		{"removed", "mode: balanced\n", false},
		{"restored", disabledMCPSections, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			r.tryReload(ReloadTriggerFile)
			event := <-r.Reloads()
			if event.Err != nil {
				t.Fatal(event.Err)
			}
			<-r.Changes()
			resolved, _ := event.Config.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})
			if tc.disabled {
				assertMCPDisabled(t, resolved)
			} else if !resolved.MCPInputScanning.Enabled || !resolved.MCPToolScanning.Enabled || !resolved.MCPToolPolicy.Enabled {
				t.Fatal("removing opt-out did not restore runtime defaults")
			}
		})
	}
}

func TestMCPExplicitDisableDoesNotDisableSiblings(t *testing.T) {
	for _, section := range []string{"mcp_input_scanning", "mcp_tool_scanning", "mcp_tool_policy"} {
		t.Run(section, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(section + ": {enabled: false}\n"))
			if err != nil {
				t.Fatal(err)
			}
			resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})
			for name, enabled := range map[string]bool{"mcp_input_scanning": resolved.MCPInputScanning.Enabled, "mcp_tool_scanning": resolved.MCPToolScanning.Enabled, "mcp_tool_policy": resolved.MCPToolPolicy.Enabled} {
				if enabled != (name != section) {
					t.Fatalf("%s enabled=%t after disabling %s", name, enabled, section)
				}
			}
		})
	}
	cfg, err := LoadBytes([]byte("mcp_input_scanning: {enabled: false, response_timeout_seconds: 10}\n"))
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := cfg.ResolveRuntime(RuntimeResolveOpts{Mode: RuntimeMCPProxy})
	if resolved.MCPInputScanning.Enabled || resolved.MCPInputScanning.ResponseTimeoutSeconds != 10 {
		t.Fatal("disabled scanning changed the independent response timeout")
	}
}
