// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cli/presets"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/discover"
)

func discoveryReport(servers int) *discover.Report {
	if servers < 0 {
		return nil
	}
	return &discover.Report{Summary: discover.Summary{TotalServers: servers}}
}

func TestBuildConfigPreservesPresetPolicy(t *testing.T) {
	for _, name := range presets.All {
		for _, servers := range []int{-1, 0, 2, 5} {
			t.Run(fmt.Sprintf("%s/%d", name, servers), func(t *testing.T) {
				want, err := presets.Config(name)
				if err != nil {
					t.Fatal(err)
				}
				got, err := buildConfig(name, discoveryReport(servers))
				if err != nil {
					t.Fatal(err)
				}
				if !got.ToolChainDetection.Enabled || got.ToolChainDetection.WindowSeconds != 300 || got.ToolChainDetection.WindowSize != 20 || got.ToolChainDetection.MaxGap == nil || *got.ToolChainDetection.MaxGap != config.DefaultMaxGap {
					t.Fatal("preset lost the tool-chain discovery window")
				}
				if got.CanonicalPolicyHash() != want.CanonicalPolicyHash() {
					t.Fatal("discovery changed configured preset policy")
				}
			})
		}
	}
}

func TestBuildConfigPreservesConfiguredScanning(t *testing.T) {
	for _, action := range []string{config.ActionBlock, config.ActionAsk, config.ActionWarn} {
		for _, enabled := range []bool{false, true} {
			for _, servers := range []int{-1, 0, 2, 5} {
				t.Run(fmt.Sprintf("%s/%t/%d", action, enabled, servers), func(t *testing.T) {
					gap := 0
					cfg := config.Defaults()
					cfg.MCPInputScanning.Enabled, cfg.MCPInputScanning.Action = enabled, action
					cfg.MCPToolScanning.Enabled, cfg.MCPToolScanning.Action = enabled, action
					cfg.MCPToolScanning.DetectDrift = false
					cfg.ToolChainDetection = config.ToolChainDetection{
						Enabled: enabled, Action: config.ActionBlock,
						WindowSize: 7, WindowSeconds: 11, MaxGap: &gap,
					}
					wantInput, wantTool, wantChain := cfg.MCPInputScanning, cfg.MCPToolScanning, cfg.ToolChainDetection
					got, err := buildConfigFromPreset(cfg, discoveryReport(servers))
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got.MCPInputScanning, wantInput) ||
						!reflect.DeepEqual(got.MCPToolScanning, wantTool) ||
						!reflect.DeepEqual(got.ToolChainDetection, wantChain) {
						t.Fatal("discovery overwrote configured scanning")
					}
				})
			}
		}
	}
}

func TestBuildConfigUnconfiguredScanning(t *testing.T) {
	for _, servers := range []int{-1, 0, 2, 5} {
		t.Run(fmt.Sprint(servers), func(t *testing.T) {
			cfg := config.Defaults()
			wantChain := cfg.ToolChainDetection
			got, err := buildConfigFromPreset(cfg, discoveryReport(servers))
			if err != nil {
				t.Fatal(err)
			}
			if got.MCPInputScanning.Enabled != (servers > 0) || got.MCPToolScanning.Enabled != (servers > 0) {
				t.Fatal("unconfigured scanning did not follow discovery")
			}
			if servers > 0 && (got.MCPInputScanning.Action != config.ActionWarn || got.MCPToolScanning.Action != config.ActionWarn || !got.MCPToolScanning.DetectDrift) {
				t.Fatal("discovery did not retain its unconfigured scanning defaults")
			}
			if !reflect.DeepEqual(got.ToolChainDetection, wantChain) {
				t.Fatal("discovery changed unconfigured chain settings")
			}
		})
	}
}

func TestBuildConfigLoadedMCPIntent(t *testing.T) {
	for _, tc := range []struct {
		name, section string
		enabled       bool
	}{
		{"omitted", "", true},
		{"null section", "null", true},
		{"null enabled", "{enabled: null}", true},
		{"blank enabled", "{enabled: }", true},
		{"legacy false", "{enabled: false}", true},
		{"legacy empty action", `{enabled: false, action: ""}`, true},
		{"legacy null action", "{enabled: false, action: null}", true},
		{"disabled warn", "{enabled: false, action: warn}", false},
		{"disabled block", "{enabled: false, action: block}", false},
		{"enabled", "{enabled: true, action: block, detect_drift: false}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "mode: balanced\n"
			if tc.section != "" {
				body += "mcp_tool_scanning: " + tc.section + "\n"
				// detect_drift belongs only to tool scanning.
				body += "mcp_input_scanning: " + strings.ReplaceAll(tc.section, ", detect_drift: false", "") + "\n"
			}
			cfg, err := config.LoadPolicyBundleBytes([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			for _, servers := range []int{-1, 0, 2, 5} {
				t.Run(fmt.Sprint(servers), func(t *testing.T) {
					beforeInput, beforeTool := cfg.MCPInputScanning, cfg.MCPToolScanning
					got, err := buildConfigFromPreset(cfg, discoveryReport(servers))
					if err != nil {
						t.Fatal(err)
					}
					if servers > 0 {
						if got.MCPInputScanning.Enabled != tc.enabled || got.MCPToolScanning.Enabled != tc.enabled {
							t.Fatal("discovery changed loaded MCP intent")
						}
						if tc.name == "enabled" && (got.MCPInputScanning.Action != config.ActionBlock || got.MCPToolScanning.Action != config.ActionBlock || got.MCPToolScanning.DetectDrift) {
							t.Fatal("discovery changed explicit settings")
						}
					} else if !reflect.DeepEqual(got.MCPInputScanning, beforeInput) || !reflect.DeepEqual(got.MCPToolScanning, beforeTool) {
						t.Fatal("no discovery changed MCP intent")
					}
					if !reflect.DeepEqual(cfg.MCPInputScanning, beforeInput) || !reflect.DeepEqual(cfg.MCPToolScanning, beforeTool) {
						t.Fatal("discovery mutated immutable loaded config")
					}
				})
			}
		})
	}
}

func TestSidecarPresetConfigRoundTrip(t *testing.T) {
	manifest, err := detectWorkload(testdataPath(t, "deployment.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range presets.All {
		t.Run(name, func(t *testing.T) {
			result, err := generateSidecarPatch(manifest, sidecarOptions{preset: name})
			if err != nil {
				t.Fatal(err)
			}
			var cm struct {
				Data map[string]string `yaml:"data"`
			}
			if err := yaml.Unmarshal([]byte(result.ConfigMapYAML), &cm); err != nil {
				t.Fatal(err)
			}
			loaded, err := config.LoadPolicyBundleBytes([]byte(cm.Data[sidecarConfigFile]))
			if err != nil {
				t.Fatal(err)
			}
			want, err := yaml.Marshal(result.Config)
			if err != nil {
				t.Fatal(err)
			}
			got, err := yaml.Marshal(loaded)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("sidecar config changed effective YAML on load")
			}
			// Audience and credential grammar metadata are runtime-only and must
			// survive mode preset generation even though YAML cannot encode them.
			// Named presets retain their established parser and gain the runtime
			// metadata only when the generated YAML is loaded.
			if len(loaded.DLP.Patterns) != len(result.Config.DLP.Patterns) {
				t.Fatal("sidecar reload changed DLP patterns")
			}
			for i, pattern := range loaded.DLP.Patterns {
				if name != config.ModeStrict && name != config.ModeBalanced && name != config.ModeAudit {
					break
				}
				wantPattern := result.Config.DLP.Patterns[i]
				if !slices.Equal(pattern.ExemptDomains, wantPattern.ExemptDomains) {
					t.Fatalf("exemptions changed for %q", pattern.Name)
				}
				pattern.ExemptDomains = wantPattern.ExemptDomains
				pattern.Compiled = wantPattern.Compiled
				if !reflect.DeepEqual(pattern, wantPattern) {
					t.Fatalf("runtime DLP properties changed for %q", pattern.Name)
				}
			}
			fresh, err := config.LoadPolicyBundleBytes([]byte(cm.Data[sidecarConfigFile]))
			if err != nil {
				t.Fatal(err)
			}
			if loaded.CanonicalPolicyHash() != fresh.CanonicalPolicyHash() {
				t.Fatal("loaded runtime hash differs from independently loaded policy")
			}
		})
	}
}

func TestBuildConfigPreservesToolChainIntent(t *testing.T) {
	for _, section := range []string{"", "tool_chain_detection: {enabled: false}\n", "tool_chain_detection: {enabled: true, action: block, window_seconds: 120}\n"} {
		for _, servers := range []int{0, 3, 4} {
			t.Run(fmt.Sprintf("%s/%d", section, servers), func(t *testing.T) {
				cfg, err := config.LoadBytes([]byte("mode: balanced\n" + section))
				if err != nil {
					t.Fatal(err)
				}
				want := cfg.ToolChainDetection
				got, err := buildConfigFromPreset(cfg, discoveryReport(servers))
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got.ToolChainDetection, want) {
					t.Fatalf("discovery changed chain intent: got %+v, want %+v", got.ToolChainDetection, want)
				}
			})
		}
	}
}
