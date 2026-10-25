// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package presets

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp/syntax"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/configs"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"gopkg.in/yaml.v3"
)

func TestModePresetsKeepRuntimeToolRules(t *testing.T) {
	for _, name := range []string{config.ModeStrict, config.ModeBalanced, config.ModeAudit} {
		t.Run(name, func(t *testing.T) {
			cfg, err := Config(name)
			if err != nil {
				t.Fatal(err)
			}
			signatures := make([]config.ToolPolicyRule, len(cfg.MCPToolPolicy.Rules))
			for i, candidate := range cfg.MCPToolPolicy.Rules {
				signatures[i] = toolRuleSignature(t, candidate)
			}
			for _, original := range policy.DefaultToolPolicyRules() {
				want := toolRuleSignature(t, original)
				found := false
				for i, candidate := range cfg.MCPToolPolicy.Rules {
					if !reflect.DeepEqual(signatures[i], want) {
						continue
					}
					found = true
					action := candidate.Action
					if action == "" {
						action = cfg.MCPToolPolicy.Action
					}
					wantAction := original.Action
					if wantAction == "" {
						wantAction = cfg.MCPToolPolicy.Action
					}
					if action != wantAction {
						t.Errorf("rule[%d] %q action = %q, want %q", i, original.Name, action, wantAction)
					}
				}
				if !found {
					t.Errorf("missing runtime rule signature: %s", want.Name)
				}
			}
		})
	}
}

// presetToolRuleOverrides lists built-in tool rules a named preset replaces on
// purpose with a stricter rule of the same name. hostile-model also covers
// Kubernetes and Docker credentials and flags any curl, wget, nc, ncat, or
// socat use.
var presetToolRuleOverrides = map[string][]string{
	"hostile-model": {"Credential File Access", "Network Exfiltration"},
}

func TestPresetsCarryBuiltInToolRulePatterns(t *testing.T) {
	for _, name := range All {
		t.Run(name, func(t *testing.T) {
			cfg, err := Config(name)
			if err != nil {
				t.Fatal(err)
			}
			signatures := make([]config.ToolPolicyRule, len(cfg.MCPToolPolicy.Rules))
			names := make(map[string]bool, len(cfg.MCPToolPolicy.Rules))
			for i, candidate := range cfg.MCPToolPolicy.Rules {
				signatures[i] = toolRuleSignature(t, candidate)
				names[candidate.Name] = true
			}
			for _, original := range policy.DefaultToolPolicyRules() {
				want := toolRuleSignature(t, original)
				found := slices.ContainsFunc(signatures, func(got config.ToolPolicyRule) bool {
					return reflect.DeepEqual(got, want)
				})
				overridden := slices.Contains(presetToolRuleOverrides[name], original.Name)
				switch {
				case overridden && found:
					t.Errorf("rule %q matches the built-in rule; drop it from presetToolRuleOverrides", original.Name)
				case overridden && !names[original.Name]:
					t.Errorf("overridden rule %q is missing", original.Name)
				case !overridden && !found:
					t.Errorf("rule %q differs from the built-in rule (tool, argument, or key pattern)", original.Name)
				}
			}
		})
	}
}

// TestExampleConfigsCarryBuiltInToolRules checks the example configs: a rule
// that carries a built-in rule's name must keep its tool, argument, and key
// patterns and its action.
func TestExampleConfigsCarryBuiltInToolRules(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "examples", "*", "pipelock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no example configs found")
	}
	builtIn := make(map[string][]config.ToolPolicyRule)
	for _, rule := range policy.DefaultToolPolicyRules() {
		builtIn[rule.Name] = append(builtIn[rule.Name], rule)
	}
	checked := 0
	for _, file := range files {
		t.Run(filepath.Base(filepath.Dir(file)), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Clean(file))
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadBytes(data)
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range cfg.MCPToolPolicy.Rules {
				originals, ok := builtIn[rule.Name]
				if !ok {
					continue
				}
				checked++
				got := toolRuleSignature(t, rule)
				if !slices.ContainsFunc(originals, func(original config.ToolPolicyRule) bool {
					return reflect.DeepEqual(got, toolRuleSignature(t, original)) && rule.Action == original.Action
				}) {
					t.Errorf("rule %q differs from the built-in rule (patterns or action)", rule.Name)
				}
			}
		})
	}
	if checked == 0 {
		t.Fatal("no example rule shares a built-in rule name")
	}
}

func toolRuleSignature(t *testing.T, rule config.ToolPolicyRule) config.ToolPolicyRule {
	t.Helper()
	// The runtime policy uses boolean regex matches, never captured groups.
	// Compare the parsed expressions without captures so different parentheses
	// in bundled YAML and built-in rules do not hide an otherwise exact match.
	for _, expression := range []*string{&rule.ToolPattern, &rule.ArgPattern, &rule.ArgKey} {
		re, err := syntax.Parse(*expression, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		*expression = withoutCaptures(re).String()
	}
	rule.Action = ""
	return rule
}

func withoutCaptures(re *syntax.Regexp) *syntax.Regexp {
	if re.Op == syntax.OpCapture {
		return withoutCaptures(re.Sub[0])
	}
	for i, sub := range re.Sub {
		re.Sub[i] = withoutCaptures(sub)
	}
	return re
}

func TestPresetRuntimeDoesNotReduceProtection(t *testing.T) {
	for _, name := range All {
		var old *config.Config
		switch name {
		case config.ModeStrict, config.ModeBalanced, config.ModeAudit:
			// Baseline uses programmatic defaults, with the audit
			// observation contract applied below.
			old = config.Defaults()
			old.Mode = name
			if name == config.ModeAudit {
				off := false
				old.Enforce = &off
				// Audit observes ordinary MCP findings while safety floors remain active.
				old.MCPInputScanning.Action = config.ActionWarn
				old.Taint.Policy = config.ModePermissive
			}
		default:
			// Named presets previously parsed YAML and applied only the
			// ordinary defaults, omitting load-time security defaults.
			data, ok := configs.Preset(name)
			if !ok {
				t.Fatal("preset not embedded")
			}
			old = &config.Config{}
			if err := yaml.Unmarshal(data, old); err != nil {
				t.Fatal(err)
			}
			old.ApplyDefaults()
		}
		updated, err := Config(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []config.RuntimeMode{config.RuntimeMCPProxy, config.RuntimeForwardWithMCPListener} {
			t.Run(fmt.Sprintf("%s/%v", name, mode), func(t *testing.T) {
				opts := config.RuntimeResolveOpts{Mode: mode, DefaultToolPolicyRules: policy.DefaultToolPolicyRules}
				before, _ := old.ResolveRuntime(opts)
				after, _ := updated.ResolveRuntime(opts)
				for _, warning := range config.ValidateReload(before, after) {
					switch warning.Field {
					case "sentry", "file_sentry", "learn_lock":
						// Restart advisories do not reduce a newly generated policy.
					default:
						t.Errorf("runtime policy reduction: %s: %s", warning.Field, warning.Message)
					}
				}
			})
		}
	}
}
