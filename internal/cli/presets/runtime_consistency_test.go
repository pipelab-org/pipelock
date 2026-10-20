// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package presets

import (
	"fmt"
	"reflect"
	"regexp/syntax"
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
					if name == config.ModeAudit {
						wantAction = config.ActionWarn
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
				old.MCPToolPolicy.Rules = policy.DefaultToolPolicyRules()
				for i := range old.MCPToolPolicy.Rules {
					old.MCPToolPolicy.Rules[i].Action = config.ActionWarn
				}
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
