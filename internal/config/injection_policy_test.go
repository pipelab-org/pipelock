// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestInjectionPolicyCompile(t *testing.T) {
	for _, tt := range []struct {
		name, yaml      string
		result, desc    string // expected modes
		resultSource    string
		wantNoticeParts []string
	}{
		{"omitted", "{}", InjectionModeBlock, InjectionModeBlock, InjectionPolicySourceLegacy, nil},
		{"surfaces_null", "prompt_injection_detection: {surfaces: null}", InjectionModeBlock, InjectionModeBlock, InjectionPolicySourceLegacy, nil},
		{"surfaces_empty", "prompt_injection_detection: {surfaces: {}}", InjectionModeBlock, InjectionModeBlock, InjectionPolicySourceLegacy, nil},
		{"legacy_off", "prompt_injection_detection: {enabled: false}", InjectionModeOff, InjectionModeOff, InjectionPolicySourceLegacy, nil},
		{"legacy_warn", "prompt_injection_detection: {action: warn}", InjectionModeWarn, InjectionModeWarn, InjectionPolicySourceLegacy, nil},
		{"result_warn", "prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: warn}}}", InjectionModeWarn, InjectionModeBlock, InjectionPolicySourceSurface, []string{"mcp_tool_result=warn"}},
		{"result_off_desc_warn", "prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: off}, mcp_tool_description: {checker: basic, mode: warn}}}", InjectionModeOff, InjectionModeWarn, InjectionPolicySourceSurface, []string{"mcp_tool_result=off", "mcp_tool_description=warn"}},
		{"same_as_legacy", "prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: block}}}", InjectionModeBlock, InjectionModeBlock, InjectionPolicySourceSurface, nil},
		{"warn_global_off_surface", "prompt_injection_detection: {action: warn, surfaces: {mcp_tool_result: {mode: off}}}", InjectionModeOff, InjectionModeWarn, InjectionPolicySourceSurface, []string{"mcp_tool_result=off"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			p := cfg.InjectionPolicy()
			r, d := p.For(InjectionSurfaceMCPToolResult), p.For(InjectionSurfaceMCPToolDescription)
			if r.Mode != tt.result || d.Mode != tt.desc || r.Checker != InjectionCheckerBasic || d.Checker != InjectionCheckerBasic {
				t.Fatalf("result=%+v desc=%+v", r, d)
			}
			if r.Source != tt.resultSource {
				t.Fatalf("result source = %q, want %q", r.Source, tt.resultSource)
			}
			if p.For("http_response").Source != InjectionPolicySourceLegacy {
				t.Fatal("unselectable surface did not follow legacy policy")
			}
			notice := cfg.PromptInjectionNotice()
			for _, part := range tt.wantNoticeParts {
				if !strings.Contains(notice, part) {
					t.Fatalf("notice %q omits %q", notice, part)
				}
			}
			if len(tt.wantNoticeParts) == 0 && strings.Contains(notice, "reduced on") {
				t.Fatalf("unexpected reduction notice: %q", notice)
			}
			if len(tt.wantNoticeParts) > 0 {
				var found bool
				for _, w := range mustValidateWarnings(t, cfg) {
					found = found || strings.Contains(w.Message, tt.wantNoticeParts[0])
				}
				if !found {
					t.Fatal("startup validation warning omits the surface reduction")
				}
			}
		})
	}
}

func mustValidateWarnings(t *testing.T, cfg *Config) []Warning {
	t.Helper()
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatal(err)
	}
	return warnings
}

func TestInjectionPolicyRejects(t *testing.T) {
	for _, tt := range []struct{ name, yaml, want string }{
		{"unknown_surface", "prompt_injection_detection: {surfaces: {unsupported_surface: {mode: warn}}}", "not selectable"},
		{"empty_mode", "prompt_injection_detection: {surfaces: {mcp_tool_result: {checker: basic}}}", "must be off, warn or block"},
		{"null_entry", "prompt_injection_detection: {surfaces: {mcp_tool_result: null}}", "must be off, warn or block"},
		{"bad_mode", "prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: strip}}}", "must be off, warn or block"},
		{"unknown_checker", "prompt_injection_detection: {surfaces: {mcp_tool_result: {checker: vendor, mode: warn}}}", "unknown checker"},
		{"raise_over_off", "prompt_injection_detection: {enabled: false, surfaces: {mcp_tool_result: {mode: warn}}}", "conflicts with the global wording setting (off)"},
		{"raise_over_warn", "prompt_injection_detection: {action: warn, surfaces: {mcp_tool_description: {mode: block}}}", "conflicts with the global wording setting (warn)"},
		{"unknown_field", "prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: warn, watch: x}}}", "watch"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadBytes([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestInjectionPolicyHash(t *testing.T) {
	load := func(yaml string) *Config {
		t.Helper()
		cfg, err := LoadBytes([]byte(yaml))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	base := load("{}")
	// Legacy configs keep their exact canonical hash.
	for _, y := range []string{"prompt_injection_detection: {surfaces: {}}", "prompt_injection_detection: {enabled: true}"} {
		if load(y).CanonicalPolicyHash() != base.CanonicalPolicyHash() {
			t.Fatalf("%s changed the legacy hash", y)
		}
	}
	warn := load("prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: warn}}}")
	off := load("prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: off}}}")
	explicitBasic := load("prompt_injection_detection: {surfaces: {mcp_tool_result: {checker: basic, mode: warn}}}")
	if warn.CanonicalPolicyHash() == base.CanonicalPolicyHash() || warn.CanonicalPolicyHash() == off.CanonicalPolicyHash() {
		t.Fatal("canonical hash does not bind surface mode")
	}
	if warn.CanonicalPolicyHash() != explicitBasic.CanonicalPolicyHash() || warn.InjectionPolicy().Digest() != explicitBasic.InjectionPolicy().Digest() {
		t.Fatal("omitted checker and explicit basic hash differently")
	}
	if warn.InjectionPolicy().Digest() == base.InjectionPolicy().Digest() || base.InjectionPolicy().Digest() == "" {
		t.Fatal("injection policy digest does not bind surface mode")
	}
}

func TestInjectionPolicyCloneAndReload(t *testing.T) {
	old, err := LoadBytes([]byte("prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: block}}}"))
	if err != nil {
		t.Fatal(err)
	}
	clone := old.Clone()
	clone.PromptInjectionDetection.Surfaces[InjectionSurfaceMCPToolResult] = InjectionSurfaceConfig{Mode: InjectionModeOff}
	if old.InjectionPolicy().For(InjectionSurfaceMCPToolResult).Mode != InjectionModeBlock {
		t.Fatal("clone aliases surface map")
	}
	for _, tt := range []struct {
		name, next string
		warn       bool
	}{
		{"unchanged", "prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: block}}}", false},
		{"to_legacy_same_mode", "{}", false},
		{"downgrade_warn", "prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: warn}}}", true},
		{"downgrade_off", "prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: off}}}", true},
		{"global_off", "prompt_injection_detection: {enabled: false}", true},
		{"unrelated", "prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: block}}}\nresponse_scanning: {action: warn}", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			updated, err := LoadBytes([]byte(tt.next))
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, w := range ValidateReload(old, updated) {
				if w.Field == "prompt_injection_detection.surfaces."+InjectionSurfaceMCPToolResult {
					found = true
					if !strings.Contains(w.Message, "basic/block (surface)") {
						t.Fatalf("warning omits old binding: %s", w.Message)
					}
				}
			}
			if found != tt.warn {
				t.Fatalf("surface reload warning = %v, want %v", found, tt.warn)
			}
		})
	}
	// Upgrade direction raises no warning.
	low, _ := LoadBytes([]byte("prompt_injection_detection: {surfaces: {mcp_tool_result: {mode: off}}}"))
	for _, w := range ValidateReload(low, old) {
		if strings.HasPrefix(w.Field, "prompt_injection_detection.surfaces") {
			t.Fatalf("upgrade warned: %+v", w)
		}
	}
}
