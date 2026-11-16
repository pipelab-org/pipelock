// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDoctorPromptInjectionDetection(t *testing.T) {
	for _, mode := range []string{config.ActionBlock, config.ActionWarn, config.ActionAllow} {
		t.Run(mode, func(t *testing.T) {
			cfg := config.Defaults()
			enabled := mode != config.ActionAllow
			cfg.PromptInjectionDetection = &config.PromptInjectionDetection{Enabled: &enabled}
			if mode == config.ActionWarn {
				cfg.PromptInjectionDetection.Action = mode
			}
			check := checkDoctorPromptInjectionDetection(cfg)
			if (check.Status == doctorStatusWarn) != (mode != config.ActionBlock) {
				t.Fatalf("check: %+v", check)
			}
			if mode != config.ActionBlock && !strings.Contains(check.Detail, "DLP and destination controls") {
				t.Fatal(check.Detail)
			}
			if mode == config.ActionAllow && !strings.Contains(check.Detail, "no prompt-injection protection remains") {
				t.Fatal(check.Detail)
			}
		})
	}
}

func TestDoctorPromptInjectionSurfaceBindings(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mode   string
		status string
	}{
		{"lowered", config.InjectionModeWarn, doctorStatusWarn},
		{"same_as_global", config.InjectionModeBlock, doctorStatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.PromptInjectionDetection = &config.PromptInjectionDetection{Surfaces: map[string]config.InjectionSurfaceConfig{
				config.InjectionSurfaceMCPToolResult: {Mode: tt.mode},
			}}
			check := checkDoctorPromptInjectionDetection(cfg)
			if check.Status != tt.status || !check.Configured {
				t.Fatalf("check: %+v", check)
			}
			for _, want := range []string{"mcp_tool_result=basic/" + tt.mode + " (surface)", "mcp_tool_description=basic/block (legacy)"} {
				if !strings.Contains(check.Detail, want) {
					t.Fatalf("detail %q omits %q", check.Detail, want)
				}
			}
		})
	}
	if check := checkDoctorPromptInjectionDetection(config.Defaults()); strings.Contains(check.Detail, "Checker bindings") {
		t.Fatalf("default config listed bindings: %s", check.Detail)
	}
}
