// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// InjectionPolicy compiles only valid selections. Entries that validation
// would reject never widen the policy, even when a caller skips validation.
func TestInjectionPolicySkipsInvalidEntries(t *testing.T) {
	cfg := Defaults()
	cfg.PromptInjectionDetection = &PromptInjectionDetection{Surfaces: map[string]InjectionSurfaceConfig{
		"http_response":                    {Mode: InjectionModeOff},
		InjectionSurfaceMCPToolResult:      {Mode: "strip"},
		InjectionSurfaceMCPToolDescription: {Mode: InjectionModeWarn},
	}}
	p := cfg.InjectionPolicy()
	if !p.Selected() {
		t.Fatal("valid description selection not compiled")
	}
	if got := p.For(InjectionSurfaceMCPToolResult); got.Source != InjectionPolicySourceLegacy || got.Mode != InjectionModeBlock {
		t.Fatalf("invalid result entry widened the policy: %+v", got)
	}
	if got := p.For("http_response"); got.Source != InjectionPolicySourceLegacy {
		t.Fatalf("unselectable surface compiled: %+v", got)
	}
	if (&Config{}).InjectionPolicy().Selected() || (*Config)(nil).InjectionPolicy().Selected() {
		t.Fatal("empty or nil config reported a selection")
	}
}

func TestInjectionSurfacesValidationWithoutSection(t *testing.T) {
	cfg := Defaults()
	cfg.PromptInjectionDetection = nil
	if err := cfg.validateInjectionSurfaces(); err != nil {
		t.Fatal(err)
	}
}
