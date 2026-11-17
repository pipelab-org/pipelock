// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestBufferedInjectionConfig(t *testing.T) {
	base, err := LoadBytes([]byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	for _, surface := range InjectionSurfaces()[2:] {
		t.Run(surface, func(t *testing.T) {
			for _, value := range []string{"null", "", "{}"} {
				cfg, err := LoadBytes([]byte("prompt_injection_detection: {surfaces: " + value + "}"))
				if err != nil {
					t.Fatal(err)
				}
				if cfg.CanonicalPolicyHash() != base.CanonicalPolicyHash() {
					t.Fatal("omitted selections changed hash")
				}
			}
			for _, mode := range []string{InjectionModeOff, InjectionModeWarn, InjectionModeBlock, "null", "", "invalid"} {
				y := fmt.Sprintf("prompt_injection_detection:\n  surfaces:\n    %s:\n      mode: %s\n", surface, mode)
				cfg, err := LoadBytes([]byte(y))
				valid := mode == InjectionModeOff || mode == InjectionModeWarn || mode == InjectionModeBlock
				if (err == nil) != valid {
					t.Fatalf("mode %q: %v", mode, err)
				}
				if !valid {
					continue
				}
				if cfg.InjectionPolicy().For(surface).Mode != mode {
					t.Fatal("selection missing")
				}
				if cfg.CanonicalPolicyHash() == base.CanonicalPolicyHash() {
					t.Fatal("selection missing from hash")
				}
				for _, same := range []bool{false, true} {
					next := cfg.Clone()
					if !same {
						next.PromptInjectionDetection.Surfaces[surface] = InjectionSurfaceConfig{Mode: InjectionModeOff}
					}
					found := false
					for _, w := range ValidateReload(cfg, next) {
						if strings.HasSuffix(w.Field, "."+surface) {
							found = true
						}
					}
					if found != (!same && mode != InjectionModeOff) {
						t.Fatalf("reload warning same=%v mode=%s got=%v", same, mode, found)
					}
					if cfg.InjectionPolicy().For(surface).Mode != mode {
						t.Fatal("snapshot mutated")
					}
				}
			}
		})
	}
}

func TestBufferedInjectionInputPrerequisites(t *testing.T) {
	for _, surface := range []string{InjectionSurfaceHTTPRequestBody, InjectionSurfaceMCPToolInput} {
		for _, mode := range []string{InjectionModeOff, InjectionModeWarn, InjectionModeBlock} {
			for _, watch := range []bool{false, true} {
				cfg := Defaults()
				cfg.RequestBodyScanning.Enabled = false
				cfg.MCPInputScanning.Enabled = false
				selection := InjectionSurfaceConfig{Checker: "fixture", Mode: mode}
				if watch {
					selection.Checker = InjectionCheckerBasic
					selection.Watch = "fixture"
				}
				cfg.PromptInjectionDetection = &PromptInjectionDetection{Surfaces: map[string]InjectionSurfaceConfig{surface: selection}, Checkers: map[string]InjectionCheckerConfig{"fixture": {}}}
				err := cfg.validateInjectionSurfaces()
				wantErr := mode != InjectionModeOff || watch
				if (err != nil) != wantErr {
					t.Fatalf("surface=%s mode=%s watch=%v error=%v", surface, mode, watch, err)
				}
			}
		}
	}
}
