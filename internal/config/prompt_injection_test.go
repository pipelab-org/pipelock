// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestPromptInjectionDetectionConfig(t *testing.T) {
	for _, tt := range []struct {
		name, yaml, mode string
	}{
		{"omitted", "{}", ActionBlock},
		{"section_null", "prompt_injection_detection: null", ActionBlock},
		{"section_blank", "prompt_injection_detection:", ActionBlock},
		{"enabled_omitted", "prompt_injection_detection: {}", ActionBlock},
		{"enabled_null", "prompt_injection_detection: {enabled: null}", ActionBlock},
		{"enabled_blank", "prompt_injection_detection:\n  enabled:", ActionBlock},
		{"false", "prompt_injection_detection: {enabled: false}", ActionAllow},
		{"true", "prompt_injection_detection: {enabled: true}", ActionBlock},
		{"warn", "prompt_injection_detection: {action: warn}", ActionWarn},
		{"block", "prompt_injection_detection: {action: block}", ActionBlock},
		{"off_wins", "prompt_injection_detection: {enabled: false, action: warn}", ActionAllow},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.PromptInjectionMode(); got != tt.mode {
				t.Fatalf("mode = %q, want %q", got, tt.mode)
			}
			if (cfg.PromptInjectionNotice() != "") != (tt.mode != ActionBlock) {
				t.Fatal("coverage disclosure does not match effective policy")
			}
			// Disabled wording earns no clean-request recovery; warn-only still does.
			if strings.Contains(cfg.PromptInjectionNotice(), "adaptive levels recover by time only, and residual scores at normal level expire after a level_duration_seconds interval without new scored signals") != (tt.mode == ActionAllow) {
				t.Fatalf("adaptive recovery disclosure mismatch for mode %q: %s", tt.mode, cfg.PromptInjectionNotice())
			}
			base, err := LoadBytes([]byte("{}"))
			if err != nil {
				t.Fatal(err)
			}
			if (base.CanonicalPolicyHash() == cfg.CanonicalPolicyHash()) != (tt.mode == ActionBlock) {
				t.Fatal("canonical policy hash does not distinguish effective wording policy")
			}
		})
	}
	for _, yaml := range []string{
		"prompt_injection_detection: {action: allow}",
		"prompt_injection_detection: {action: strip}",
		"prompt_injection_detection: {enabled: false, action: invalid}",
		"prompt_injection_detection: {enabled: invalid}",
	} {
		if _, err := LoadBytes([]byte(yaml)); err == nil {
			t.Fatalf("invalid policy accepted: %s", yaml)
		}
	}
}

func TestPromptInjectionDetectionCloneAndReload(t *testing.T) {
	for _, initial := range []string{ActionBlock, ActionWarn, ActionAllow} {
		for _, next := range []string{ActionBlock, ActionWarn, ActionAllow} {
			t.Run(initial+"_to_"+next, func(t *testing.T) {
				makeConfig := func(mode string) *Config {
					cfg := Defaults()
					enabled := mode != ActionAllow
					action := ActionBlock
					if mode == ActionWarn {
						action = ActionWarn
					}
					cfg.PromptInjectionDetection = &PromptInjectionDetection{Enabled: &enabled, Action: action}
					return cfg
				}
				old, updated := makeConfig(initial), makeConfig(next)
				warnings := ValidateReload(old, updated)
				found := false
				for _, warning := range warnings {
					if warning.Field == "prompt_injection_detection" {
						found = true
						if !strings.Contains(warning.Message, "DLP and destination") {
							t.Fatal("reload warning omits remaining protections")
						}
					}
				}
				if want := (initial == ActionBlock && next != ActionBlock) || (initial == ActionWarn && next == ActionAllow); found != want {
					t.Fatalf("reload disclosure = %v, want %v", found, want)
				}
				clone := old.Clone()
				*clone.PromptInjectionDetection.Enabled = !*old.PromptInjectionDetection.Enabled
				if *clone.PromptInjectionDetection.Enabled == *old.PromptInjectionDetection.Enabled {
					t.Fatal("clone aliases enabled flag")
				}
			})
		}
	}
	var cfg *Config
	if cfg.PromptInjectionMode() != ActionBlock {
		t.Fatal("nil config weakened default")
	}
}
