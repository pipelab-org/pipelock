// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
)

func TestLegacyCardPatternCompatibility(t *testing.T) {
	legacyYAML := []byte("mode: strict\napi_allowlist:\n  - api.vendor.example\ndlp:\n  patterns:\n    - name: \"Credit Card Number\"\n      regex: '" + jsonnumber.LegacyCardPattern + "'\n      severity: medium\n      validator: luhn\n")
	legacyCfg, err := LoadBytes(legacyYAML)
	if err != nil {
		t.Fatalf("LoadBytes(legacyYAML) error = %v", err)
	}
	var legacyCard DLPPattern
	for _, p := range legacyCfg.DLP.Patterns {
		if p.Name == "Credit Card Number" {
			legacyCard = p
		}
	}
	if !legacyCard.BuiltInCreditCard {
		t.Fatal("legacy shipped Credit Card Number copy lost BuiltInCreditCard provenance")
	}

	// Legacy shipped regex remains a canonical built-in detector: warn mode and
	// keyword gating must still be rejected.
	for _, tc := range []struct {
		name string
		line string
	}{
		{"warn action", "      action: warn\n"},
		{"keywords", "      keywords: [\"credit\"]\n"},
	} {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			badYAML := append([]byte("mode: balanced\ndlp:\n  patterns:\n    - name: \"Credit Card Number\"\n      regex: '"+jsonnumber.LegacyCardPattern+"'\n      severity: medium\n      validator: luhn\n"), []byte(tc.line)...)
			if _, err := LoadBytes(badYAML); err == nil {
				t.Fatalf("LoadBytes accepted %s on legacy built-in card pattern", tc.name)
			}
		})
	}

	// Reloading between LegacyCardPattern and ShippedCardPattern executes the
	// same built-in candidate engine and must not emit a downgrade warning.
	newCfg := Defaults()
	newCfg.Mode = ModeStrict
	newCfg.APIAllowlist = []string{"api.vendor.example"}
	for _, tc := range []struct {
		name     string
		old, new *Config
	}{
		{"legacy to shipped", legacyCfg, newCfg},
		{"shipped to legacy", newCfg, legacyCfg},
	} {
		t.Run("reload "+tc.name, func(t *testing.T) {
			for _, w := range ValidateReload(tc.old, tc.new) {
				if w.Field == "dlp.patterns" {
					t.Fatalf("unexpected dlp.patterns reload downgrade warning: %+v", w)
				}
			}
		})
	}

	// Changing Credit Card Number to an unrelated custom regex must still warn.
	customCfg := Defaults()
	customCfg.Mode = ModeStrict
	customCfg.APIAllowlist = []string{"api.vendor.example"}
	for i := range customCfg.DLP.Patterns {
		if customCfg.DLP.Patterns[i].Name == "Credit Card Number" {
			customCfg.DLP.Patterns[i].Regex = `\b4\d{15}\b`
		}
	}
	foundDowngrade := false
	for _, w := range ValidateReload(newCfg, customCfg) {
		if w.Field == "dlp.patterns" && strings.Contains(w.Message, "Credit Card Number (regex changed)") {
			foundDowngrade = true
		}
	}
	if !foundDowngrade {
		t.Fatal("changing Credit Card Number to a custom regex lost its reload downgrade warning")
	}

	// Mixed-version Conductor bundles carrying either shipped spelling merge
	// cleanly against local defaults carrying the other spelling.
	localShipped := Defaults().DLP.Patterns
	legacyBundle := []DLPPattern{{
		Name:      "Credit Card Number",
		Regex:     jsonnumber.LegacyCardPattern,
		Severity:  SeverityMedium,
		Validator: ValidatorLuhn,
	}}
	if _, err := mergeConductorBundleDLPPatterns(localShipped, legacyBundle); err != nil {
		t.Fatalf("legacy Conductor bundle rejected against shipped local defaults: %v", err)
	}
	shippedBundle := []DLPPattern{{
		Name:      "Credit Card Number",
		Regex:     jsonnumber.ShippedCardPattern,
		Severity:  SeverityMedium,
		Validator: ValidatorLuhn,
	}}
	if _, err := mergeConductorBundleDLPPatterns(legacyCfg.DLP.Patterns, shippedBundle); err != nil {
		t.Fatalf("shipped Conductor bundle rejected against legacy local defaults: %v", err)
	}
	// A different custom regex in a Conductor bundle must still be rejected.
	customBundle := []DLPPattern{{
		Name:      "Credit Card Number",
		Regex:     `\b4\d{15}\b`,
		Severity:  SeverityMedium,
		Validator: ValidatorLuhn,
	}}
	if _, err := mergeConductorBundleDLPPatterns(localShipped, customBundle); err == nil {
		t.Fatal("custom Credit Card Number bundle unexpectedly merged over local defaults")
	}
}
