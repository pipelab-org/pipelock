// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestIdentifierValidatorYAML(t *testing.T) {
	for _, tt := range []struct {
		name, field, want string
		wantError         bool
	}{
		{"omitted", "", "", false},
		{"null", "validator: null", "", false},
		{"blank", "validator:", "", false},
		{"empty", `validator: ""`, "", false},
		{"dea", "validator: dea", ValidatorDEA, false},
		{"npi", "validator: npi", ValidatorNPI, false},
		{"unknown", "validator: deaa", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := fmt.Sprintf("version: 1\ndlp:\n  include_defaults: false\n  patterns:\n    - name: identifier\n      regex: '[A-Z0-9]+'\n      severity: high\n      %s\n", tt.field)
			cfg, err := LoadBytes([]byte(data))
			if tt.wantError {
				if err == nil || !strings.Contains(err.Error(), "unknown validator") {
					t.Fatalf("unknown validator error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.DLP.Patterns) != 1 || cfg.DLP.Patterns[0].Validator != tt.want {
				t.Fatalf("unexpected loaded validator: %+v", cfg.DLP.Patterns)
			}
		})
	}
}

func TestIdentifierValidatorReload(t *testing.T) {
	for _, tt := range []struct {
		name, before, after string
		wantWarning         bool
	}{
		{"unchanged shape", "", "", false},
		{"enable DEA", "", ValidatorDEA, true},
		{"enable NPI", "", ValidatorNPI, true},
		{"enable existing validator", "", ValidatorABA, true},
		{"swap validators", ValidatorDEA, ValidatorNPI, true},
		{"unchanged validator", ValidatorDEA, ValidatorDEA, false},
		{"restore shape detection", ValidatorDEA, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			old, next := Defaults(), Defaults()
			old.DLP.Patterns = []DLPPattern{{Name: "identifier", Regex: `[A-Z0-9]+`, Severity: SeverityHigh, Validator: tt.before}}
			next.DLP.Patterns = []DLPPattern{{Name: "identifier", Regex: `[A-Z0-9]+`, Severity: SeverityHigh, Validator: tt.after}}
			found := false
			for _, warning := range ValidateReload(old, next) {
				if warning.Field == "dlp.patterns" {
					found = true
					if warning.Disposition == ReloadWarningDispositionAdvisory || !strings.Contains(warning.Message, "validator changed") {
						t.Fatalf("validator filtering must produce a rejectable warning: %+v", warning)
					}
				}
			}
			if found != tt.wantWarning {
				t.Fatalf("validator reload warning=%v, want %v", found, tt.wantWarning)
			}
		})
	}
}
