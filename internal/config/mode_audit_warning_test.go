// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestModeAuditEnforcedWarnings(t *testing.T) {
	off := false
	for _, tc := range []struct {
		name    string
		mode    string
		enforce *bool
		want    bool
	}{
		{"audit enforce default", ModeAudit, nil, true},
		{"audit enforce false", ModeAudit, &off, false},
		{"balanced enforce default", ModeBalanced, nil, false},
		{"strict enforce default", ModeStrict, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Mode = tc.mode
			cfg.Enforce = tc.enforce
			got := cfg.ModeAuditEnforcedWarnings()
			if (len(got) == 1) != tc.want || len(got) > 1 {
				t.Fatalf("ModeAuditEnforcedWarnings() = %+v, want warning=%v", got, tc.want)
			}
			if tc.want && (got[0].Field != "mode" || !strings.Contains(got[0].Message, "enforce: false")) {
				t.Fatalf("warning does not name the setting that observes: %+v", got[0])
			}

			warnings, err := cfg.ValidateWithWarnings()
			if err != nil {
				t.Fatalf("ValidateWithWarnings: %v", err)
			}
			found := false
			for _, w := range warnings {
				if w.Field == "mode" && strings.Contains(w.Message, "mode: audit does not turn off blocking") {
					found = true
				}
			}
			if found != tc.want {
				t.Fatalf("startup warnings include audit notice = %v, want %v: %+v", found, tc.want, warnings)
			}
		})
	}
}
