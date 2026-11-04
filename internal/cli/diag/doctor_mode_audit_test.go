// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// mode: audit with enforce on blocks more than its name suggests. doctor says
// so as information, so the fail-closed config does not raise its warning exit.
func TestDoctorModeAuditEnforcedNotice(t *testing.T) {
	off := false
	for _, tc := range []struct {
		name    string
		enforce *bool
		want    bool
	}{
		{"enforce default", nil, true},
		{"enforce false", &off, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.Mode = config.ModeAudit
			cfg.Enforce = tc.enforce
			report := buildDoctorReport(cfg, "test.yaml")
			found := false
			for _, check := range report.Checks {
				if check.Name != "mode_audit_enforced" {
					continue
				}
				found = true
				if check.Status != doctorStatusInfo {
					t.Fatalf("mode_audit_enforced status = %q, want info", check.Status)
				}
			}
			if found != tc.want {
				t.Fatalf("mode_audit_enforced present = %v, want %v", found, tc.want)
			}
		})
	}
}
