// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDoctorMCPFindingKinds(t *testing.T) {
	report := buildDoctorReport(config.Defaults(), "test")
	var detail string
	for _, check := range report.Checks {
		if check.Name == "taint.mcp_finding_kinds" {
			detail = check.Detail
			if check.Reachable || check.Enforcing {
				t.Fatal("config-only doctor claimed live cause inspection")
			}
		}
	}
	for _, want := range []string{"Wording alone is a warning and does not make the session hostile", "DLP and tool poisoning still make the session hostile", "cause not recorded (older state or aggregate finding)", "no live session history"} {
		t.Run(want, func(t *testing.T) {
			if !strings.Contains(detail, want) {
				t.Fatalf("doctor omitted %q: %s", want, detail)
			}
		})
	}
}
