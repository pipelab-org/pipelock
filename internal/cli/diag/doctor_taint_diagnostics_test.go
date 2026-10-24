// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDoctorMCPTaintDiagnostics_NoLiveCoverageClaim(t *testing.T) {
	for _, body := range []string{"", "taint: {enabled: false}\n", "session_profiling: {enabled: true}\n"} {
		t.Run(body, func(t *testing.T) {
			cfg, err := config.LoadBytes([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			report := buildDoctorReport(cfg, "test")
			for _, d := range cfg.MCPTaintDiagnostics() {
				found := false
				for _, c := range report.Checks {
					if c.Name == d.Field {
						found = true
						if c.Reachable || c.Enforcing || c.Configured != cfg.Taint.Enabled || c.Detail != d.Message {
							t.Fatalf("configuration confused with live coverage: %+v", c)
						}
					}
				}
				if !found {
					t.Fatalf("doctor omitted %s", d.Field)
				}
			}
			var text strings.Builder
			for _, c := range report.Checks {
				text.WriteString(c.Detail)
			}
			if !strings.Contains(text.String(), "cross-request taint protection is NOT active") {
				t.Fatal("doctor omitted anonymous limit")
			}
		})
	}
}
