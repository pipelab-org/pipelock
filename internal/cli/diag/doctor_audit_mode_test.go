// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const mcpAuditModeDoctorDetail = "some configured MCP request block and ask actions are observed; other checks, floors, limits, redirect, defer and responses still apply"

func TestBuildDoctorReportMCPAuditMode(t *testing.T) {
	t.Run("enforce", func(t *testing.T) {
		report := buildDoctorReport(config.Defaults(), configLabelDefaults)
		for _, check := range report.Checks {
			if strings.Contains(check.Detail, mcpAuditModeDoctorDetail) {
				t.Fatalf("enforcing doctor named audit mode: %+v", check)
			}
		}
	})
	t.Run("audit", func(t *testing.T) {
		cfg := config.Defaults()
		off := false
		cfg.Enforce = &off
		report := buildDoctorReport(cfg, configLabelDefaults)
		if !doctorReportHasCheck(report, "mcp_request_policy", doctorStatusWarn) {
			t.Fatalf("missing mcp request policy warning: %+v", report.Checks)
		}
		check := doctorCheckFor(report, "mcp_request_policy")
		if check.Detail != mcpAuditModeDoctorDetail || check.Enforcing {
			t.Fatalf("doctor check = %+v", check)
		}
	})
}
