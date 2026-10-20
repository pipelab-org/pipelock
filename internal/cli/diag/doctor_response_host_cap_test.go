// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDoctorResponseHostCapExpiry(t *testing.T) {
	now := time.Now().UTC()
	c := config.Defaults()
	c.ResponseScanning.SizeExemptScanLimits = []config.ResponseSizeScanLimit{{
		Host: "downloads.vendor.example", MaxBytes: 128 << 20, Owner: "operator", Reason: "scanned fixture",
		Added: now.Add(-2 * time.Hour).Format(time.RFC3339Nano), Expires: now.Add(-time.Hour).Format(time.RFC3339Nano),
	}}
	before := c.CanonicalPolicyHash()
	report := buildDoctorReport(c, "/config/pipelock.yaml")
	found := false
	for _, check := range report.Checks {
		if strings.Contains(check.Name, "size_exempt_scan_limits") {
			found = check.Status == doctorStatusWarn && strings.Contains(check.Detail, "/config/pipelock.yaml") && strings.Contains(check.Detail, "downloads.vendor.example") && strings.Contains(check.Detail, "size_exempt_scan_max_bytes")
		}
	}
	if !found {
		t.Fatal("doctor omitted the expiring cap remedy or config path")
	}
	if c.CanonicalPolicyHash() != before {
		t.Fatal("doctor mutated loaded policy")
	}
}
