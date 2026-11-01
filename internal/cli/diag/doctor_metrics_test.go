// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDoctorMetricsInformational(t *testing.T) {
	for _, address := range []string{"", "127.0.0.1:9091"} {
		cfg := config.Defaults()
		cfg.MetricsListen = address
		report := buildDoctorReport(cfg, configLabelDefaults)
		found := false
		for _, check := range report.Checks {
			if check.Name != "metrics" {
				continue
			}
			found = true
			if check.Status != doctorStatusInfo || check.Configured != (address != "") || check.Reachable || check.Enforcing {
				t.Fatalf("metrics check = %+v", check)
			}
			if address == "" && !strings.Contains(check.Detail, "not exposed unless metrics_listen is set") {
				t.Fatal(check.Detail)
			}
			if address != "" && !strings.Contains(check.Detail, address) {
				t.Fatal(check.Detail)
			}
		}
		if !found {
			t.Fatal("missing metrics information")
		}
	}
}
