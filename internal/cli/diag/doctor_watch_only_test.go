// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/spf13/cobra"
)

func TestDoctorWatchOnly(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.WatchOnly = enabled
		cfg.ForwardProxy.Enabled = true
		report := buildDoctorReport(cfg, "test configuration")
		if report.WatchOnly != enabled || doctorGlobalEnforce(cfg) == enabled {
			t.Fatal("doctor disagrees with effective enforcement")
		}
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(encoded), `"watch_only":`) {
			t.Fatal("JSON omits explicit mode")
		}
		found := false
		for _, c := range report.Checks {
			if enabled && strings.Contains(c.Detail, "enforce=false") {
				t.Fatalf("watch-only misreported as audit: %+v", c)
			}
			if c.Name == "watch_only" {
				found = true
				if c.Enforcing || !strings.Contains(c.Detail, "core credential floor") || !strings.Contains(c.Detail, "kill switch") || !strings.Contains(c.Detail, "access controls") {
					t.Fatalf("bad watch-only check: %+v", c)
				}
			}
		}
		if found != enabled {
			t.Fatalf("watch-only check=%t want %t", found, enabled)
		}
		var buf bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&buf)
		printDoctorReport(cmd, report, false)
		if strings.Contains(buf.String(), "Watch-only: enabled") != enabled {
			t.Fatal("text output mode missing or spurious")
		}
	}
}
