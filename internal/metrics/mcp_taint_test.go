// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"fmt"
	"strings"
	"testing"
)

func TestMCPTaintContextMetrics_BoundedActualStatus(t *testing.T) {
	var absent *Metrics
	absent.RecordMCPTaintContext("stdio_subprocess", "active")
	m := New()
	for _, binding := range []string{"stdio_subprocess", "stdio_http", "stdio_ws", "listener_principal", "listener_legacy", "listener_token", "listener_stateless"} {
		for _, status := range []string{"active", "inactive", "disabled"} {
			m.RecordMCPTaintContext(binding, status)
			want := fmt.Sprintf(`pipelock_mcp_taint_contexts_total{binding=%q,status=%q} 1`, binding, status)
			if !strings.Contains(scrapeMetrics(t, m), want) {
				t.Fatalf("missing %s", want)
			}
		}
	}
	m.RecordMCPTaintContext("api.vendor.example", "active")
	m.RecordMCPTaintContext("stdio_http", "private-label")
	if body := scrapeMetrics(t, m); strings.Contains(body, "api.vendor.example") || strings.Contains(body, "private-label") {
		t.Fatal("unbounded input entered metric labels")
	}
}

func TestMCPTaintContextMetrics_ZeroValue(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("zero-value metrics panicked: %v", r)
		}
	}()
	(&Metrics{}).RecordMCPTaintContext("listener_principal", "inactive")
}

func TestMCPTaintReportSkippedMetrics(t *testing.T) {
	var absent *Metrics
	absent.RecordMCPTaintReportSkipped()
	(&Metrics{}).RecordMCPTaintReportSkipped()
	m := New()
	for want := 0; want < 3; want++ {
		if body := scrapeMetrics(t, m); !strings.Contains(body, fmt.Sprintf("pipelock_mcp_taint_reports_skipped_total %d\n", want)) {
			t.Fatalf("missing skipped report count %d", want)
		}
		m.RecordMCPTaintReportSkipped()
	}
}

func TestMCPTaintReportSkippedMetrics_UninitializedIsSafe(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    *Metrics
	}{{"nil", nil}, {"zero", &Metrics{}}} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Error("uninitialized skipped counter did not remain inert")
				}
			}()
			tc.m.RecordMCPTaintReportSkipped()
		})
	}
}
