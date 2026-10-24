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
