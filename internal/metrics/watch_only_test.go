// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestWatchOnlyMetricsAndStatus(t *testing.T) {
	m := New()
	for _, enabled := range []bool{false, true, false} {
		m.SetWatchOnly(enabled)
		w := httptest.NewRecorder()
		m.StatsHandler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))
		var got statsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.WatchOnly != enabled {
			t.Fatalf("status mode=%t want %t", got.WatchOnly, enabled)
		}
	}
	m.SetWatchOnly(true)
	m.RecordWatchOnly("forward", "response_size", "uninspected", 42)
	m.RecordWatchOnly("forward", "response_size", "uninspected", -1)
	m.RecordWatchOnly("forward", "blocklist", "block", 0)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	for _, want := range []string{`pipelock_watch_only 1`, `pipelock_watch_only_uninspected_bytes_total{transport="forward"} 42`, `pipelock_watch_only_events_total{action="block",scanner="blocklist",transport="forward"} 1`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("missing %s", want)
		}
	}
	if m.blockedCount != 0 || m.allowedCount != 0 || m.watchOnlyUninspectedBytes != 42 {
		t.Fatal("observations changed traffic counts or lost byte totals")
	}
}

func TestWatchOnlyMetricsConcurrent(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				m.SetWatchOnly(true)
				m.RecordWatchOnly("forward", "response_size", "uninspected", 1)
			}
		})
	}
	wg.Wait()
	if m.watchOnlyUninspectedBytes != 80 {
		t.Fatalf("lost bytes: %d", m.watchOnlyUninspectedBytes)
	}
	var absent *Metrics
	absent.SetWatchOnly(true)
	absent.RecordWatchOnly("forward", "response_size", "uninspected", 1)
}
