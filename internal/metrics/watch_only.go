// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

func (m *Metrics) registerWatchOnlyMetrics(reg *prometheus.Registry) {
	m.watchOnlyMode = prometheus.NewGauge(prometheus.GaugeOpts{Name: "pipelock_watch_only", Help: "Whether watch-only mode is enabled."})
	m.watchOnlyEvents = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "pipelock_watch_only_events_total", Help: "Observed watch-only findings by scanner and original action."}, []string{"transport", "scanner", "action"})
	m.watchOnlyBytes = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "pipelock_watch_only_uninspected_bytes_total", Help: "Bytes forwarded without complete inspection in watch-only."}, []string{"transport"})
	reg.MustRegister(m.watchOnlyMode, m.watchOnlyEvents, m.watchOnlyBytes)
}

// SetWatchOnly publishes the current mode to metrics and status.
func (m *Metrics) SetWatchOnly(enabled bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.watchOnlyEnabled = enabled
	value := 0.0
	if enabled {
		value = 1
	}
	m.watchOnlyMode.Set(value)
}

// RecordWatchOnly accepts bounded transport/scanner/action identifiers, not
// destinations or finding text. Byte counts describe actual forwarded bytes.
func (m *Metrics) RecordWatchOnly(transport, scannerName, action string, uninspectedBytes int64) {
	if m == nil {
		return
	}
	m.watchOnlyEvents.WithLabelValues(transport, scannerName, action).Inc()
	if uninspectedBytes > 0 {
		m.watchOnlyBytes.WithLabelValues(transport).Add(float64(uninspectedBytes))
		m.mu.Lock()
		m.watchOnlyUninspectedBytes += uninspectedBytes
		m.mu.Unlock()
	}
}
