// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

func (m *Metrics) registerMCPTaintMetrics(reg *prometheus.Registry) {
	m.mcpTaintContexts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "mcp_taint_contexts_total",
		Help: "MCP invocation or listener request contexts by actual taint recorder status; not a count of protected sessions or enforced decisions.",
	}, []string{"binding", "status"})
	m.mcpTaintReportsSkipped = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "mcp_taint_reports_skipped_total",
		Help: "Optional MCP invocation, listener and refusal reports skipped because the shared log writer was busy; excludes throttled contexts and config-only notices.",
	})
	reg.MustRegister(m.mcpTaintContexts, m.mcpTaintReportsSkipped)
}

// RecordMCPTaintContext records bounded state-registry outcomes without caller
// names, session keys, URLs, or other request-controlled metric labels.
func (m *Metrics) RecordMCPTaintContext(binding, status string) {
	if m == nil || m.mcpTaintContexts == nil {
		return
	}
	switch binding {
	case "stdio_subprocess", "stdio_http", "stdio_ws", "listener_principal", "listener_legacy", "listener_token", "listener_stateless":
	default:
		return
	}
	switch status {
	case "active", "inactive", "disabled":
		m.mcpTaintContexts.WithLabelValues(binding, status).Inc()
	}
}

// RecordMCPTaintReportSkipped counts busy-writer admission refusals without
// labels or caller-controlled values. A delivered report is not guaranteed.
func (m *Metrics) RecordMCPTaintReportSkipped() {
	if m != nil && m.mcpTaintReportsSkipped != nil {
		m.mcpTaintReportsSkipped.Inc()
	}
}
