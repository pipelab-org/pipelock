// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// Issuer ID block scopes describe the existing host and global history gates.
const (
	IssuerIDBlockHost   = "host"
	IssuerIDBlockGlobal = "global"
)

func (m *Metrics) registerIssuerIDMetrics(reg *prometheus.Registry) {
	m.issuerIDBlocks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "issuer_id_blocks_total",
		Help:      "Server-issued ID history blocking transitions by scope, without host or ID labels.",
	}, []string{"scope"})
	reg.MustRegister(m.issuerIDBlocks)
}

// RecordIssuerIDBlock counts a newly blocked host or global history gate.
func (m *Metrics) RecordIssuerIDBlock(scope string) {
	if m == nil || (scope != IssuerIDBlockHost && scope != IssuerIDBlockGlobal) {
		return
	}
	m.issuerIDBlocks.WithLabelValues(scope).Inc()
}
