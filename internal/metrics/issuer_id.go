// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// Issuer ID block scopes describe the caller/destination history and new-bucket capacity gates.
const (
	IssuerIDBlockSession     = "session"
	IssuerIDBlockDestination = "destination"
	IssuerIDBlockCapacity    = "capacity"
)

func (m *Metrics) registerIssuerIDMetrics(reg *prometheus.Registry) {
	m.issuerIDBlocks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "issuer_id_blocks_total",
		Help:      "Server-issued ID history blocking transitions by scope, without host or ID labels.",
	}, []string{"scope"})
	reg.MustRegister(m.issuerIDBlocks)
}

// RecordIssuerIDBlock counts a newly frozen caller or destination or new-bucket capacity gate.
func (m *Metrics) RecordIssuerIDBlock(scope string) {
	if m == nil || (scope != IssuerIDBlockSession && scope != IssuerIDBlockCapacity && scope != IssuerIDBlockDestination) {
		return
	}
	m.issuerIDBlocks.WithLabelValues(scope).Inc()
}
