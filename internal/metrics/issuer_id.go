// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// Issuer ID block scopes describe the caller-local history and new-bucket capacity gates.
const (
	IssuerIDBlockSession  = "session"
	IssuerIDBlockCapacity = "capacity"
)

func (m *Metrics) registerIssuerIDMetrics(reg *prometheus.Registry) {
	m.issuerIDBlocks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "issuer_id_blocks_total",
		Help:      "Server-issued ID history blocking transitions by scope, without host or ID labels.",
	}, []string{"scope"})
	reg.MustRegister(m.issuerIDBlocks)
}

// RecordIssuerIDBlock counts a newly tainted caller bucket or new-bucket capacity gate.
func (m *Metrics) RecordIssuerIDBlock(scope string) {
	if m == nil || (scope != IssuerIDBlockSession && scope != IssuerIDBlockCapacity) {
		return
	}
	m.issuerIDBlocks.WithLabelValues(scope).Inc()
}
