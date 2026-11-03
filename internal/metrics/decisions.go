// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type urlDecisionKey struct {
	transport string
	check     string
}

const decisionOutcomeCount = 5

// registerDecisionMetrics prebinds every counter. Request recording only reads
// this immutable map and increments Prometheus counters; it creates no series.
func (m *Metrics) registerDecisionMetrics(reg *prometheus.Registry) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "url_check_decisions_total",
		Help:      "Top-level URL check outcomes before transport enforcement; counts may overlap.",
	}, []string{"check", "outcome", "transport", "part"})
	reg.MustRegister(counter)
	m.urlDecisions = make(map[urlDecisionKey][decisionOutcomeCount]prometheus.Counter)
	// These are the URL entry transports in internal/proxy. There is no
	// caller-controlled label fallback.
	for _, transport := range []string{"fetch", "forward", "connect", "intercept", "websocket", "reverse"} {
		for _, check := range []string{
			scanner.ScannerContext, scanner.ScannerLength, scanner.ScannerParser,
			scanner.ScannerScheme, scanner.ScannerCRLF, scanner.ScannerPathTraversal,
			scanner.ScannerAllowlist, scanner.ScannerBlocklist, scanner.ScannerCoreSSRF,
			scanner.ScannerCoreDLP, scanner.ScannerDLP, scanner.ScannerEntropy,
			scanner.ScannerSubdomainEntropy, scanner.ScannerAll, scanner.ScannerSSRF, scanner.ScannerRateLimit,
			scanner.ScannerDataBudget,
		} {
			part := "url"
			if check == scanner.ScannerAll {
				part = "url_query"
			}
			var handles [decisionOutcomeCount]prometheus.Counter
			for i, outcome := range []string{"not_evaluated", "allowed", "fired", "blocked", "relieved"} {
				handles[i] = counter.WithLabelValues(check, outcome, transport, part)
			}
			m.urlDecisions[urlDecisionKey{transport, check}] = handles
		}
	}
}

// RecordURLDecisions counts the selected URL scan once, after any issuer rescan.
// Unknown transports and zero-value traces produce no samples.
func (m *Metrics) RecordURLDecisions(transport string, decisions scanner.URLDecisions) {
	if m == nil {
		return
	}
	decisions.Range(func(check, _ string, outcome scanner.Decision) {
		handles, ok := m.urlDecisions[urlDecisionKey{transport, check}]
		if !ok {
			return
		}
		if outcome == scanner.DecisionNotEvaluated {
			handles[0].Inc()
			return
		}
		for i, flag := range [...]scanner.Decision{
			scanner.DecisionAllowed, scanner.DecisionFired,
			scanner.DecisionBlocked, scanner.DecisionRelieved,
		} {
			if outcome&flag != 0 {
				handles[i+1].Inc()
			}
		}
	})
}
