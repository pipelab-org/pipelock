// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// registerGitPushMetrics builds the git-push allowlist observation counter.
// The only label is the bounded action. The repository is attacker-controlled
// and is not a label. Enforce-mode refusals are not counted here.
func (m *Metrics) registerGitPushMetrics(reg *prometheus.Registry) {
	m.gitPushDecisions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "git_push_decisions_total",
		Help:      "Configured git push allowlist mismatches observed while enforcement is off.",
	}, []string{"action"})

	reg.MustRegister(m.gitPushDecisions)
}

// RecordGitPushDecision increments the git-push observation counter. action is
// the bounded decision label. A nil Metrics, or one built without New, is safe.
func (m *Metrics) RecordGitPushDecision(action string) {
	if m == nil || m.gitPushDecisions == nil {
		return
	}
	m.gitPushDecisions.WithLabelValues(action).Inc()
}
