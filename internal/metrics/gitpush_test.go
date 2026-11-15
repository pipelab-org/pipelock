// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordGitPushDecision(t *testing.T) {
	t.Parallel()
	m := New()
	m.RecordGitPushDecision("audit_block")
	m.RecordGitPushDecision("audit_block")
	if got := testutil.ToFloat64(m.gitPushDecisions.WithLabelValues("audit_block")); got != 2 {
		t.Errorf("audit_block count = %v, want 2", got)
	}
}

func TestRecordGitPushDecisionNilSafe(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordGitPushDecision("audit_block")
	(&Metrics{}).RecordGitPushDecision("audit_block")
}
