// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package decide_test

import (
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestCrossAgentFindingKinds(t *testing.T) {
	rec := &riskRecorder{}
	want := []session.HostileFindingKind{session.FindingDLP, session.FindingWording}
	rec.ObserveRisk(session.RiskObservation{FindingKinds: want})
	for _, boundary := range []session.CrossAgentBoundary{session.CrossAgentBoundaryA2ARequest, session.CrossAgentBoundaryMCPToolCall} {
		first := decide.ObserveCrossAgentContamination(rec, enabledTaintCfg(), boundary)
		if !first.Contaminated || !first.ShouldEscalate || !first.SourceRecorded {
			t.Fatalf("cross-agent behavior changed: %+v", first)
		}
		risk := rec.RiskSnapshot()
		if !slices.Equal(risk.FindingKinds, want) || !slices.Equal(risk.Sources[len(risk.Sources)-1].FindingKinds, want) {
			t.Fatalf("propagation lost causes: %+v", risk)
		}
		repeat := decide.ObserveCrossAgentContamination(rec, enabledTaintCfg(), boundary)
		if repeat.SourceRecorded || !repeat.ShouldEscalate {
			t.Fatalf("same-cause propagation no longer deduplicates: %+v", repeat)
		}
	}
}
