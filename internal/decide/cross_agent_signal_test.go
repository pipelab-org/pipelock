// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestCrossAgentSignalRequiresEnforcedEvidence(t *testing.T) {
	for _, enforced := range []bool{false, true} {
		for _, indeterminate := range []bool{false, true} {
			for _, hostile := range []bool{false, true} {
				observation := CrossAgentResult{ShouldEscalate: hostile, Indeterminate: indeterminate}
				want := session.SignalWarning
				if hostile && (enforced || indeterminate) {
					want = session.SignalCrossAgentContamination
				}
				if got := observation.AdaptiveSignal(enforced); got != want {
					t.Fatalf("%+v enforced=%v: got %v, want %v", observation, enforced, got, want)
				}
			}
		}
	}
}
