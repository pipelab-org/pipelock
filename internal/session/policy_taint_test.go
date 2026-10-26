// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package session

import "testing"

func TestSessionRiskHasPolicyTaintMatchesEnforcement(t *testing.T) {
	for _, level := range []TaintLevel{TaintTrusted, TaintInternalGenerated, TaintAllowlistedReference, TaintExternalLowRisk, TaintExternalUntrusted, TaintExternalHostile} {
		t.Run(level.String(), func(t *testing.T) {
			for _, contaminated := range []bool{false, true} {
				risk := SessionRisk{Level: level, Contaminated: contaminated}
				decision := (PolicyMatrix{}).Evaluate(level, ActionClassExec, SensitivityNormal, AuthorityUserBroad)
				if risk.HasPolicyTaint() != (decision.Decision != PolicyAllow) {
					t.Fatalf("level=%v contaminated=%t: protection=%t decision=%v", level, contaminated, risk.HasPolicyTaint(), decision)
				}
			}
		})
	}
}
