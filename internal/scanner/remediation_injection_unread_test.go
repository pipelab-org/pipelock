// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
)

// An injection finding with an unread upload names the injection first, as a
// secret finding does.
func TestInjectionAndUnreadGuidance(t *testing.T) {
	reason := "request body contains prompt injection: Prompt Injection; RAR upload not fully read: no reader; " + IncompleteFileGovernedSuffix
	got, ok := GuidanceForResult(AuditBodyPromptInjection, reason)
	if !ok || !strings.HasPrefix(got.AgentReason, promptInjectionAgentReason) || !strings.Contains(got.AgentReason, "could not be fully read") ||
		strings.Contains(got.AgentReason, "secret") || strings.Contains(got.OperatorKnob, "suppress:") ||
		!strings.Contains(got.OperatorKnob, "trusted_hosts") || !strings.Contains(got.OperatorKnob, "request_body_scanning.action") {
		t.Fatalf("guidance = %+v ok=%t", got, ok)
	}
	agent, ok := FindingAndUnreadAgentReason(reason)
	if !ok || agent != got.AgentReason {
		t.Fatalf("agent reason = %q ok=%t", agent, ok)
	}
	if _, ok := FindingAndUnreadAgentReason("request body contains prompt injection: Prompt Injection"); ok {
		t.Fatal("an injection reason without an unread upload matched")
	}
}
