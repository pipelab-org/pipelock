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

// Address-poisoning and high-entropy findings with an unread upload keep their
// own sentences first; the unread-file guidance follows.
func TestAddressAndEntropyUnreadGuidance(t *testing.T) {
	unread := "; RAR upload not fully read: no reader; " + IncompleteFileGovernedSuffix
	for _, tc := range []struct {
		name, reason, agent, knob string
	}{
		{"address", "address poisoning detected: lookalike of a known address" + unread, auditPolicyAgentReason, "address_protection.allowed_addresses"},
		{"entropy", "high entropy request body content (5.10 > 4.50 threshold, 64 bytes)" + unread, highEntropyAgentReason, "content_entropy_warn_routes"},
		{"opaque entropy", "opaque hex request body content (entropy 3.90, threshold 3.50, 64 bytes)" + unread, highEntropyAgentReason, "content_entropy_warn_routes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := GuidanceForResult(AuditBodyEntropy, tc.reason)
			if !ok || !strings.HasPrefix(got.AgentReason, tc.agent) || !strings.Contains(got.AgentReason, "could not be fully read") ||
				!strings.Contains(got.OperatorKnob, tc.knob) || !strings.Contains(got.OperatorKnob, "request_body_scanning.action") {
				t.Fatalf("guidance = %+v ok=%t", got, ok)
			}
			agent, ok := FindingAndUnreadAgentReason(tc.reason)
			if !ok || agent != got.AgentReason {
				t.Fatalf("agent reason = %q ok=%t", agent, ok)
			}
		})
	}
	// "opaque " alone is not the entropy form, and no reason matches without
	// an unread upload.
	if _, ok := FindingAndUnreadAgentReason("opaque payload" + unread); ok {
		t.Fatal("a non-entropy opaque reason matched")
	}
	if _, ok := FindingAndUnreadAgentReason("high entropy request body content (5.10 > 4.50 threshold, 64 bytes)"); ok {
		t.Fatal("an entropy reason without an unread upload matched")
	}
}

// A JSON inspection limit with an unread upload keeps the fixed-limit guidance:
// suppression cannot lift it, so the secret-finding sentence must not appear.
func TestJSONInspectionLimitAndUnreadGuidance(t *testing.T) {
	unread := "; ZIP upload not fully read: encrypted member; " + IncompleteFileGovernedSuffix
	limit := jsonInspectionLimitGuidance()
	for _, names := range []string{UninspectableJSONNumberPattern, "Stripe Key, " + UninspectableJSONNumberPattern} {
		reason := "request body contains secret: " + names + unread
		got, ok := GuidanceForResult(ScannerBodyDLP, reason)
		if !ok || !got.Immutable || !strings.HasPrefix(got.AgentReason, limit.AgentReason) || !strings.Contains(got.AgentReason, "could not be fully read") ||
			strings.Contains(got.OperatorKnob, "suppress:") || !strings.Contains(got.OperatorKnob, limit.OperatorKnob) || !strings.Contains(got.OperatorKnob, "request_body_scanning.action") {
			t.Fatalf("%s: guidance = %+v ok=%t", names, got, ok)
		}
		agent, ok := FindingAndUnreadAgentReason(reason)
		if !ok || agent != got.AgentReason {
			t.Fatalf("%s: agent reason = %q ok=%t", names, agent, ok)
		}
	}
	// An ordinary secret with an unread upload keeps the suppression sentence.
	got, ok := GuidanceForResult(ScannerBodyDLP, "request body contains secret: Stripe Key"+unread)
	if !ok || got.Immutable || !strings.Contains(got.OperatorKnob, "suppress:") {
		t.Fatalf("ordinary secret guidance = %+v ok=%t", got, ok)
	}
}
