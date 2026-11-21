// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"reflect"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestActionSetAttribution(t *testing.T) {
	action := Action{}
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 6, time.FixedZone("example", 3600))
	opts := receipt.EmitOpts{
		SessionID: "session", SessionIDOriginal: "original", SessionTaskID: "task",
		SessionTaskLabel: "label", SessionTaintLevel: "low",
		RecentTaintSources: []session.TaintSourceRef{
			{},
			{URL: "https://api.vendor.example/path?query=value", Timestamp: stamp, ReceiptID: "reference", MatchReason: "matched"},
		},
		AuthorityKind: "task", TaintDecision: "allow", TaintDecisionReason: "matched", TaskOverrideApplied: true,
		ContractGeneration: 3, ContractPolicySources: []string{"manifest"},
		RedactionProfile: "example",
		RedactionReport: &redact.Report{
			Applied: true, Provider: "generic-json", Parser: "json", TotalRedactions: 3,
			ByClass: map[redact.Class]int{"z": 2, "a": 1},
		},
		Shield: &receipt.ShieldSummary{Pipeline: "html", TotalRewrites: 2, FingerprintShimInjected: true, Partial: true},
	}
	action.SetAttribution(opts)
	opts.ContractPolicySources[0] = "changed"
	wantSession := &Session{
		ID: "session", OriginalID: "original", TaskID: "task", TaskLabel: "label", TaintLevel: "low", Contaminated: new(false),
		TaintSources: []TaintSource{{URL: "https://api.vendor.example", Timestamp: "2026-01-02T02:04:05.000000006Z", ReceiptID: "reference", MatchReason: "matched"}},
	}
	wantTaint := &Taint{AuthorityKind: "task", Decision: "allow", Reason: "matched", TaskOverrideApplied: new(true)}
	wantContract := &Contract{Generation: new(int64(3)), PolicySources: []string{"manifest"}}
	wantRedaction := &Redaction{
		Profile: "example", Provider: "generic-json", Parser: "json", TotalRedactions: new(int64(3)),
		Classes: []RedactionClass{{Class: "a", Count: 1}, {Class: "z", Count: 2}},
	}
	wantShield := &Shield{Pipeline: "html", TotalRewrites: new(int64(2)), FingerprintShimInjected: new(true), Partial: new(true)}
	for _, check := range []struct {
		name      string
		got, want any
	}{
		{"session", action.Session, wantSession},
		{"taint", action.Taint, wantTaint},
		{"contract", action.Contract, wantContract},
		{"redaction", action.Redaction, wantRedaction},
		{"shield", action.Shield, wantShield},
	} {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s attribution = %+v, want %+v", check.name, check.got, check.want)
		}
	}

	action.SetAttribution(receipt.EmitOpts{
		RedactionReport: &redact.Report{Applied: true}, Shield: &receipt.ShieldSummary{},
	})
	if action.Session != nil || action.Taint != nil || action.Contract != nil || action.Redaction != nil || action.Shield != nil {
		t.Fatalf("empty options retained attribution: %+v", action)
	}
}

func TestActionContractGenerationForWireValidation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		generation uint64
		want       *int64
	}{
		{"absent", 0, nil},
		{"maximum", maxInteger, new(int64(maxInteger))},
		{"overflow", maxInteger + 1, new(int64(-1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action := Action{}
			action.SetAttribution(receipt.EmitOpts{ContractHash: Digest([]byte("contract")), ContractGeneration: tc.generation})
			if action.Contract == nil || !reflect.DeepEqual(action.Contract.Generation, tc.want) {
				t.Fatalf("generation mapping for %d = %+v, want %+v", tc.generation, action.Contract, tc.want)
			}
		})
	}
}
