// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"crypto/ed25519"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestSetAttributionRedaction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report *redact.Report
	}{
		{name: "missing"},
		{name: "not applied", report: &redact.Report{TotalRedactions: 2}},
		{name: "zero redactions", report: &redact.Report{Applied: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action := Action{Redaction: &Redaction{}}
			action.SetAttribution(receipt.EmitOpts{RedactionReport: tc.report})
			if action.Redaction != nil {
				t.Fatalf("redaction attribution = %+v, want none", action.Redaction)
			}
		})
	}

	var action Action
	action.SetAttribution(receipt.EmitOpts{
		RedactionProfile: "default",
		RedactionReport: &redact.Report{
			Applied: true, TotalRedactions: 3, Provider: "vendor", Parser: "json",
			ByClass: map[redact.Class]int{"email": 2, "address": 1},
		},
	})
	got := action.Redaction
	want := []RedactionClass{{Class: "address", Count: 1}, {Class: "email", Count: 2}}
	if got == nil || got.Profile != "default" || got.Provider != "vendor" || got.Parser != "json" ||
		got.TotalRedactions == nil || *got.TotalRedactions != 3 || !slices.Equal(got.Classes, want) {
		t.Fatalf("redaction attribution = %+v, want profile and sorted class counts", got)
	}
}

func TestSetAttributionContractGeneration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		generation uint64
		want       int64
	}{
		{name: "maximum", generation: maxInteger, want: maxInteger},
		{name: "out of range", generation: maxInteger + 1, want: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var action Action
			action.SetAttribution(receipt.EmitOpts{ContractGeneration: tc.generation})
			if action.Contract == nil || action.Contract.Generation == nil || *action.Contract.Generation != tc.want {
				t.Fatalf("contract attribution = %+v, want generation %d", action.Contract, tc.want)
			}
		})
	}
}

func TestStreamWriterSignsShieldAttribution(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	action := writerTestIntent("shield")
	action.SetAttribution(receipt.EmitOpts{Shield: &receipt.ShieldSummary{
		Pipeline: "html", TotalRewrites: 5, TrackingBeacons: 4, AgentTraps: 1,
		FingerprintShimInjected: true, BodyBytes: 100, ScannedBytes: 80, Partial: true,
	}})
	if err := w.WriteAction(t.Context(), action, PolicySnapshot{}); err != nil {
		t.Fatal(err)
	}
	stream := w.active.id
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	actions := readRecoveryActions(t, opts.Dir, stream)
	if len(actions) != 1 {
		t.Fatalf("signed actions = %d, want 1", len(actions))
	}
	want := Shield{
		Pipeline: "html", TotalRewrites: new(int64(5)), TrackingBeacons: new(int64(4)), AgentTraps: new(int64(1)),
		FingerprintShimInjected: new(true), BodyBytes: new(int64(100)), ScannedBytes: new(int64(80)), Partial: new(true),
	}
	if !reflect.DeepEqual(actions[0].Shield, &want) {
		t.Fatalf("signed Browser Shield summary = %+v, want %+v", actions[0].Shield, want)
	}
}

func TestSetAttributionOmitsURLLessTaintSources(t *testing.T) {
	stamp := time.Date(2026, 1, 1, 12, 30, 0, 123, time.FixedZone("example", 3600))
	opts := receipt.EmitOpts{
		SessionID: "example-session", SessionTaintLevel: "external_untrusted",
		AuthorityKind: "policy", TaintDecision: "warn",
		TaintDecisionReason: "review requested", TaskOverrideApplied: true,
		RecentTaintSources: []session.TaintSourceRef{
			{Kind: "mcp_response", Level: session.TaintExternalUntrusted, Timestamp: stamp},
			{Kind: "fetch", URL: "https://api.vendor.example/private?item=example", Level: session.TaintExternalUntrusted, Timestamp: stamp},
		},
	}
	var action Action
	action.SetAttribution(opts)
	wantSession := &Session{
		ID: "example-session", TaintLevel: "external_untrusted", Contaminated: new(false),
		TaintSources: []TaintSource{{
			Kind: "fetch", Level: int64(session.TaintExternalUntrusted),
			Timestamp: "2026-01-01T11:30:00.000000123Z", URL: "https://api.vendor.example",
		}},
	}
	wantTaint := &Taint{AuthorityKind: "policy", Decision: "warn", Reason: "review requested", TaskOverrideApplied: new(true)}
	if !reflect.DeepEqual(action.Session, wantSession) || !reflect.DeepEqual(action.Taint, wantTaint) {
		t.Fatalf("session = %+v, taint = %+v, want %+v and %+v", action.Session, action.Taint, wantSession, wantTaint)
	}
	action.SetAttribution(receipt.EmitOpts{RecentTaintSources: opts.RecentTaintSources[:1]})
	if action.Session != nil || action.Taint != nil {
		t.Fatalf("URL-less source created attribution: %+v", action)
	}
}

func TestSetAttributionPreservesContractSourceSnapshot(t *testing.T) {
	sources := []string{"header"}
	var action Action
	action.SetAttribution(receipt.EmitOpts{ContractPolicySources: sources})
	sources[0] = "body"
	if action.Contract == nil || !slices.Equal(action.Contract.PolicySources, []string{"header"}) {
		t.Fatalf("contract attribution changed with the caller's slice: %+v", action.Contract)
	}
}

func TestStreamWriterOmitsEmptyShieldAttribution(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	action := writerTestIntent("empty-shield")
	action.SetAttribution(receipt.EmitOpts{Shield: &receipt.ShieldSummary{}})
	if err := w.WriteAction(t.Context(), action, PolicySnapshot{}); err != nil {
		t.Fatalf("empty summary prevented receipt admission: %v", err)
	}
	if got := readRecoveryActions(t, opts.Dir, w.active.id); len(got) != 1 || got[0].Shield != nil {
		t.Fatalf("signed action retained an empty Shield object: %+v", got)
	}
}
