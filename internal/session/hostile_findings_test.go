// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

var allHostileKinds = []session.HostileFindingKind{
	session.FindingWording, session.FindingDLP, session.FindingToolPoisoning, session.FindingToolDrift,
	session.FindingToolAcknowledgment, session.FindingURL, session.FindingEntropy, session.FindingUnattributed,
	session.FindingToolProvenance, session.FindingAgentCard, session.FindingInspectionIncomplete, session.FindingScanError,
	session.FindingSSEEventTooLarge, session.FindingSSEInvalidUTF8,
}

func TestHostileFindingKindsVerdictEquivalence(t *testing.T) {
	// Every subset, including no findings, is compared with the pre-existing
	// boolean path at every source level and every policy matrix input.
	for mask := 0; mask < 1<<len(allHostileKinds); mask++ {
		var kinds []session.HostileFindingKind
		for bit, kind := range allHostileKinds {
			if mask&(1<<bit) != 0 {
				kinds = append(kinds, kind)
			}
		}
		for level := session.TaintTrusted; level <= session.TaintExternalHostile; level++ {
			var old, attributed session.SessionRisk
			source := session.TaintSourceRef{URL: "https://api.vendor.example/result", Kind: "http_response", Level: level, Timestamp: time.Unix(1, 0).UTC()}
			old.Observe(session.RiskObservation{Source: source, PromptHit: len(kinds) > 0})
			attributed.Observe(session.RiskObservation{Source: source, FindingKinds: kinds})
			if old.Level != attributed.Level || old.PromptHit != attributed.PromptHit || old.Contaminated != attributed.Contaminated || old.Sources[0].MatchReason != attributed.Sources[0].MatchReason {
				t.Fatalf("mask=%d level=%v boolean=%+v attributed=%+v", mask, level, old, attributed)
			}
			old.FindingKinds, attributed.FindingKinds = nil, nil
			old.Sources[0].FindingKinds, attributed.Sources[0].FindingKinds = nil, nil
			if !reflect.DeepEqual(old, attributed) {
				t.Fatalf("non-metadata state changed mask=%d level=%v", mask, level)
			}
			for _, profile := range []string{"strict", "balanced", "permissive"} {
				matrix := session.PolicyMatrix{Profile: profile}
				for action := session.ActionClassRead; action <= session.ActionClassNetwork; action++ {
					for sensitivity := session.SensitivityNormal; sensitivity <= session.SensitivityProtected; sensitivity++ {
						for authority := session.AuthorityUnknown; authority <= session.AuthorityOperatorOverride; authority++ {
							if matrix.Evaluate(old.Level, action, sensitivity, authority) != matrix.Evaluate(attributed.Level, action, sensitivity, authority) {
								t.Fatalf("decision changed mask=%d profile=%s", mask, profile)
							}
						}
					}
				}
			}
		}
	}
}

func TestHostileFindingCauseAndMalformedJSON(t *testing.T) {
	if got := (session.SessionRisk{}).HostileCause(); got != "" {
		t.Fatalf("clean state explains hostility: %q", got)
	}
	var risk session.SessionRisk
	if err := json.Unmarshal([]byte(`{"prompt_hit":"invalid"}`), &risk); err == nil {
		t.Fatal("malformed snapshot accepted")
	}
	for _, kind := range allHostileKinds {
		t.Run(string(kind), func(t *testing.T) {
			if got := (session.SessionRisk{FindingKinds: []session.HostileFindingKind{kind}}).HostileCause(); got == "" {
				t.Fatal("cause omitted")
			}
		})
	}
}

func TestHostileFindingKindsStickyUnion(t *testing.T) {
	for _, kind := range allHostileKinds {
		t.Run(string(kind), func(t *testing.T) {
			var risk session.SessionRisk
			for range 3 {
				risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{Kind: "response"}, FindingKinds: []session.HostileFindingKind{kind}, MaxSources: 1})
			}
			if !slices.Equal(risk.FindingKinds, []session.HostileFindingKind{kind}) || !risk.PromptHit || !risk.Contaminated || risk.Level != session.TaintExternalHostile {
				t.Fatalf("kind lost or verdict changed: %+v", risk)
			}
			risk.Observe(session.RiskObservation{FindingKinds: allHostileKinds, MaxSources: 1})
			risk.Observe(session.RiskObservation{Source: session.TaintSourceRef{Kind: "clean"}, MaxSources: 1})
			if !slices.Equal(risk.FindingKinds, session.MergeFindingKinds(allHostileKinds)) {
				t.Fatalf("union lost after source eviction: %+v", risk)
			}
			encoded, err := json.Marshal(risk)
			if err != nil {
				t.Fatal(err)
			}
			var decoded session.SessionRisk
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			roundTrip, err := json.Marshal(decoded)
			if err != nil || string(roundTrip) != string(encoded) || !slices.Equal(decoded.FindingKinds, risk.FindingKinds) {
				t.Fatalf("live snapshot round trip lost evidence: %s err=%v", roundTrip, err)
			}
			snapshotClone := risk.Snapshot()
			snapshotClone.FindingKinds[0] = "changed"
			if slices.Contains(risk.FindingKinds, "changed") {
				t.Fatal("snapshot aliases live evidence")
			}
		})
	}
}

func TestHostileFindingKindsJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want []session.HostileFindingKind
	}{
		{"legacy", `{"prompt_hit":true}`, []session.HostileFindingKind{session.FindingUnattributed}},
		{"wording", `{"level":5,"contaminated":true,"prompt_hit":true,"finding_kinds":["prompt_injection_wording"]}`, []session.HostileFindingKind{session.FindingWording}},
		{"mixed", `{"prompt_hit":true,"finding_kinds":["dlp","prompt_injection_wording","dlp"]}`, session.MergeFindingKinds([]session.HostileFindingKind{session.FindingWording, session.FindingDLP})},
		{"unknown", `{"prompt_hit":true,"finding_kinds":["future","another"]}`, []session.HostileFindingKind{session.FindingUnattributed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var risk session.SessionRisk
			if err := json.Unmarshal([]byte(tc.raw), &risk); err != nil {
				t.Fatal(err)
			}
			if !risk.Contaminated || risk.Level != session.TaintExternalHostile || !slices.Equal(risk.FindingKinds, tc.want) {
				t.Fatalf("unexpected decoded state: %+v", risk)
			}
			encoded, err := json.Marshal(risk)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip session.SessionRisk
			if err := json.Unmarshal(encoded, &roundTrip); err != nil || !reflect.DeepEqual(risk, roundTrip) {
				t.Fatalf("round trip lost evidence: %s err=%v", encoded, err)
			}
		})
	}
	encoded, err := json.Marshal(session.SessionRisk{})
	if err != nil || strings.Contains(string(encoded), "finding_kinds") {
		t.Fatalf("unused field extended old JSON: %s err=%v", encoded, err)
	}
	observation, err := json.Marshal(session.RiskObservation{})
	if err != nil || strings.Contains(string(observation), "finding_kinds") {
		t.Fatalf("unused observation field extended old JSON: %s err=%v", observation, err)
	}
	observation, err = json.Marshal(session.RiskObservation{FindingKinds: []session.HostileFindingKind{session.FindingWording}})
	if err != nil || !strings.Contains(string(observation), `"finding_kinds":["prompt_injection_wording"]`) {
		t.Fatalf("observation lost its cause: %s err=%v", observation, err)
	}
	// TaintSourceRef is embedded in signed v1 receipts. Its JSON cannot grow.
	plain, _ := json.Marshal(session.TaintSourceRef{})
	withKinds, _ := json.Marshal(session.TaintSourceRef{FindingKinds: allHostileKinds})
	if string(plain) != string(withKinds) {
		t.Fatalf("signed source schema changed: %s != %s", plain, withKinds)
	}
}

func TestHostileFindingKindsLegacySurvivesObservationsAndCrossAgent(t *testing.T) {
	risk := session.SessionRisk{Level: session.TaintExternalHostile, PromptHit: true, Contaminated: true}
	risk.Observe(session.RiskObservation{FindingKinds: []session.HostileFindingKind{session.FindingWording}})
	want := session.MergeFindingKinds([]session.HostileFindingKind{session.FindingUnattributed, session.FindingWording})
	if !slices.Equal(risk.FindingKinds, want) {
		t.Fatal("legacy evidence silently relabeled wording-only")
	}
	observation := session.ClassifyCrossAgentObservation(risk, session.CrossAgentBoundaryMCPToolCall)
	if observation.PromptHit || !slices.Equal(observation.Source.FindingKinds, want) {
		t.Fatalf("cross-agent observation changed the old trigger: %+v", observation)
	}
	risk.Observe(observation)
	if !slices.Equal(risk.FindingKinds, want) || risk.Sources[len(risk.Sources)-1].MatchReason != "cross_agent_mcp_tool_call" {
		t.Fatalf("cross-agent cause or reason lost: %+v", risk)
	}
	snapshotClone := risk.Snapshot()
	snapshotClone.Sources[len(snapshotClone.Sources)-1].FindingKinds[0] = "changed"
	if slices.Contains(risk.Sources[len(risk.Sources)-1].FindingKinds, "changed") {
		t.Fatal("snapshot source aliases live evidence")
	}
}
