// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func testDecisionIndexFinding(t *testing.T) {
	ctx := t.Context()
	a := appraisal{
		index:       decisionIndex{ctx: ctx, maxIDs: 1},
		fullHistory: true,
	}
	verification := verification{ctx: ctx}
	if err := a.index.reset(); err != nil {
		t.Fatal(err)
	}
	remember := func() {
		t.Helper()
		for _, id := range []string{"first", "first", "second"} {
			if err := a.index.remember(id, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	remember()
	if err := verification.appraiseHistory(&a, nil, &verifiedStream{}); err != nil {
		t.Fatal(err)
	}
	if !hasFinding(verification.result, codeDecisionIndexFull) || a.fullHistory || len(a.index.ids) != 1 {
		t.Fatalf("limit not enforced: %+v, %+v", a.index, verification.result.Findings)
	}
	baseline := verification.result
	verification.result = Result{}
	a.index.skipLimit = true
	if err := a.index.reset(); err != nil {
		t.Fatal(err)
	}
	remember()
	if err := verification.appraiseHistory(&a, nil, &verifiedStream{}); err != nil {
		t.Fatal(err)
	}
	if len(a.index.ids) != 2 {
		t.Fatal("disabled limit still drops a decision identifier")
	}
	requireMutation(t, codeDecisionIndexFull, baseline, verification.result)
}

func TestPieceShapeAndUnknownStart(t *testing.T) {
	one := int64(1)
	correction := true
	for _, tc := range []struct {
		name              string
		action            Action
		unknown, required bool
		want              string
	}{
		{"unobserved ask", Action{Phase: "decision", Verdict: "ask", EffectBoundary: "hook_execution", EffectRelation: "before", Ask: &Ask{Channel: "host_prompt"}}, false, true, "asked_unobserved"},
		{"ask without channel", Action{Phase: "decision", Verdict: "ask", EffectBoundary: "hook_execution", EffectRelation: "before"}, false, false, ""},
		{"best effort", Action{Phase: "decision", Verdict: "warn", EffectBoundary: "upstream_send", EffectRelation: "unknown"}, false, false, "allowed_effect_unrecorded"},
		{"required intent absent", Action{Phase: "decision", Verdict: "allow", EffectBoundary: "upstream_send", EffectRelation: "before"}, false, true, ""},
		{"attempt absent", Action{Phase: "intent", Verdict: "allow", EffectBoundary: "upstream_send", EffectRelation: "before"}, false, true, ""},
		{"non-releasing intent", Action{Phase: "intent", Verdict: "defer", EffectBoundary: "upstream_send", EffectRelation: "before", Attempt: &one}, false, true, ""},
		{"standalone successful block", Action{Phase: "outcome", Verdict: "block", EffectBoundary: "upstream_send", EffectRelation: "after", Attempt: &one, OutcomeClass: "completed"}, true, true, ""},
		{"success after gap without effect", Action{Phase: "outcome", Verdict: "allow", EffectBoundary: "none", EffectRelation: "after", Attempt: &one, OutcomeClass: "completed"}, true, true, ""},
		{"resolution after gap", Action{Phase: "resolution", Verdict: "block", EffectBoundary: "approval_prompt", EffectRelation: "unknown", Hold: &Hold{ID: "example", Correction: &correction}}, true, true, "blocked"},
		{"wrong resolution boundary", Action{Phase: "resolution", Verdict: "block", EffectBoundary: "upstream_send", EffectRelation: "after", Hold: &Hold{ID: "example"}}, true, true, ""},
		{"correction on hold", Action{Phase: "hold", Verdict: "defer", EffectBoundary: "approval_prompt", EffectRelation: "before", Hold: &Hold{ID: "example", Correction: &correction}}, false, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := AppraisePiece([]Action{tc.action}, []bool{tc.required}, tc.unknown)
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("got %q %t, want %q", got, ok, tc.want)
			}
		})
	}
	if _, ok := AppraisePiece(nil, nil, false); ok {
		t.Fatal("appraised empty piece")
	}
}

func TestAppraisalRejectsHoldCollisionsAndInvalidShapes(t *testing.T) {
	base := Action{
		ActionID: "example", ActionType: "write", Actor: "example", Principal: "example",
		Caller: Caller{Authn: "none"}, Data: Data{Reversibility: "unknown", SideEffectClass: "unknown"},
		EffectBoundary: "approval_prompt", EffectRelation: "before",
		Phase: "hold", Policy: ActionPolicy{Source: "unavailable"},
		Target: "api.vendor.example", Transport: "mcp", Verdict: "defer", Hold: &Hold{ID: "example", Policy: "example"},
	}
	other := base
	other.ActionID = "different"
	incorrect := base
	attempt := int64(1)
	incorrect.Attempt = &attempt
	for _, tc := range []struct {
		name    string
		actions []Action
	}{
		{"hold identity", []Action{base, other}},
		{"unexpected attempt", []Action{incorrect}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
			for _, action := range tc.actions {
				root.add(kindAction, action)
			}
			root.close()
			opts := Options{Keys: []ed25519.PublicKey{root.public()}, DiskIndex: true}
			result, err := VerifyPaths(t.Context(), []string{root.write(t.TempDir())}, opts)
			if err != nil || result.Verdict != "INVALID" || !hasFinding(result, codeDecisionInconsistent) {
				t.Fatalf("expected fail-closed decision result: %+v, %v", result, err)
			}
		})
	}
}

func TestMemoryDecisionIndexScopesShapesAndHoldOwnership(t *testing.T) {
	index := decisionIndex{}
	if err := index.reset(); err != nil {
		t.Fatal(err)
	}
	const hold, action, other = "hold", "first", "second"
	if err := index.rememberBadShape(1, action); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		segment int
		action  string
		bad     bool
	}{
		{1, action, true},
		{2, action, false},
		{1, other, false},
	} {
		got, err := index.badShape(tc.segment, tc.action)
		if err != nil || got != tc.bad {
			t.Fatalf("segment %d, %s: bad shape = %t, %v", tc.segment, tc.action, got, err)
		}
	}
	for _, claim := range []string{action, other} {
		if owner, err := index.holdOwner(hold, claim); err != nil || owner != action {
			t.Fatalf("hold ownership changed after claim by %q: owner %q, %v", claim, owner, err)
		}
	}
	if err := index.reset(); err != nil {
		t.Fatal(err)
	}
	if bad, err := index.badShape(1, action); err != nil || bad {
		t.Fatalf("malformed shape leaked across histories: %t, %v", bad, err)
	}
	if owner, err := index.holdOwner(hold, other); err != nil || owner != other {
		t.Fatalf("hold ownership leaked across histories: %q, %v", owner, err)
	}
}

func TestPendingHoldReplayRetainsOnlyIdentity(t *testing.T) {
	hold := strings.Repeat("hold-", 16384)
	pending := Action{Phase: "hold", Hold: &Hold{ID: hold}}
	matching := Action{Phase: "resolution", Verdict: "allow", Hold: &Hold{ID: hold}}
	different := Action{Phase: "resolution", Verdict: "allow", Hold: &Hold{ID: "other"}}
	var piece, inferred decisionPiece
	if !piece.advance(pending, false) || len(piece.HoldID) >= 100 {
		t.Fatal("pending hold did not use a fixed-size identity")
	}
	if piece.advance(different, false) || !piece.advance(matching, false) {
		t.Fatal("hold identity did not distinguish resolutions")
	}
	if !inferred.advance(matching, true) || inferred.HoldID != piece.HoldID {
		t.Fatal("inferred hold used a different identity")
	}
}
