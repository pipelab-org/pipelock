// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"testing"
)

func testDecisionIndexFinding(t *testing.T) {
	ctx := t.Context()
	store, err := newStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	tx, err := store.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	a := appraisal{
		index:       decisionIndex{ctx: ctx, tx: tx, maxIDs: 1},
		fullHistory: true,
	}
	verification := verification{ctx: ctx, store: store}
	if err := a.index.reset(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"first", "first", "second"} {
		if err := a.index.remember(id, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := verification.appraiseHistory(&a, nil, &verifiedStream{}); err != nil {
		t.Fatal(err)
	}
	if !hasFinding(verification.result, codeDecisionIndexFull) || a.fullHistory || len(a.index.ids) != 1 {
		t.Fatalf("limit not enforced: %+v, %+v", a.index, verification.result.Findings)
	}
}

func TestDecisionIndexRejectsUnusableTransaction(t *testing.T) {
	ctx := t.Context()
	store, err := newStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	tx, err := store.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	index := &decisionIndex{ctx: ctx, tx: tx, disk: true}
	for _, tc := range []struct {
		name  string
		check func() error
	}{
		{"reset", index.reset},
		{"remember", func() error { return index.remember("decision", true) }},
		{"opaque", func() error { _, err := index.opaque("decision"); return err }},
		{"begin", index.beginSegment},
		{"get", func() error { _, err := index.get("decision"); return err }},
		{"put", func() error { return index.put("decision", pieceEntry{}) }},
		{"each", func() error { return index.eachPiece(func(pieceEntry) {}) }},
		{"shape", func() error { _, err := index.badShape(0, "decision"); return err }},
		{"hold", func() error { _, err := index.holdOwner("hold", "decision"); return err }},
		{"walk", func() error {
			return walkRecords(ctx, tx, "stream", maxInteger, func(stagedRecord) error { return nil })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check(); !errors.Is(err, sql.ErrTxDone) {
				t.Fatalf("want closed transaction error, got %v", err)
			}
		})
	}
	if _, err := decodePiece([]byte("[")); err == nil {
		t.Fatal("accepted corrupt decision state")
	}
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
		{"unexpected attempt", []Action{incorrect, incorrect}},
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
