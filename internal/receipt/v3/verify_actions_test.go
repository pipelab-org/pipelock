// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net/http"
	"runtime"
	"testing"
)

func TestVerifyPathsWithActions(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("receipt v3 writer fixtures require Linux directory locking")
	}
	dir := t.TempDir()
	seed := sha256.Sum256([]byte("verify-actions-test-key"))
	key := ed25519.NewKeyFromSeed(seed[:])
	pub := key.Public().(ed25519.PublicKey)
	policyHash := Digest([]byte("policy"))
	w, err := OpenStreamWriter(t.Context(), StreamWriterOptions{
		Dir: dir, SigningKey: key,
		Coverage: Coverage{
			Surfaces: []string{"forward"}, ReceiptsRequired: true,
			RedactionRuleset: Ruleset{Hash: Digest([]byte("rules")), ID: "example", Version: "1"},
		},
		Identity: Writer{Product: "example", Version: "1", Instance: "test"}, PolicyHash: policyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	action := Action{
		ActionID: "a-1", Phase: "decision", Verdict: "block",
		EffectBoundary: "upstream_send", EffectRelation: "not_attempted",
		Actor: "agent", Principal: "local", Caller: Caller{Authn: "none"},
		Transport: "forward", Target: "http://api.vendor.example/", Method: http.MethodGet,
		ActionType: "read", Data: Data{SideEffectClass: "none", Reversibility: "not_applicable"},
	}
	if err := w.WriteAction(t.Context(), action, CapturePolicy(policyHash)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}

	opts := Options{Directory: true, Keys: []ed25519.PublicKey{pub}}
	// Nil visitor on a VALID stream with actions must not panic.
	res, err := VerifyPathsWithActions(t.Context(), []string{dir}, opts, nil)
	if err != nil || res.Verdict != "VALID" {
		t.Fatalf("nil visitor: verdict=%s err=%v", res.Verdict, err)
	}

	// Valid visitor sees exactly the verified action.
	var seen []string
	res, err = VerifyPathsWithActions(t.Context(), []string{dir}, opts, func(a Action) error {
		seen = append(seen, a.ActionID)
		return nil
	})
	if err != nil || res.Verdict != "VALID" || len(seen) != 1 || seen[0] != "a-1" {
		t.Fatalf("visitor: verdict=%s seen=%v err=%v", res.Verdict, seen, err)
	}

	// Visitor error is propagated.
	stopErr := errors.New("stop")
	if _, err := VerifyPathsWithActions(t.Context(), []string{dir}, opts, func(Action) error { return stopErr }); !errors.Is(err, stopErr) {
		t.Fatalf("visitor error: %v", err)
	}

	// Non-VALID verdict never invokes visitor.
	called := false
	res, err = VerifyPathsWithActions(t.Context(), []string{dir}, Options{Directory: true, AllowUnpinned: true}, func(Action) error {
		called = true
		return nil
	})
	if err != nil || res.Verdict == "VALID" || called {
		t.Fatalf("non-VALID invoked visitor=%t verdict=%s err=%v", called, res.Verdict, err)
	}
}
