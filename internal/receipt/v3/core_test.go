// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestDecisionPolicyAfterReload(t *testing.T) {
	for _, tc := range []struct {
		name     string
		captured string
		want     ActionPolicy
	}{
		{"missing", "", ActionPolicy{Source: "unavailable"}},
		{"present", Digest([]byte("old")), ActionPolicy{Source: "request_snapshot", Hash: Digest([]byte("old"))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var current atomic.Pointer[string]
			before, after := Digest([]byte("old")), Digest([]byte("new"))
			current.Store(&before)
			captured := tc.captured
			if captured != "" {
				captured = *current.Load()
			}
			snapshot := CapturePolicy(captured)
			current.Store(&after)
			actual := snapshot.ActionPolicy()
			serialized, err := json.Marshal(Action{Policy: actual})
			if err != nil {
				t.Fatal(err)
			}
			if actual != tc.want || bytes.Contains(serialized, []byte(*current.Load())) {
				t.Fatalf("got %+v, want %+v", actual, tc.want)
			}
		})
	}
}

func TestWycheproofEd25519(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "v3", "wycheproof", "ed25519.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Vectors []struct {
			ID        int      `json:"tcId"`
			Public    string   `json:"public_key"`
			Message   string   `json:"msg"`
			Signature string   `json:"sig"`
			Result    string   `json:"result"`
			Flags     []string `json:"flags"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Vectors) == 0 {
		t.Fatal("no signature cases")
	}
	for _, row := range document.Vectors {
		t.Run(strconv.Itoa(row.ID), func(t *testing.T) {
			a, errA := hex.DecodeString(row.Public)
			m, errM := hex.DecodeString(row.Message)
			sig, errS := hex.DecodeString(row.Signature)
			if errA != nil || errM != nil || errS != nil || len(sig) != 64 {
				t.Fatalf("bad source vector: %v %v %v", errA, errM, errS)
			}
			code := verifyEd25519(m, validateKey(a), sig, "")
			torsion := slices.Contains(row.Flags, "SmallOrderPublicKey") || slices.Contains(row.Flags, "MixedOrderPublicKey")
			if torsion && code != codeSignatureKey {
				t.Fatalf("wanted key rejection, got %q (suite result %s)", code, row.Result)
			}
			if (code == "") != (row.Result == "valid" && !torsion) {
				t.Fatalf("suite result %s, profile finding %q", row.Result, code)
			}
		})
	}
}

func TestDecisionWorkBound(t *testing.T) {
	t.Run("wire maximum after gap", func(t *testing.T) {
		number := int64(maxInteger)
		action := Action{
			Phase: "outcome", Verdict: "allow", EffectBoundary: "upstream_send",
			EffectRelation: "after", OutcomeClass: "completed", Attempt: &number,
		}
		start := time.Now()
		state, ok := AppraisePiece([]Action{action}, []bool{true}, true)
		if !ok || state != "completed" || time.Since(start) > time.Second {
			t.Fatalf("result %s %t, duration %s", state, ok, time.Since(start))
		}
	})
	t.Run("repeat resolutions", func(t *testing.T) {
		var piece decisionPiece
		hold := &Hold{ID: "approval"}
		if !piece.advance(Action{Phase: "hold", Hold: hold}, false) {
			t.Fatal("could not start hold")
		}
		block := Action{Phase: "resolution", Verdict: "block", Hold: hold}
		if !piece.advance(block, false) {
			t.Fatal("could not block hold")
		}
		want := piece
		for i := range 100_000 {
			if !piece.advance(block, false) || piece != want {
				t.Fatal(fmt.Errorf("state grew or changed after %d repeated blocks", i))
			}
		}
	})
}
