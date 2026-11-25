// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
)

func TestCardAtomOwningKeys(t *testing.T) {
	raw := json.RawMessage(`{"card":["first",{"pan":"nested"},["later"],true,null],"other":"tail","amount":123,"empty":[],"value":"unlabelled"}`)
	result := AllStringsFromJSONResult(raw)
	if result.Truncated {
		t.Fatal("unexpected truncation")
	}
	expected := map[string]string{"first": "card", "nested": "pan", "later": "card", "true": "card", "null": "card", "tail": "other", "123": "amount", "unlabelled": "value"}
	for _, atom := range result.Atoms {
		if atom.Key {
			if atom.ContextKey != "" {
				t.Fatal("member name inherited value context")
			}
			continue
		}
		want, ok := expected[atom.Text]
		if !ok || atom.ContextKey != want {
			t.Fatalf("atom %q key=%q want=%q", atom.Text, atom.ContextKey, want)
		}
		delete(expected, atom.Text)
	}
	if len(expected) != 0 {
		t.Fatalf("missing atoms: %v", expected)
	}
}

func TestKeyedCardRunBoundaries(t *testing.T) {
	pan := cardtest.Issuer("453912341234123", 16)
	raw := json.RawMessage(`{"card":[` + pan[:4] + `,` + pan[4:8] + `,` + pan[8:12] + `,` + pan[12:] + `]}`)
	atoms := AllStringsFromJSONResult(raw).Atoms
	if !VisitKeyedCardRuns(atoms, func(key string, run jsonnumber.CardRun) bool {
		return key == "card" && run.Digits == pan && run.NumberOnly
	}) {
		t.Fatal("key lost across numeric run")
	}
	count := 0
	if VisitKeyedCardRuns(atoms, func(string, jsonnumber.CardRun) bool { count++; return false }) || count == 0 {
		t.Fatal("visitor did not continue")
	}
	if VisitKeyedCardRuns(nil, func(string, jsonnumber.CardRun) bool { return true }) {
		t.Fatal("empty atoms produced a run")
	}
}
