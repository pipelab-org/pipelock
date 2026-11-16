// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// sessionReceiptEntries returns the run's action receipt entries in order.
func sessionReceiptEntries(t *testing.T, run testRun) []recorder.Entry {
	t.Helper()
	files, err := recorderFiles(run.rec.Dir(), run.session)
	if err != nil {
		t.Fatal(err)
	}
	var out []recorder.Entry
	for _, file := range files {
		entries, err := recorder.ReadEntries(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Type == recorderEntryType {
				out = append(out, entry)
			}
		}
	}
	return out
}

// linkAfter returns next as the recorder entry directly after prev, so the
// recorder's own hash chain holds and only the receipt chain can object.
// A non-nil r replaces the entry's receipt.
func linkAfter(t *testing.T, prev, next recorder.Entry, r *Receipt) recorder.Entry {
	t.Helper()
	if r != nil {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		next.Detail, next.RawDetail = json.RawMessage(raw), raw
	}
	next.Sequence, next.PrevHash = prev.Sequence+1, prev.Hash
	next.Hash = recorder.ComputeHash(next)
	return next
}

func TestTailChainStateRefusesBrokenReceiptChain(t *testing.T) {
	_, priv := generateTestKey(t)
	run := startRun(t, t.TempDir(), priv)
	run.openAndEmit(t, 3)
	keys := []string{run.e.SignerKeyHex()}
	entries := sessionReceiptEntries(t, run)
	if len(entries) < 3 {
		t.Fatalf("want at least 3 receipts, got %d", len(entries))
	}
	first, second, third := entries[0], entries[1], entries[2]

	r, err := receiptFromEntry(second)
	if err != nil {
		t.Fatal(err)
	}
	// Correctly linked to the first receipt by hash, signed by the run's key,
	// but numbered as if a receipt were missing in between.
	skipped := r.ActionRecord
	skipped.ChainSeq++
	resigned, err := Sign(skipped, priv)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		next recorder.Entry
		want string
	}{
		{name: "linked", next: linkAfter(t, first, second, nil)},
		{name: "receipt missing", next: linkAfter(t, first, third, nil), want: "receipt hash link mismatch"},
		{name: "sequence skipped", next: linkAfter(t, first, second, &resigned), want: "receipt sequence mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var state tailChainState
			if err := state.advance(first, run.session, keys); err != nil {
				t.Fatal(err)
			}
			err := state.advance(tc.next, run.session, keys)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("intact chain refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("advance = %v, want %q", err, tc.want)
			}
		})
	}
}
