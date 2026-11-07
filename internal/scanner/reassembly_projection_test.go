// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"strings"
	"testing"
)

func TestReassemblyAlphabetUnion(t *testing.T) {
	// RFC 4648 sections 4-8: hex and both base32 alphabets are subsets of
	// the union of standard and URL-safe base64, including ASCII case variants.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_"
	for value := range 256 {
		if got, want := reassemblyAlphabet[value], strings.ContainsRune(alphabet, rune(value)); got != want {
			t.Fatalf("byte %02x: %v != %v", value, got, want)
		}
	}
	// Punctuation and invalid UTF-8 must neither advance nor alter a projection.
	all := string([]byte{0, 0xff}) + "a!B@c#D$0%1^2&3*4(5)6=7:8;9"
	plain := "aBcD0123456789"
	if assembledFingerprint(all) != assembledFingerprint(plain) {
		t.Fatal("non-alphabet bytes changed a projection")
	}
}

func TestReassemblyProjectionRetention(t *testing.T) {
	memo := &decodingMemo{reassemblyPlan: reassemblyTestPlan(t), reassemblyDeferred: true}
	defer memo.releaseProjection()
	for index := range maxDecodeCandidates + 2 {
		memo.reassemblyObserveView(fmt.Sprintf("record-%016x", index), assembledInputView)
		skip := memo.assembledSkip(index)
		if memo.assembledProjectionEntries > maxDecodeCandidates || len(memo.assembledProjectionTable) > 2*maxDecodeCandidates {
			t.Fatal("projection index exceeded its existing bound")
		}
		if index > maxDecodeCandidates && skip != 0 {
			t.Fatal("full reuse index suppressed inspection")
		}
	}
	if memo.incomplete || memo.assembledProjectionEntries != maxDecodeCandidates {
		t.Fatal("reuse retention changed scan completeness or missed its bound")
	}
	held := memo.assembledProjectionTable
	memo.releaseProjection()
	if memo.assembledProjectionStorage != nil || memo.assembledProjectionTable != nil {
		t.Fatal("projection pool owner retained")
	}
	for _, entry := range held {
		if entry.ready {
			t.Fatal("pooled projection state was not cleared")
		}
	}
}

func TestReassemblyProjectionInvalidIdentity(t *testing.T) {
	memo := &decodingMemo{reassemblyPlan: reassemblyTestPlan(t), reassemblyDeferred: true}
	defer memo.releaseProjection()
	memo.reassemblyObserveView("record-abcdef012345", assembledInputView)
	if memo.assembledSkip(0) != 0 {
		t.Fatal("first view skipped")
	}
	memo.assembledProjectionFirst[0].view = -1
	memo.reassemblyObserveView("record-abcdef012345!", assembledInputView)
	if memo.assembledSkip(1) != 31 || !memo.inspectionIncomplete() {
		t.Fatal("invalid retained identity did not fail closed")
	}
	other := &decodingMemo{}
	if other.assembledSkip(-1) != 31 || !other.inspectionIncomplete() {
		t.Fatal("invalid view index did not fail closed")
	}
}
