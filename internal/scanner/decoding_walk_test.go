// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestOutboundDecodePauseKeepsPrefix(t *testing.T) {
	plain := strings.Repeat("!", minKnownSecretSubstringLen) + "?"
	encoded := base64.RawStdEncoding.EncodeToString([]byte(plain))
	for _, credit := range []int{0, 1} {
		t.Run(fmt.Sprint(credit), func(t *testing.T) {
			prefix := make([]decodedResult, maxDecodeCandidates)
			seen := newDecodeSeen(encoded)
			for i := range prefix {
				prefix[i] = decodedResult{text: fmt.Sprintf("prior view %04d", i), encoding: encodingURL}
				seen.add(prefix[i].text)
			}
			state := newOutboundDecodeState(prefix, []string{encoded}, seen, outboundDecodeOptions{includeURL: true, minPrefix: minKnownSecretSubstringLen})
			out, complete, paused := state.run()
			if complete || !paused || len(out) != len(prefix) {
				t.Fatal("walk did not pause at the candidate stop")
			}
			// Other phases finish before the first walk resumes. Their output
			// stays ahead of every appended first-walk view.
			secondary := decodedResult{text: "prior secondary phase", encoding: encodingHTML}
			prefix = append(prefix, secondary)
			seen.add(secondary.text)
			out, complete = state.resume(prefix, credit)
			if complete != (credit == 1) || len(out) != len(prefix)+credit {
				t.Fatal("resume did not honor the transferred slots", complete, len(out))
			}
			for i := range prefix {
				if out[i] != prefix[i] {
					t.Fatalf("prefix changed at %d", i)
				}
			}
			if credit == 1 && (out[len(prefix)].text != plain || out[len(prefix)].encoding != encodingBase64) {
				t.Fatal("continuation lost its pending sibling")
			}
		})
	}
}

func TestOutboundDecodeResumeKeepsByteStop(t *testing.T) {
	encoded := base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("!", minKnownSecretSubstringLen) + "?"))
	state := newOutboundDecodeState(nil, []string{encoded}, newDecodeSeen(encoded), outboundDecodeOptions{minPrefix: minKnownSecretSubstringLen})
	state.freeRoots = 0 // a recursive parent, already past the free transport root
	state.consumed = maxDecodeTotalBytes
	if out, complete, paused := state.run(); complete || paused || len(out) != 0 {
		t.Fatal("byte exhaustion must not become a candidate pause")
	}
	if out, complete := state.resume(nil, maxDecodeCandidates); complete || len(out) != 0 || state.consumed != maxDecodeTotalBytes {
		t.Fatal("resumption replenished the recursive byte allowance")
	}
}

func TestResumedDecodeNeedsClosedPhases(t *testing.T) {
	seen := newDecodeSeen("root")
	if resumedDecodePhasesClosed([]decodedResult{{text: "&amp;", encoding: encodingBase64}}, seen) {
		t.Fatal("new HTML work was treated as completed")
	}
	seen.add("&")
	if !resumedDecodePhasesClosed([]decodedResult{{text: "&amp;", encoding: encodingBase64}}, seen) {
		t.Fatal("already inspected HTML view was not recognized")
	}
	if resumedDecodePhasesClosed([]decodedResult{{text: "new tag view", encoding: encodingUnicodeTags}}, seen) {
		t.Fatal("new tag work was treated as completed")
	}
}

func TestKnownDecodeCreditAndIncompleteIsolation(t *testing.T) {
	encoded := base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("!", minKnownSecretSubstringLen) + "?"))
	for _, tc := range []struct {
		name                string
		base, credit        int
		inbound, incomplete bool
	}{
		{name: "unused", credit: maxDecodeCandidates},
		{name: "one", base: maxDecodeCandidates - 1, credit: 1},
		{name: "spent", base: maxDecodeCandidates},
		{name: "other phases", base: maxDecodeCandidates + 1},
		{name: "inbound", inbound: true},
		{name: "prior incomplete", incomplete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memo := &decodingMemo{inbound: tc.inbound, incomplete: tc.incomplete}
			memo.decodeKnownSecretWithBase(encoded, minKnownSecretSubstringLen, make([]decodedResult, tc.base))
			if memo.incomplete != tc.incomplete {
				t.Fatal("credit changed an earlier completeness result")
			}
			for key := range memo.views {
				if key.knownCredit != tc.credit {
					t.Fatalf("credit=%d want=%d", key.knownCredit, tc.credit)
				}
			}
		})
	}
}

func TestOrdinaryDecodeKeepsScratchLocal(t *testing.T) {
	text := strings.Repeat("!", 64)
	for _, inbound := range []bool{false, true} {
		t.Run(fmt.Sprint(inbound), func(t *testing.T) {
			allocs := testing.AllocsPerRun(1, func() {
				views, complete := decodeEncodingsForScan(text, true, 0, decodeBudgetMode{inbound: inbound}, nil)
				if !complete || len(views) != 0 {
					t.Fatal("ordinary text did not finish without decoded views")
				}
			})
			// One existing decoder allocation remains; continuation bookkeeping adds none.
			if allocs > 1 {
				t.Fatalf("ordinary decoder scratch escaped: %g allocations", allocs)
			}
		})
	}
}
