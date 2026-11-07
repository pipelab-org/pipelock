// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestReassemblyDistinctSourceContext(t *testing.T) {
	sc := keywordScanner(t, []string{"~~~"}, 10)
	defer sc.Close()
	body := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 5000) + keywordNumber)))
	for _, tc := range []struct{ qualified, decoder bool }{{false, false}, {true, false}, {true, true}} {
		qualified := tc.qualified
		t.Run(fmt.Sprintf("qualified=%v/decoder=%v", qualified, tc.decoder), func(t *testing.T) {
			first := body + strings.Repeat("!", 20)
			second := body + "!!!"
			if qualified {
				second = body + "~~~"
			}
			source := first + strings.Repeat("!", 100) + second
			memo := &decodingMemo{keywordMode: true, keywordInput: source, keywordUnit: source, reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true}
			defer memo.releaseProjection()
			// Occupy the first fingerprint slot so this also exercises table reuse.
			memo.reassemblyObserve(strings.Repeat("ab!", 600))
			memo.reassemblyObserve(first)
			kind := assembledInputView
			if tc.decoder {
				kind = assembledDecoderView
			}
			memo.reassemblyObserveView(second, kind)
			result := finishAssembled(TextDLPResult{Clean: true}, memo)
			if keywordFound(result) != (qualified && !tc.decoder) || HasInspectionLimit(result.Matches) {
				t.Fatalf("distinct source context: qualified=%v result=%+v", qualified, result)
			}
			t.Logf("qualified=%v clean=%v finding=%v refusal=%v", qualified, result.Clean, keywordFound(result), HasInspectionLimit(result.Matches))
		})
	}
}

func TestReassemblyKeywordReuseBudget(t *testing.T) {
	sc := keywordScanner(t, []string{"~~~"}, 10)
	defer sc.Close()
	body := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 5000) + keywordNumber)))
	first, second := body+strings.Repeat("!", 20), body+"~~~"
	for _, inbound := range []bool{false, true} {
		for _, replay := range []bool{false, true} {
			t.Run(fmt.Sprintf("inbound=%v/replay=%v", inbound, replay), func(t *testing.T) {
				source := first + strings.Repeat("!", 100) + second
				m := &decodingMemo{keywordMode: true, keywordInput: source, keywordUnit: source, reassemblyPlan: sc.reassemblyPlan, reassemblyInbound: inbound, inbound: inbound}
				defer m.releaseProjection()
				if replay {
					m.reassemblyObserve(first)
				}
				m.keywordBudgetForScan().used = maxDecodeTotalBytes
				if replay {
					m.reassemblyObserve(second)
				} else {
					m.reassemblyObserve(first)
				}
				r := finishAssembled(TextDLPResult{Clean: true}, m)
				if r.Clean != inbound || HasInspectionLimit(r.Matches) == inbound {
					t.Fatalf("keyword reuse exhaustion direction: %+v", r)
				}
				if inbound && (len(r.Matches) != 1 || r.Matches[0].PatternName != PartialEncodedContentPattern) {
					t.Fatalf("partial evidence lost: %+v", r)
				}
			})
		}
	}
}
