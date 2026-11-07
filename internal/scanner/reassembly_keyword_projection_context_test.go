// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestReassemblyKeywordProjectionContext(t *testing.T) {
	sc := keywordScanner(t, []string{"~~~"}, 10)
	defer sc.Close()
	body := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 5000) + "3333333333333333")))
	first := body + strings.Repeat("!", 20)
	second := body + "~~~"
	source := first + strings.Repeat("!", 100) + second
	memo := &decodingMemo{keywordMode: true, keywordInput: source, keywordUnit: source, reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true}
	defer memo.releaseProjection()
	memo.reassemblyObserve(first)
	memo.reassemblyObserve(second)
	result := finishAssembled(TextDLPResult{Clean: true}, memo)
	if !keywordFound(result) || HasInspectionLimit(result.Matches) {
		t.Fatalf("projection lost qualified context: %+v", result)
	}
}
