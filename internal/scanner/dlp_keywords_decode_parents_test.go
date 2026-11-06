// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordsDecodeCacheNewParent(t *testing.T) {
	value := "identifier_" + keywordNumber
	encoded := hex.EncodeToString([]byte(value))
	source := encoded[:20] + "\x00" + encoded[20:]
	memo := &decodingMemo{keywordMode: true, keywordUnit: "account " + source}
	first := memo.decode(encoded, true)
	if len(first) == 0 {
		t.Fatal("decode control yielded no views")
	}
	memo.registerKeywordTransform(source, encoded, "projection")
	second := memo.decode(encoded, true)
	gate, err := (config.DLPPattern{Name: keywordPattern, Regex: `identifier_[0-9]{16}`, Keywords: []string{"account"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	pattern := compiledPattern{re: regexp.MustCompile(`identifier_[0-9]{16}`), keywords: gate}
	if _, _, ok := pattern.matchSpanWithDecodes(value, value, memo); !ok || memo.inspectionIncomplete() {
		t.Fatalf("cached view lost new parent: matched=%v incomplete=%v views=%d/%d", ok, memo.inspectionIncomplete(), len(first), len(second))
	}
}
