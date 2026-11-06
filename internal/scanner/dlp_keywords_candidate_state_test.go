// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordsEarlierCandidateIncomplete(t *testing.T) {
	gate, err := (config.DLPPattern{Name: keywordPattern, Regex: `[0-9]{16}`, Keywords: []string{"account"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	text := keywordNumber + strings.Repeat(" ", 70) + "account " + keywordNumber
	root := hex.EncodeToString([]byte(text))
	graph := newKeywordDecodeSources(root)
	node := graph.add(root, text, encodingHex)
	graph.budget.used = maxDecodeTotalBytes
	memo := &decodingMemo{keywordMode: true, keywordUnit: root, keywordBudget: graph.budget, keywordSources: map[string][]*keywordDecodeSource{text: {node}}}
	pattern := compiledPattern{re: regexp.MustCompile(`[0-9]{16}`), keywords: gate, warn: true}
	if _, _, ok := pattern.matchSpanWithDecodes(text, text, memo); !ok {
		t.Fatal("later decoded keyword did not qualify")
	}
	if !memo.inspectionIncomplete() {
		t.Fatal("later accepted candidate cleared earlier incomplete inspection")
	}
}
