// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordsFailedProjectionCached(t *testing.T) {
	gate, err := (config.DLPPattern{Name: keywordPattern, Regex: `[0-9]{16}`, Keywords: []string{"account"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	logical := "reference " + strings.Repeat(keywordNumber+" ", 200)
	view := compactTextDLPWhitespace(logical)
	// Escape decoding has no projection from the original literal percent text.
	source := "%72eference " + strings.Repeat(keywordNumber+" ", 200)
	graph := newKeywordDecodeSources(source)
	node := graph.add(source, logical, encodingURL)
	memo := &decodingMemo{keywordBudget: graph.budget}
	ctx := keywordCandidateContext{alternatives: []*keywordDecodeSource{node}, source: source, memo: memo}
	for _, hit := range regexp.MustCompile(`[0-9]{16}`).FindAllStringIndex(view, -1) {
		if ctx.matches(gate, view, hit[0], hit[1]) {
			t.Fatal("unlabeled candidate qualified")
		}
	}
	if memo.inspectionIncomplete() || graph.budget.incomplete {
		t.Fatalf("repeated failed projections exhausted budget: %+v", graph.budget)
	}
}
