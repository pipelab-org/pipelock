// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordsOfflineWhitespace(t *testing.T) {
	gate, err := (config.DLPPattern{Name: keywordPattern, Regex: `[0-9]{16}`, Keywords: []string{"account"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	for _, distance := range []int{1, 100} {
		text := "account" + strings.Repeat("\u00a0", distance) + keywordNumber
		if got := ContextualPatternMatches(text, regexp.MustCompile(`[0-9]{16}`), nil, false, false, gate); got != (distance == 1) {
			t.Fatalf("distance=%d finding=%v", distance, got)
		}
	}
}
