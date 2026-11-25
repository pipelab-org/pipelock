// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package carddlp

import (
	"strings"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// VisitText folds Unicode card spellings and returns spans in the original
// text, for consumers that must replace bytes rather than report view offsets.
// Digit folding is rune-local; removed marks and invisible runes between the
// first and last digit remain inside the returned original span.
func VisitText(text string, yield func(Candidate) bool) bool {
	return visitMappedText(text, visitTextView, yield)
}

// VisitTextWithKey retains ordinary redaction spans and adds candidates
// corroborated by the enclosing JSON member name.
func VisitTextWithKey(text, key string, yield func(Candidate) bool) bool {
	if VisitText(text, yield) {
		return true
	}
	if !CorroboratedKey(key) {
		return false
	}
	return visitMappedText(text, func(view string, next func(Candidate) bool) bool {
		return visit(view, candidateView{strictSeparators: true}, next)
	}, yield)
}

func visitMappedText(text string, visitView func(string, func(Candidate) bool) bool, yield func(Candidate) bool) bool {
	if normalize.ForCardText(text) == text {
		return visitView(text, yield)
	}
	var view strings.Builder
	var starts, ends []int
	for at := 0; at < len(text); {
		_, size := utf8.DecodeRuneInString(text[at:])
		folded := normalize.ForCardText(text[at : at+size])
		view.WriteString(folded)
		for range len(folded) {
			starts = append(starts, at)
			ends = append(ends, at+size)
		}
		at += size
	}
	return visitView(view.String(), func(c Candidate) bool {
		c.Start, c.End = starts[c.Start], ends[c.End-1]
		return yield(c)
	})
}
