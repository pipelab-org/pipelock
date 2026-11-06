// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
)

// FuzzQuotedPrintableTextRuns checks that run recovery never panics and only
// yields source ranges inside the input, whatever escapes surround a run.
func FuzzQuotedPrintableTextRuns(f *testing.F) {
	for _, seed := range []string{
		"=41" + strings.Repeat("A", 20),
		"\x01" + strings.Repeat("A", 20) + "=4",
		strings.Repeat("A", 20) + "=ZZ\x01" + strings.Repeat("B", 20),
		"=41=ZZ\x01" + strings.Repeat("C", 30) + "\x02",
		"=E2=80" + strings.Repeat("D", 25) + "=\n\x03" + strings.Repeat("E", 25),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		decoded, _ := decodeQuotedPrintable(source, false)
		visitQuotedPrintableTextRuns(source, decoded, func(text string, bounds encodingSourceRange) bool {
			if bounds.start < 0 || bounds.end > len(source) || bounds.start > bounds.end {
				t.Fatalf("run %q has source range %+v outside %d bytes", text, bounds, len(source))
			}
			return true
		})
	})
}

// A soft break that precedes a literal run must not mark that run decoded:
// the run is plain source text and needs no separate view.
func TestQuotedPrintableSoftBreakBeforeLiteralRun(t *testing.T) {
	input := "=EF=BF=\n=BD\x01" + strings.Repeat("a", 16) + strings.Repeat("\x01", 10) + "=GG"
	decoded, _ := decodeQuotedPrintable(input, false)
	visitQuotedPrintableTextRuns(input, decoded, func(text string, bounds encodingSourceRange) bool {
		t.Fatalf("literal run yielded as decoded view: %q %+v", text, bounds)
		return false
	})
	_ = textEncodingViewsMode(input, true)
	_ = appendTextEncodingViews(nil, input)
}
