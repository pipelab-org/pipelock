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
