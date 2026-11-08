// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordHTMLPresence(t *testing.T) {
	sc := keywordScanner(t, []string{"lookup"}, 50)
	t.Cleanup(sc.Close)
	// Exercise the ordinary decoder independently of terminal production.
	sc.reassemblyPlan = nil
	body := "&lt;p&gt;" + hex.EncodeToString([]byte(strings.Repeat(keywordNumber, 1000))) + "&lt;/p&gt;"
	result := sc.ScanTextForDLP(t.Context(), body)
	if !result.Clean || len(result.Matches) != 0 {
		t.Fatalf("unlabeled HTML-decoded record: %+v", result.Matches)
	}
	body = "&lt;p&gt;" + hex.EncodeToString([]byte("lookup "+keywordNumber)) + "&lt;/p&gt;"
	result = sc.ScanTextForDLP(t.Context(), body)
	if !keywordFound(result) || HasInspectionLimit(result.Matches) {
		t.Fatalf("labeled HTML-decoded record: %+v", result.Matches)
	}
}

func TestDLPKeywordHTMLSeparatedPresence(t *testing.T) {
	sc := keywordScanner(t, []string{"lookup"}, 50)
	t.Cleanup(sc.Close)
	sc.reassemblyPlan = nil
	encoded := hex.EncodeToString([]byte(strings.Repeat("x", 6000) + keywordNumber))
	var value strings.Builder
	for i := 0; i < len(encoded); i += 40 {
		if i > 0 {
			value.WriteByte('!')
		}
		value.WriteString(encoded[i:min(i+40, len(encoded))])
	}
	body := "&lt;p&gt; " + value.String() + " &amp;"
	result := sc.ScanTextForDLP(t.Context(), body)
	if !result.Clean || len(result.Matches) != 0 {
		t.Fatalf("unlabeled HTML-wrapped value: %+v", result.Matches)
	}
	result = sc.ScanTextForDLP(t.Context(), body+" lookup")
	if !keywordFound(result) || HasInspectionLimit(result.Matches) {
		t.Fatalf("labeled HTML-wrapped value: %+v", result.Matches)
	}
}

func TestDLPKeywordSourceOccurrenceReuse(t *testing.T) {
	for _, tc := range []struct {
		name, source, root string
		want               []int
	}{
		{name: "identity", source: "record", root: "record", want: []int{0}},
		{name: "overlapping", source: "aaaa", root: "aa", want: []int{0, 1, 2}},
		{name: "distinct", source: "x record y record", root: "record", want: []int{2, 11}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sources := newKeywordDecodeSources(tc.source)
			// Stop discovery on the first occurrence, then resume for a later
			// candidate. A cached early success must not hide another window.
			if !sources.visitOccurrences(tc.source, tc.root, func(at int) bool { return at == tc.want[0] }) {
				t.Fatal("first occurrence missing")
			}
			var got []int
			sources.visitOccurrences(tc.source, tc.root, func(at int) bool { got = append(got, at); return false })
			if !slices.Equal(got, tc.want) {
				t.Fatalf("positions %v, want %v", got, tc.want)
			}
			used := sources.budget.used
			for range 10 {
				sources.visitOccurrences(tc.source, tc.root, func(int) bool { return false })
			}
			if sources.budget.used-used != 10*len(tc.want)*keywordSpanBytes {
				t.Fatal("source search was repeated")
			}
		})
	}
}

func TestDLPKeywordPresenceNormalization(t *testing.T) {
	// Mark removal leaves a Cyrillic base letter; the next normalization
	// pass would map it to ASCII. Presence must use the main keyword unit.
	label := "\u0401xx"
	once := config.DLPKeywordContext(label)
	if once == config.DLPKeywordContext(once) {
		t.Fatal("fixture did not change on a second pass")
	}
	gate, err := (config.DLPPattern{Name: keywordPattern, Regex: `[0-9]{16}`, Keywords: []string{"exx"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	context := keywordCandidateContext{source: once}
	if !context.keywordPossible(gate, once, false) {
		t.Fatal("raw source presence was treated as an already normalized lane")
	}
	sc := keywordScanner(t, []string{label}, 50)
	t.Cleanup(sc.Close)
	result := sc.ScanTextForDLP(t.Context(), label+" "+keywordNumber)
	if !keywordFound(result) {
		t.Fatalf("keyword unit normalized twice: %+v", result.Matches)
	}
}
