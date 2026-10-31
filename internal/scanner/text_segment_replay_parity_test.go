// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// The text_segment directive claims isTextDLPEncodingDelimiter. Every
// published profile must split on exactly the same runes, or a recipe would
// replay a different segment than the scanner inspected.
func TestTextSegmentDelimiterMatchesReplay(t *testing.T) {
	for _, digest := range []string{
		normalize.EvidenceProvenanceProfileV1Digest,
		normalize.EvidenceProvenanceProfileV2Digest,
		normalize.EvidenceProvenanceProfileV3Digest,
		normalize.EvidenceProvenanceProfileV4Digest,
		normalize.EvidenceProvenanceProfileV5Digest,
	} {
		recipe := normalize.Recipe{
			TransformProfileDigest: digest,
			Operations:             []normalize.Operation{{Kind: normalize.OperationTextSegment}},
		}
		delimiters := 0
		for r := rune(0); r <= 0x3000; r++ {
			if !utf8.ValidRune(r) {
				continue
			}
			got, err := recipe.Apply("a" + string(r) + "b")
			if err != nil {
				t.Fatalf("profile %s rune %U: %v", digest, r, err)
			}
			if replaySplits := got == "a"; replaySplits != isTextDLPEncodingDelimiter(r) {
				t.Fatalf("profile %s rune %U: replay splits=%t, scanner splits=%t", digest, r, replaySplits, isTextDLPEncodingDelimiter(r))
			}
			if got == "a" {
				delimiters++
			}
		}
		if delimiters == 0 {
			t.Fatalf("profile %s: no delimiters found; parity check is vacuous", digest)
		}
	}
}

// textDLPSegments adds a '#' split after text_segment. Its segments must equal
// one split on both delimiter sets, which is what every caller inspected
// before the fragment step was separated from the replayed transform.
func TestTextDLPSegmentsEqualsCombinedSplit(t *testing.T) {
	combined := func(r rune) bool { return isTextDLPEncodingDelimiter(r) || r == '#' }
	const alphabet = "ab#/?& =:\n,"
	r := &knownValueTestRNG{state: 11}
	withFragment := 0
	for range 20000 {
		b := make([]byte, r.IntN(24))
		for i := range b {
			b[i] = alphabet[r.IntN(len(alphabet))]
		}
		text := string(b)
		got := textDLPSegments(text)
		want := strings.FieldsFunc(text, combined)
		if len(got) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got, want)) {
			t.Fatalf("%q: got %q want %q", text, got, want)
		}
		if strings.Contains(text, "#") {
			withFragment++
		}
	}
	if withFragment == 0 {
		t.Fatal("corpus never exercised the fragment split")
	}
}
