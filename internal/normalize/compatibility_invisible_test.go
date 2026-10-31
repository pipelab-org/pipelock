// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

func TestCompatibilityFoldedInvisibles(t *testing.T) {
	// Derive the cases from the pinned Unicode normalization data and the
	// repository's InvisibleRanges contract, including unchanged invisibles.
	var cases []rune
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		for _, folded := range norm.NFKC.String(string(r)) {
			if unicode.Is(InvisibleRanges, folded) {
				cases = append(cases, r)
				break
			}
		}
	}
	if len(cases) == 0 {
		t.Fatal("Unicode normalization produced no invisible cases")
	}
	foundHalfwidth := false
	for _, r := range cases {
		foundHalfwidth = foundHalfwidth || r == '\uFFA0'
		t.Run(fmt.Sprintf("U+%04X", r), func(t *testing.T) {
			for _, pipeline := range []struct {
				name string
				run  func(string) string
			}{
				{"matching", ForMatching},
				{"matching_decomposed", decomposedMatchingFull},
				{"dlp", ForDLP},
				{"policy", ForPolicy},
				{"tool_text", ForToolText},
				{"tool_text_spaced", ForToolTextSpaced},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					// A compatibility character must behave like its folded form.
					input := string(r)
					want := pipeline.run(norm.NFKC.String(input))
					if got := pipeline.run(input); got != want {
						t.Fatalf("folded character: got %q, want %q", got, want)
					}
					got := pipeline.run("a" + input + "z")
					if strings.ContainsFunc(got, func(r rune) bool { return unicode.Is(InvisibleRanges, r) }) {
						t.Fatalf("invisible survived compatibility folding: %q", got)
					}
					if want := "a" + want + "z"; got != want {
						t.Fatalf("surrounding text: got %q, want %q", got, want)
					}
				})
			}
		})
	}
	if !foundHalfwidth {
		t.Fatal("Unicode-derived cases omitted U+FFA0")
	}
	t.Logf("checked %d code points using Unicode %s", len(cases), norm.Version)
}

func TestCompatibilityFoldedInvisibleInterleaving(t *testing.T) {
	const plain = "normalization witness"
	input := strings.Join(strings.Split(plain, ""), "\uFFA0")
	for _, pipeline := range []struct {
		name string
		run  func(string) string
	}{
		{"matching", ForMatching},
		{"dlp", ForDLP},
		{"tool_text", ForToolText},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			if got := pipeline.run(input); got != plain {
				t.Fatalf("got %q, want %q", got, plain)
			}
		})
	}
	for _, pipeline := range []struct {
		name string
		run  func(string) string
	}{
		{"policy", ForPolicy},
		{"tool_text_spaced", ForToolTextSpaced},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			if got := pipeline.run("normalization\uFFA0witness"); got != plain {
				t.Fatalf("got %q, want %q", got, plain)
			}
		})
	}
}

// Published transform-profile JSON pins the order used by receipt replay.
func TestCompatibilityFoldedInvisibleProfileReplay(t *testing.T) {
	for _, digest := range []string{
		EvidenceProvenanceProfileV1Digest,
		EvidenceProvenanceProfileV2Digest,
		EvidenceProvenanceProfileV3Digest,
		EvidenceProvenanceProfileV4Digest,
		EvidenceProvenanceProfileV5Digest,
	} {
		t.Run(digest, func(t *testing.T) {
			for _, op := range []Operation{
				{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1"},
				{Kind: OperationMatchingNormalize, Profile: "pipelock-matching-v1"},
			} {
				recipe := Recipe{TransformProfileDigest: digest, Operations: []Operation{op}}
				got, err := recipe.Apply("a\uFFA0z")
				if err != nil || got != "a\u1160z" {
					t.Fatalf("%s replay = %q, %v; want published output", op.Kind, got, err)
				}
			}
		})
	}
}
