// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math/rand"
	"reflect"
	"regexp/syntax"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDLPPreFilterCompiledPrefixParity(t *testing.T) {
	sc := MustNew(testConfig())
	t.Cleanup(sc.Close)
	for _, patterns := range [][]*compiledPattern{sc.dlpPatterns, sc.core.dlpPatterns, nil} {
		pf := newDLPPreFilter(patterns)
		prefixes := make(map[string][]int)
		var alwaysRun []int
		for i, pattern := range patterns {
			anchors := extractRequiredLiteralAnchors(pattern.re.String())
			if len(anchors) == 0 {
				alwaysRun = append(alwaysRun, i)
			}
			for _, anchor := range anchors {
				lower := strings.ToLower(anchor)
				prefixes[lower] = append(prefixes[lower], i)
			}
		}
		inputs := []string{"", "ordinary first body", "different second body", "\xff\x00", "ÜNİCODE"}
		var joined strings.Builder
		for prefix := range prefixes {
			inputs = append(inputs, "before "+prefix+" after", strings.ToUpper(prefix), prefix+prefix)
			joined.WriteString(prefix)
			joined.WriteByte(' ')
		}
		inputs = append(inputs, joined.String(), "ordinary first body")
		for _, input := range inputs {
			var want []int
			lower := strings.ToLower(input)
			for prefix, indices := range prefixes {
				if strings.Contains(lower, prefix) {
					want = append(want, indices...)
				}
			}
			want = append(want, alwaysRun...)
			sort.Ints(want)
			if len(want) > 0 {
				unique := want[:1]
				for _, index := range want[1:] {
					if index != unique[len(unique)-1] {
						unique = append(unique, index)
					}
				}
				want = unique
			}
			// Text shorter than every pattern's shortest match cannot match any
			// of them (see TestDecodedLengthAdmission), so length admission
			// declines it before the prefix search.
			if pf.minimumRunes > 0 && utf8.RuneCountInString(input) < pf.minimumRunes {
				want = nil
			}
			if got := pf.patternsToCheck(input); !reflect.DeepEqual(got, want) {
				t.Fatalf("candidate order differs for %q: got %v, want %v", input, got, want)
			}
		}
	}
}

// The prefilter's byte filters read strings.ToLower's output without building
// it. Inputs whose lowering changes bytes or length must still find every
// prefix the lowered text contains.
func TestDLPPreFilterLoweringParity(t *testing.T) {
	sc := MustNew(testConfig())
	t.Cleanup(sc.Close)
	pf := newDLPPreFilter(sc.dlpPatterns)
	reference := func(input string) []int {
		lower := strings.ToLower(input)
		var hits []int
		for _, prefix := range pf.prefixes {
			if strings.Contains(lower, prefix.text) {
				hits = append(hits, prefix.indices...)
			}
		}
		return hits
	}
	var inputs []string
	for _, prefix := range pf.prefixes {
		upper := strings.ToUpper(prefix.text)
		inputs = append(inputs,
			upper, "\xff"+upper, upper+"\xff", "K"+upper, "xİ"+upper,
			strings.ReplaceAll(upper, "K", "K"), strings.ReplaceAll(upper, "I", "İ"),
			"ÀÉ"+prefix.text+"ÕÜ", "\xc3"+prefix.text, prefix.text[:len(prefix.text)/2]+"\xff"+prefix.text[len(prefix.text)/2:],
		)
	}
	for _, input := range inputs {
		if got, want := pf.candidates(input), reference(input); !reflect.DeepEqual(got, want) {
			t.Fatalf("candidates(%q) = %v, want %v", input, got, want)
		}
	}
}

// The shared shape summary may only skip a gate that would itself reject.
func TestDLPShapeSummaryOnlySkipsRejectedGates(t *testing.T) {
	sc := MustNew(testConfig())
	t.Cleanup(sc.Close)
	rnd := rand.New(rand.NewSource(17)) // #nosec G404 -- deterministic property corpus.
	var corpus []string
	alphabet := []byte("aZ09-_.=:/+ \x00\xff\xc3\xa9\xe2\x84\xaa\xc5\xbf")
	for range 4000 {
		b := make([]byte, rnd.Intn(80))
		for i := range b {
			b[i] = alphabet[rnd.Intn(len(alphabet))]
		}
		corpus = append(corpus, string(b))
	}
	for _, pf := range []*dlpPreFilter{sc.dlpPreFilter, sc.core.dlpPreFilter} {
		for _, r := range pf.shapeBypass {
			corpus = append(corpus, "x"+string(r)+"y", strings.Repeat("a", 3)+string(r))
		}
	}
	gated := 0
	for _, patterns := range [][]*compiledPattern{sc.dlpPatterns, sc.core.dlpPatterns} {
		pf := newDLPPreFilter(patterns)
		for _, p := range patterns {
			if p.shapeGate == nil {
				continue
			}
			gated++
			tree, err := syntax.Parse(p.re.String(), syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			texts := corpus
			for range 40 {
				texts = append(texts, genMatch(tree.Simplify(), rnd, 0))
			}
			for _, text := range texts {
				var summary dlpShapeSummary
				if pf.shapeRejects(p.shapeGate, text, &summary) && p.shapeGate.admits(text) {
					t.Fatalf("%s: summary skipped a text its gate admits: %q", p.name, text)
				}
			}
		}
	}
	if gated == 0 {
		t.Fatal("no shape-gated patterns exercised")
	}
}

func TestMatchDLPPatternsNormalizedShapeSkipParity(t *testing.T) {
	sc := MustNew(testConfig())
	t.Cleanup(sc.Close)
	reference := func(text string) []TextDLPMatch {
		var names []TextDLPMatch
		for _, idx := range sc.dlpPreFilter.patternsToCheck(text) {
			p := sc.dlpPatterns[idx]
			if start, end, ok := p.matchSpanInView(text, text); ok {
				names = append(names, TextDLPMatch{PatternName: p.name, span: MatchSpan{ByteStart: start, ByteEnd: end}})
			}
		}
		return names
	}
	rnd := rand.New(rand.NewSource(23)) // #nosec G404 -- deterministic property corpus.
	var texts []string
	for _, p := range sc.dlpPatterns {
		tree, err := syntax.Parse(p.re.String(), syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		for range 10 {
			texts = append(texts, genMatch(tree.Simplify(), rnd, 0), "\xff"+genMatch(tree.Simplify(), rnd, 0)+" tail")
		}
	}
	for _, text := range texts {
		got := sc.matchDLPPatternsNormalized(text, "", text)
		want := reference(text)
		if len(got) != len(want) {
			t.Fatalf("%q: %d matches, reference %d", text, len(got), len(want))
		}
		for i := range got {
			if got[i].PatternName != want[i].PatternName || got[i].span.ByteStart != want[i].span.ByteStart || got[i].span.ByteEnd != want[i].span.ByteEnd {
				t.Fatalf("%q: match %d differs: %s %d-%d vs %s %d-%d", text, i, got[i].PatternName, got[i].span.ByteStart, got[i].span.ByteEnd, want[i].PatternName, want[i].span.ByteStart, want[i].span.ByteEnd)
			}
		}
	}
}
