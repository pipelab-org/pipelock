// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

func gluedTestPattern(t *testing.T, s *Scanner, name string) *compiledPattern {
	t.Helper()
	for _, p := range s.dlpPatterns {
		if p.name == name {
			return p
		}
	}
	t.Fatalf("pattern %q not compiled", name)
	return nil
}

// fullWindowLeftBoundary is candidateHasLeftBoundary without the provider
// window bound: the regex reads the whole candidate.
func fullWindowLeftBoundary(p *compiledPattern, source string, loc [2]int) bool {
	windowStart := loc[0]
	if windowStart > 0 {
		_, size := utf8.DecodeLastRuneInString(source[:windowStart])
		windowStart -= size
	}
	window := source[windowStart:loc[1]]
	for _, m := range p.re.FindAllStringIndex(window, -1) {
		body := p.withoutLeftBoundary.FindStringIndex(window[m[0]:m[1]])
		if body != nil && windowStart+m[0]+body[0] == loc[0] {
			return true
		}
	}
	return false
}

// The bounded left-boundary window gives the same answer as reading the whole
// candidate, for every provider candidate, including prefixes spelled with
// case-folded runes wider than one byte (U+017F long s, U+212A Kelvin sign).
func TestProviderLeftBoundaryWindowMatchesFullCandidate(t *testing.T) {
	s := gluedBoundaryScanner(t)
	suffixes := []string{
		strings.Repeat("Q", 25),
		"api03-" + strings.Repeat("Ab9_", 30),
		strings.Repeat("sk-ant-Q", 12),
		strings.Repeat("K", 30),
	}
	leads := []string{"", " ", "x", "-", "_", "xx", "é", "ſ", "x-", "!x"}
	for _, name := range []string{"Anthropic API Key", "OpenAI API Key", "OpenAI Service Key"} {
		p := gluedTestPattern(t, s, name)
		if p.providerPrefixRE == nil {
			t.Fatalf("%s has no provider prefix", name)
		}
		prefixes := []string{p.providerKeyPrefix, strings.ToUpper(p.providerKeyPrefix), strings.Replace(p.providerKeyPrefix, "s", "ſ", 1), strings.Replace(p.providerKeyPrefix, "k", "K", 1)}
		checked := 0
		for _, lead := range leads {
			for _, prefix := range prefixes {
				for _, suffix := range suffixes {
					text := lead + prefix + suffix + " " + lead + prefix + suffix
					for _, loc := range p.providerCandidateSpans(text) {
						checked++
						if got, want := p.candidateHasLeftBoundary(text, loc), fullWindowLeftBoundary(p, text, loc); got != want {
							t.Fatalf("%s %q at %v: bounded=%v full=%v", name, text, loc, got, want)
						}
					}
				}
			}
		}
		if checked == 0 {
			t.Fatalf("%s: no candidates checked", name)
		}
	}
}

func gluedSearchAllocBytes(p *compiledPattern, text string) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	p.earliestGluedSpan(text, len(text)+1)
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// One glued rune before a long run of nested provider prefixes used to cost
// work proportional to the run for every nested prefix: quadratic in the
// input. Doubling the input must roughly double the work, measured here as
// allocated bytes, which unlike wall time does not depend on machine load.
func TestGluedProviderNestedPrefixWorkIsLinear(t *testing.T) {
	s := gluedBoundaryScanner(t)
	p := gluedTestPattern(t, s, "Anthropic API Key")
	small := "x" + strings.Repeat("sk-ant-Q", 2000)
	large := "x" + strings.Repeat("sk-ant-Q", 4000)
	if start, _, ok := p.earliestGluedSpan(large, len(large)+1); ok {
		t.Fatalf("digitless nested run reported a key at %d", start)
	}
	a, b := gluedSearchAllocBytes(p, small), gluedSearchAllocBytes(p, large)
	if a == 0 {
		t.Fatal("no allocation measured")
	}
	if ratio := float64(b) / float64(a); ratio > 3 {
		t.Fatalf("doubling the nested run multiplied glued search allocation by %.1f (%d -> %d bytes)", ratio, a, b)
	}
}

func TestUniformGlueDecodeEdges(t *testing.T) {
	if uniformGlueTextAdmitted("") {
		t.Fatal("empty run admitted")
	}
	if !isGlueControlPad(-1) {
		t.Fatal("invalid rune is not padding")
	}
	if isGlueControlPad('A') || !isGlueControlPad(0) || !isGlueControlPad(utf8.RuneError) {
		t.Fatal("pad classification wrong")
	}
	// Too few digits for a run, and digits that never form one.
	if got := uniformByteGlueRuns("1x2"); got != nil {
		t.Fatalf("short input produced runs: %v", got)
	}
	if text, ranges := decodeUniformByteGlue("1x2", true); text != "" || ranges != nil {
		t.Fatalf("short input decoded: %q %v", text, ranges)
	}
	noRun := "999999999 888888888"
	if got := uniformByteGlueRuns(noRun); len(got) != 0 {
		t.Fatalf("out-of-range fields produced runs: %v", got)
	}
	if text, _ := decodeUniformByteGlue(noRun, false); text != "" {
		t.Fatalf("out-of-range fields decoded: %q", text)
	}
	// Two separate runs decode on separate lines, with a gap range between.
	first, second := decimalByteList("ABCDEFGH", "x"), decimalByteList("IJKLMNOP", ".")
	text, ranges := decodeUniformByteGlue(first+" and "+second, true)
	if text != "ABCDEFGH\nIJKLMNOP" {
		t.Fatalf("two runs decoded as %q", text)
	}
	if len(ranges) != len(text) || ranges[8] != (encodingSourceRange{}) {
		t.Fatalf("separator range missing: %d ranges for %d bytes", len(ranges), len(text))
	}
	if runs := uniformByteGlueRuns(first + " and " + second); len(runs) != 2 {
		t.Fatalf("want 2 runs, got %d", len(runs))
	}
}

func TestGluedCandidateConfirmedInSourceEdges(t *testing.T) {
	s := gluedBoundaryScanner(t)
	p := gluedTestPattern(t, s, "Social Security Number")
	ssn := "123" + "-45-" + "6789"
	if p.gluedCandidateConfirmedInSource(ssn, "") {
		t.Fatal("empty candidate confirmed")
	}
	if p.gluedCandidateConfirmedInSource("12", ssn) {
		t.Fatal("candidate longer than source confirmed")
	}
	if p.gluedCandidateConfirmedInSource("no number here", ssn) {
		t.Fatal("absent candidate confirmed")
	}
	if !p.gluedCandidateConfirmedInSource("id x"+ssn+" on file", ssn) {
		t.Fatal("letter-glued candidate not confirmed")
	}
	// A digit glued in front lengthens the number, and two glued letters
	// are a word, so neither occurrence confirms; the search moves past both.
	if p.gluedCandidateConfirmedInSource("9"+ssn+" xy"+ssn, ssn) {
		t.Fatal("digit-glued or two-letter candidate confirmed")
	}
}

// The card and SSN glued search is skipped on text with no ASCII letter or
// underscore. That skip is exact: on such text the glued search itself never
// finds a candidate, whatever sits before the number.
func TestGluedNumberSearchNeedsASCIIGlueLetter(t *testing.T) {
	s := gluedBoundaryScanner(t)
	card := strings.Join([]string{"4111", "1111", "1111", "1111"}, " ")
	ssn := "123" + "-45-" + "6789"
	leads := []string{"", "9", "0", "-", ".", " ", "é", "ß", "K", "а", " ", "#", "+", "/", "\t", "21"}
	for _, name := range []string{"Credit Card Number", "Social Security Number"} {
		p := gluedTestPattern(t, s, name)
		if !p.gluedDigitExtendsNumber {
			t.Fatalf("%s does not reject a glued digit", name)
		}
		for _, number := range []string{card, ssn, strings.ReplaceAll(card, " ", ""), strings.ReplaceAll(ssn, "-", "")} {
			for _, lead := range leads {
				text := strings.Repeat("21", 40) + " " + lead + number + " " + lead + number
				if hasASCIIGlueLetter(text) {
					t.Fatalf("fixture has a glue letter: %q", text)
				}
				if start, _, ok := p.earliestGluedSpan(text, len(text)+1); ok {
					t.Fatalf("%s: glued search found %q in letterless text", name, text[start:])
				}
			}
		}
		// With a glue letter the search runs and finds the candidate.
		glued := "id x" + ssn
		if name == "Credit Card Number" {
			glued = "id x" + card
		}
		if !hasASCIIGlueLetter(glued) {
			t.Fatal("glue letter not detected")
		}
		if _, _, ok := p.firstBoundaryOrGluedSpan(glued); !ok {
			t.Fatalf("%s: letter-glued candidate missed in %q", name, glued)
		}
	}
	for _, c := range []string{"A", "z", "_", "Q"} {
		if !hasASCIIGlueLetter("12" + c) {
			t.Fatalf("%q is a glue letter", c)
		}
	}
	for _, c := range []string{"@", "[", "`", "{", "é", "\x80", "\xff"} {
		if hasASCIIGlueLetter("12" + c) {
			t.Fatalf("%q is not a glue letter", c)
		}
	}
}
