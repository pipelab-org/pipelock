// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMatchingViewWhitespacePositions(t *testing.T) {
	padding := strings.Repeat("~", regexpWindowMinText)
	needles := []string{"aba", "ba", "marker", "é", "ſ", "K", "�"}
	program := newMatchingLiterals(needles)
	for _, tc := range []struct {
		name, input string
		delta       bool
	}{
		{"overlap and seam", "ababa aBA mark er", true},
		{"adjacent multibyte spaces", " ab\u2003\u00a0a MARKER\u2003éſK� ", true},
		{"same bytes at different offsets", "  marker marker marker", true},
		{"malformed byte", "mark\xef er", false},
		{"dense edits", strings.Repeat("a b ", matchingMaxEdits), false},
		{"dense occurrences", strings.Repeat("ababa", matchingMaxHits) + "x y", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := padding + tc.input + padding
			parent := newMatchingView(source, program)
			text, offsets, delta := (*decodingMemo)(nil).compactWhitespaceWithView(source, parent)
			wantText, wantOffsets := compactTextDLPWhitespaceWithOffsets(source)
			if text != wantText || !slices.Equal(offsets, wantOffsets) || (delta != nil) != tc.delta {
				t.Fatal("compaction or edit proof differs")
			}
			full := newMatchingView(text, program)
			for _, needle := range needles {
				got, complete := delta.positions(needle)
				want, fullComplete := full.positions(needle)
				if delta != nil && complete != fullComplete {
					t.Fatalf("literal %q completion %v, full index %v", needle, complete, fullComplete)
				}
				if complete && !slices.Equal(got, want) {
					t.Fatalf("literal %q positions %v, full index %v", needle, got, want)
				}
				if !fullComplete {
					continue
				}
				var exact []int
				for i := 0; i+len(needle) <= len(text); i++ {
					if windowLiteralEqual(text[i:], needle) {
						exact = append(exact, i)
					}
				}
				if !slices.Equal(want, exact) {
					t.Fatalf("literal %q positions %v, direct match %v", needle, want, exact)
				}
			}
		})
	}
}

func TestMatchingViewRegexpParity(t *testing.T) {
	padding := strings.Repeat("~", regexpWindowMinText)
	for _, tc := range []struct {
		name, expression, input string
	}{
		{"overlap and priority", `(?i)aba(?:[0-9]{1,2}|[0-9]{3})`, "aba12~aba123~ab a124"},
		{"Unicode simple fold", `(?i)skate[0-9]{2}`, "ſKa\u2003TE42~sKate23"},
		{"word boundary", `\bmarker[0-9]{2}\b`, "x marker12~ mark er34"},
		{"absolute end", `marker[0-9]{2}\z`, padding + "mar ker12"},
		{"empty match", `(?:marker)?`, "mark er12"},
		{"no literal", `[a-z]{3}[0-9]{2}`, "ab c12"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			re := regexp.MustCompile(tc.expression)
			plan := analyzeCompiledRegexpMatchRequirements(re).windows
			var parent *matchingView
			source := padding + tc.input
			if plan != nil {
				parent = newMatchingView(source, newMatchingLiterals(plan.anchors))
			}
			text, _, delta := (*decodingMemo)(nil).compactWhitespaceWithView(source, parent)
			got := plan.findAllWithPositions(re, re, text, text, delta)
			if want := re.FindAllStringIndex(text, -1); !reflect.DeepEqual(got, want) {
				t.Fatalf("spans differ: got %v, want %v", got, want)
			}
		})
	}
}

func TestMatchingViewDLPParity(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns,
		config.DLPPattern{Name: "Catalog marker", Regex: `\bmarker[0-9]{2}\b`, Severity: config.SeverityHigh},
		config.DLPPattern{Name: "Catalog sample", Regex: `\bsample[0-9]{2}\b`, Severity: config.SeverityHigh, Action: config.ActionWarn},
	)
	sc, reference := MustNew(cfg), MustNew(cfg)
	t.Cleanup(sc.Close)
	t.Cleanup(reference.Close)
	reference.dlpMatchingLiterals = nil
	if sc.dlpMatchingLiterals == nil {
		t.Fatal("fixture has no compiled literal program")
	}
	padding := strings.Repeat("~", regexpWindowMinText)
	for _, tc := range []struct {
		name, input string
	}{
		{"raw and joined", "sample42~mar ker12"},
		{"same labels through transforms", "marker42~sample%31%32~sam ple15"},
		{"normalization and Unicode spaces", "ＭＡＲ\u2003ＫＥＲ14~sample13"},
		{"same bytes from separate positions", "sam\u2003ple41~sam ple41"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := padding + tc.input + padding
			for _, inbound := range []bool{false, true} {
				scan, baseline := sc.ScanTextForDLPQuiet, reference.ScanTextForDLPQuiet
				if inbound {
					scan, baseline = sc.ScanTextForDLPInbound, reference.ScanTextForDLPInbound
				}
				if got, want := scan(t.Context(), text), baseline(t.Context(), text); !reflect.DeepEqual(got, want) {
					t.Fatalf("inbound=%v: findings, ordering or spans differ: got %+v, want %+v", inbound, got, want)
				}
			}
		})
	}
}

func TestMatchingViewReuseWindowAndTransformIdentity(t *testing.T) {
	padding := strings.Repeat("~", regexpWindowMinText)
	source := "prefix " + padding + "marker42"
	program := newMatchingLiterals([]string{"marker"})
	root := newMatchingView(source, program)
	joined := root.transformed(matchingURL, "prefix"+padding+"marker42")
	if joined == nil {
		t.Fatal("fixture needs a proved child")
	}
	other := root.transformed(matchingHTML, joined.text)
	if other == nil || joined == other || root.transformed(matchingURL, joined.text) != joined {
		t.Fatal("identity must follow the parent and transform")
	}
	if root.transformed(matchingURL, padding+"marker41") != nil {
		t.Fatal("an unexpected output must use ordinary matching")
	}
	re := regexp.MustCompile(`marker[0-9]{2}$`)
	sourceWindow := regexpWindowRange{len(source) - 9, len(source)}
	childWindow := regexpWindowRange{sourceWindow.start - 1, sourceWindow.end - 1}
	srcMatches := root.windowMatches(re, source, sourceWindow)
	got := joined.windowMatches(re, joined.text, childWindow)
	if want := re.FindAllStringIndex(joined.text, -1); !reflect.DeepEqual(got, want) {
		t.Fatalf("shifted hits = %v, want %v", got, want)
	}
	if len(joined.windows) != 0 {
		t.Fatal("unchanged guarded window was searched again")
	}
	got[0][0] = 0
	if again := joined.windowMatches(re, joined.text, childWindow); again[0][0] != srcMatches[0][0]-1 {
		t.Fatal("changing returned coordinates mutated cached coordinates")
	}
	edited := root.transformed(matchingLeet, source[:len(source)-1]+"3")
	if _, ok := edited.sourcePosition(sourceWindow); ok {
		t.Fatal("window overlapping a replacement was reused")
	}
}

func TestMatchingViewSegmentWalkParity(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		exceeded   bool
	}{
		{"ordered fragments", strings.Repeat("z", regexpWindowMinText) + " / one#two#one / line| 123", false},
		{"malformed bytes", strings.Repeat("z", regexpWindowMinText) + " / foo\xffbar#baz", false},
		{"too many tokens", strings.Repeat("word ", matchingMaxSegments+1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := newMatchingView(tc.text, newMatchingLiterals([]string{"word"}))
			collect := func(walk func(string, func(string, int) bool), limit int) []textByteSpan {
				var spans []textByteSpan
				walk(tc.text, func(value string, start int) bool {
					spans = append(spans, textByteSpan{start, start + len(value)})
					return limit < 0 || len(spans) < limit
				})
				return spans
			}
			if got, want := collect(view.walkSegments, 1), collect(walkTextDLPSegments, 1); !slices.Equal(got, want) || view.segmentsReady {
				t.Fatal("an early stop was treated as a completed walk")
			}
			want := collect(walkTextDLPSegments, -1)
			for _, limit := range []int{len(want) + 1, 1, len(want) + 1} {
				if got := collect(view.walkSegments, limit); !slices.Equal(got, want[:min(limit, len(want))]) {
					t.Fatal("cached token order or offsets differ")
				}
			}
			if view.segmentsExceeded != tc.exceeded || view.segmentsReady == tc.exceeded {
				t.Fatal("unexpected token retention result")
			}
		})
	}
}

func TestMatchingViewResponseParity(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns,
		config.ResponseScanPattern{Name: "Case-sensitive catalog marker", Regex: `CATALOG marker[0-9]{2}`},
		config.ResponseScanPattern{Name: "Folded catalog mark", Regex: `(?i)catalog (?:mark[0-9]{2}|entry)`},
	)
	sc, reference := MustNew(cfg), MustNew(cfg)
	t.Cleanup(sc.Close)
	t.Cleanup(reference.Close)
	reference.responseMatchingLiterals = nil
	if sc.responseMatchingLiterals == nil {
		t.Fatal("fixture has no compiled response literal program")
	}
	padding := strings.Repeat("~", responseMemoMinBytes)
	probe := newMatchingView(padding, sc.responseMatchingLiterals)
	if _, ok := probe.positions("CATALOG marker"); !ok {
		t.Fatal("fixture did not exercise the bounded literal index")
	}
	for _, tc := range []struct {
		name, input string
		clean       bool
	}{
		{"case-sensitive hit", "CATALOG marker12", false},
		{"case-sensitive miss", "catalog marker12", true},
		{"folded hit", "cATalOg MARK12", false},
		{"invisible spaced", "catalog\u200bmark12", false},
		{"sparse substitution", "catal0g entry", false},
		{"non-ASCII", "日本語 Kſ catalog MARK12", false},
		{"malformed byte", "\xff catalog MARK12", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := padding + tc.input + padding
			got := sc.ScanResponse(t.Context(), text)
			want := reference.ScanResponse(t.Context(), text)
			if got.Clean != tc.clean || !reflect.DeepEqual(got, want) {
				t.Fatalf("got clean=%t findings=%v, reference clean=%t findings=%v", got.Clean, got.Matches, want.Clean, want.Matches)
			}
		})
	}
}

func TestMatchingViewDecoderClassParity(t *testing.T) {
	for _, tc := range []struct {
		name, text string
	}{
		{"empty", ""},
		{"separator only", "~.=\r\n"},
		{"one data symbol", " ~A== "},
		{"hex", "636174616c6f67"},
		{"separator hex", "0x63:0x61:0x74"},
		{"base32", "MNQXI"},
		{"base32hex lowercase", "cdgn8"},
		{"base64 padded", "Y2F0YWxvZw=="},
		{"raw base64", "Y2F0YWxvZw"},
		{"not all alphabets", "~_q "},
		{"incomplete UTF-8 and carrier", "\xef\xbb⤵Y2F0 "},
		{"text encoding independent of class", `\u0043\u0061\u0074`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, prefix := range []int{0, 1, 4} {
				got := decodeEncodingsModeInto(nil, tc.text, prefix)
				want := decodeEncodingsByClass(nil, tc.text, prefix, decoderAll)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("prefix=%d: got %v, want %v", prefix, got, want)
				}
			}
		})
	}
}

func FuzzMatchingViewDeltaParity(f *testing.F) {
	f.Add("mark er12", "marker12")
	f.Add("ababaſKate14", "ab baſKate14")
	f.Add("x marker34\n", "marker34\n")
	f.Add("a\xffcb", "aébb")
	re := regexp.MustCompile(`(?i)\b(?:marker|skate|ababa)[0-9]{2}\b`)
	plan := analyzeCompiledRegexpMatchRequirements(re).windows
	program := newMatchingLiterals(plan.anchors)
	padding := strings.Repeat("~", regexpWindowMinText)
	f.Fuzz(func(t *testing.T, before, after string) {
		if len(before)+len(after) > 512 {
			t.Skip()
		}
		source, text := padding+before+padding, padding+after+padding
		parent := newMatchingView(source, program)
		view := parent.deriveText(text)
		plan.findAllWithPositions(re, re, source, source, parent)
		got := plan.findAllWithPositions(re, re, text, text, view)
		if want := re.FindAllStringIndex(text, -1); !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}
