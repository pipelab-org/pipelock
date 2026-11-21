// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"reflect"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestRegexpWindowFindAllParity(t *testing.T) {
	const line = "~~~ Build status: all unit jobs passed. ~~~\n"
	padding := strings.Repeat(line, 50)
	for _, tc := range []struct {
		name, expression, text string
	}{
		{"leftmost first", `(?i)marker(?:[0-9]{1,3}|[0-9]{4})`, padding + "MARKER1234 marker4567" + padding},
		{"lazy repetition", `marker[0-9]+?`, padding + "marker1234 marker4567" + padding},
		{"greedy repetition", `marker[0-9]+`, padding + "marker1234 marker4567" + padding},
		{"folded anchor", `(?i)skate[0-9]{2}`, padding + "ſKaTE42  sKate23" + padding},
		{"malformed rune", `\x{FFFD}(?:marker|sample)[0-9]{2}`, padding + "\xffmarker12 \xfesample34" + padding},
		{"word and line context", `(?im)^\bmarker[0-9]{2}\b$`, padding + "MARKER12\n[marker13]\nmarker14x\n" + padding},
		{"absolute context", `\Afirst[0-9]{2}|last[0-9]{2}\z`, "first12\n" + padding + "first13\nlast14\n" + padding + "last15"},
		{"spaces and wild bytes", `(?i)\bmarker\s+.{1,2}result\b`, padding + "MARKER \t  !éresult" + padding + "marker\n\n*result" + padding},
		{"repeated whitespace groups", `(?:a\s+){9}marker[0-9]{2}`, padding + strings.Repeat("a \t ", 9) + "marker12" + padding},
		{"interleaved core and hop whitespace", `marker\s+ result[0-9]{2}`, padding + "marker" + strings.Repeat(" \t", 12) + " result12" + padding},
		{"pure core runs", `\b[0-9]{6}\b`, padding + "123456 234567 345678x" + padding},
		{"no anchors in text", `marker[0-9]{2}`, padding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			re := regexp.MustCompile(tc.expression)
			plan := analyzeCompiledRegexpMatchRequirements(re).windows
			if plan == nil {
				t.Fatal("fixture has no positional plan")
			}
			ranges, ok := plan.ranges(tc.text)
			if !ok {
				t.Fatal("fixture unexpectedly used whole-input fallback")
			}
			var covered int
			for i, candidate := range ranges {
				if i > 0 && ranges[i-1].end > candidate.start {
					t.Fatal("planned ranges overlap")
				}
				covered += candidate.end - candidate.start
			}
			if covered >= len(tc.text)/2 {
				t.Fatalf("planned to search %d of %d bytes", covered, len(tc.text))
			}
			if got, want := plan.findAll(re, tc.text), re.FindAllStringIndex(tc.text, -1); !reflect.DeepEqual(got, want) {
				t.Fatalf("spans differ: got %v, want %v", got, want)
			}
		})
	}
}

func TestRegexpWindowWholeInputFallback(t *testing.T) {
	for _, tc := range []struct {
		name, expression, text string
		hasPlan                bool
	}{
		{"empty match", `(?:marker)?`, strings.Repeat("!marker#", 140), false},
		{"wild class without anchor", `[a-z]{4}[0-9]{4}`, strings.Repeat("test0123 ", 140), false},
		{"universal core", `(?s)marker.*result`, "marker" + strings.Repeat("line\n", 250) + "result", false},
		{"dense growth", `marker(?:\s+[ab]){1,125}`, strings.Repeat("marker a ", 400), true},
		{"dense disjoint windows", `marker[0-9]{2}`, strings.Repeat("marker12 ~~~~~~~~~~~~~~~~ ", regexpWindowMaxRanges+1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			re := regexp.MustCompile(tc.expression)
			plan := analyzeCompiledRegexpMatchRequirements(re).windows
			if (plan != nil) != tc.hasPlan {
				t.Fatalf("plan presence = %v, want %v", plan != nil, tc.hasPlan)
			}
			if plan != nil {
				if ranges, ok := plan.ranges(tc.text); ok || ranges != nil {
					t.Fatalf("expected full-input fallback, got %d ranges", len(ranges))
				}
			}
			if got, want := plan.findAll(re, tc.text), re.FindAllStringIndex(tc.text, -1); !reflect.DeepEqual(got, want) {
				t.Fatalf("whole-input fallback differs: got %d spans, want %d", len(got), len(want))
			}
		})
	}

	// A replacement with different matching semantics must ignore stale metadata.
	original := regexp.MustCompile(`marker|marker12`)
	plan := analyzeCompiledRegexpMatchRequirements(original).windows
	replacement := regexp.MustCompilePOSIX(original.String())
	text := strings.Repeat(".", regexpWindowMinText) + "marker12"
	if got, want := plan.findAll(replacement, text), replacement.FindAllStringIndex(text, -1); !reflect.DeepEqual(got, want) {
		t.Fatalf("replacement spans = %v, want %v", got, want)
	}
}

func TestRegexpWindowScannerParity(t *testing.T) {
	const markerName = "Synthetic build marker"
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name: markerName, Regex: `build_marker_[0-9]{8}`, Severity: config.SeverityHigh, Action: config.ActionWarn,
	})
	windowed, reference := MustNew(cfg), MustNew(cfg)
	t.Cleanup(windowed.Close)
	t.Cleanup(reference.Close)
	disable := func(patterns []*compiledPattern) []*compiledPattern {
		out := make([]*compiledPattern, len(patterns))
		for i, p := range patterns {
			cp := *p
			cp.regexpWindows, cp.bodyRegexpWindows = nil, nil
			out[i] = &cp
		}
		return out
	}
	reference.dlpPatterns = disable(reference.dlpPatterns)
	core := *reference.core
	core.dlpPatterns = disable(core.dlpPatterns)
	reference.core = &core

	padding := strings.Repeat("Build status: all unit jobs passed.\n", 48)
	const marker = "BUILD_MARKER_73190482"
	for _, tc := range []struct {
		name, text string
		matched    bool
	}{
		{"natural prose", padding, false},
		{"configured match and rejected prefix", padding + "BUILD_MARKER_2222\n" + marker, true},
		{"ASCII-folded decoded view", padding + base64.StdEncoding.EncodeToString([]byte(marker)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotWarnings, wantWarnings []string
			windowed.SetDLPWarnHook(func(_ context.Context, name, _ string) { gotWarnings = append(gotWarnings, name) })
			reference.SetDLPWarnHook(func(_ context.Context, name, _ string) { wantWarnings = append(wantWarnings, name) })
			got := windowed.ScanTextForDLP(t.Context(), tc.text)
			want := reference.ScanTextForDLP(t.Context(), tc.text)
			if !reflect.DeepEqual(got, want) || !slices.Equal(gotWarnings, wantWarnings) {
				t.Fatalf("findings or warning order differ: got %+v / %v, want %+v / %v", got, gotWarnings, want, wantWarnings)
			}
			if slices.Contains(gotWarnings, markerName) != tc.matched {
				t.Fatalf("marker warning = %v, want present=%v", gotWarnings, tc.matched)
			}
		})
	}
}

func FuzzRegexpWindowFindAllParity(f *testing.F) {
	f.Add(`(?im)^\bmarker[0-9]{2}\b$`, "marker12\nmarker13")
	f.Add(`(?i)skate\s+.{0,2}[0-9]{3}`, "ſKate ! é123")
	f.Add(`\x{FFFD}(?:marker|sample)[0-9]{2}`, "\xffmarker23")
	f.Add(`(?:[a-z]\s+){2,10}marker[0-9]{2}`, "a b c d e f marker12")
	f.Fuzz(func(t *testing.T, expression, input string) {
		if len(expression) > 128 || len(input) > 2048 {
			t.Skip()
		}
		tree, err := syntax.Parse(expression, syntax.Perl)
		if err != nil || len(tree.Simplify().String()) > 4096 {
			t.Skip()
		}
		re, err := regexp.Compile(expression)
		if err != nil {
			t.Skip()
		}
		plan := newRegexpWindowPlan(re, tree)
		if plan == nil {
			t.Skip()
		}
		text := strings.Repeat(" #.\n", regexpWindowMinText/4) + input + "\n" + input
		if got, want := plan.findAll(re, text), re.FindAllStringIndex(text, -1); !reflect.DeepEqual(got, want) {
			t.Fatalf("pattern %q over %q: got %v, want %v", expression, input, got, want)
		}
	})
}
