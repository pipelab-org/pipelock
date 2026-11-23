// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

func testResponseWindowPlan(t testing.TB, expression string) *regexpWindowPlan {
	t.Helper()
	re := regexp.MustCompile(expression)
	tree, err := syntax.Parse(expression, syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	return newResponseRegexpWindowPlan(re, tree)
}

func TestResponseRegexpWindowSpans(t *testing.T) {
	const paddingLen = 4096
	padding := strings.Repeat("~", paddingLen)
	for _, tc := range []struct {
		name, expression, input string
	}{
		{"overlap", `(?i)marker(?:[A-Z]{0,8}marker|[A-Z]{1,12})`, padding + "markerMARKERxx markerxyz" + padding + "markerend"},
		{"folded unicode", `(?i)sketch\s*[0-9]{2}\b`, padding + "ſKetch\t\t42 SKETCH12 すけっち" + padding},
		{"rune and invalid bytes", `catalog.{1,3}end`, padding + "catalog🌿é\xffend" + padding},
		{"line and word edges", `(?im)^\bmarker\s*[0-9]{2}\b$`, "marker01\n" + padding + "marker02\nMaRKer03\n" + padding + "\nmarker04"},
		{"absolute edges", `\Afirst[0-9]{2}|last[0-9]{2}\z`, "first12\n" + padding + "first13\nlast14\n" + padding + "last15"},
		{"observed runs", `catalog[\t _-]+[0-9]+\s+marker`, padding + "catalog" + strings.Repeat(" _-", 97) + "12345 \n marker" + padding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := testResponseWindowPlan(t, tc.expression)
			if plan == nil {
				t.Fatal("fixture requires a width proof")
			}
			want := plan.re.FindAllStringIndex(tc.input, -1)
			for _, folded := range []string{"", responseWindowFold(tc.input, responseSimpleFold(tc.input))} {
				ranges, ok := plan.responseRanges(tc.input, folded, nil, responseMaxWindowRun(tc.input))
				if !ok || len(ranges) == 0 {
					t.Fatal("fixture requires literal windows")
				}
				got := matchRegexpWindows(plan.re, tc.input, ranges, nil)
				if len(want) == 0 || !reflect.DeepEqual(got, want) {
					t.Fatalf("got %v, want nonempty %v", got, want)
				}
			}
		})
	}
}

func TestResponseRegexpWindowFallback(t *testing.T) {
	for _, expression := range []string{`marker.*tail`, `marker(?:x\s+)+tail`, `marker\S+tail`, `(?:marker)?`, `marker|[a-z]{8}`} {
		if plan := testResponseWindowPlan(t, expression); plan != nil {
			t.Fatalf("unexpected width proof for %q", expression)
		}
	}
	plan := testResponseWindowPlan(t, `marker\s+tail`)
	text := "marker" + strings.Repeat(" ", responseWindowMaxWidth+1) + "tail"
	if ranges, ok := plan.responseRanges(text, "", nil, responseMaxWindowRun(text)); ok || ranges != nil {
		t.Fatal("wide run must use whole-view matching")
	}
}

func FuzzResponseRegexpWindowSpans(f *testing.F) {
	patterns := []string{
		`(?i)sketch\s*[0-9]{2}\b`,
		`marker(?:[a-z]{0,8}marker|[a-z]{1,12})`,
		`(?im)^\bmarker\s*[0-9]{2}\b$`,
		`catalog.{1,3}end`,
		`\Afirst[0-9]{2}|last[0-9]{2}\z`,
	}
	for i, seed := range []string{"ſKetch\t42", "markermarkerxyz", "marker42\nmarker17x", "catalog🌿\xffend", "last42"} {
		f.Add(uint8(i), seed, "marker05")
	}
	plans := make([]*regexpWindowPlan, len(patterns))
	for i, pattern := range patterns {
		plans[i] = testResponseWindowPlan(f, pattern)
	}
	padding := strings.Repeat("~", regexpWindowMinText)
	f.Fuzz(func(t *testing.T, index uint8, prefix, suffix string) {
		if len(prefix)+len(suffix) > 8192 {
			t.Skip("bounded fuzz input")
		}
		text := prefix + padding + suffix
		plan := plans[int(index)%len(plans)]
		folded := responseWindowFold(text, responseSimpleFold(text))
		ranges, ok := plan.responseRanges(text, folded, nil, responseMaxWindowRun(text))
		if !ok {
			return
		}
		got := matchRegexpWindows(plan.re, text, ranges, nil)
		want := plan.re.FindAllStringIndex(text, -1)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: got %v, want %v", plan.re, got, want)
		}
	})
}
