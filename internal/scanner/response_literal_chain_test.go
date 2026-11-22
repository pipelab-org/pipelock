// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"strings"
	"testing"
)

var responseChainFixtures = []struct {
	name, expression, text string
	empty                  bool
}{
	{"gap at bound", `\balpha\b.{1,8}\bbravo\b`, "alpha--------bravo", false},
	{"gap over bound", `\balpha\b.{1,8}\bbravo\b`, "alpha---------bravo", true},
	{"gap below bound", `alpha[!]{2,5}bravo`, "alpha!bravo", true},
	{"overlapping literals", `ababa.{0,1}babab`, "ababab", true},
	{"overlapping hits", `ababa.{0,1}babab`, "ababababababababab", false},
	{"unicode fold and mixed case", `(?i)sketch.{1,2}(?-i:Tail)|(?i)kelp\s+ſeal`, "ſKetch🌿Tail SKETCH-Tail SKETCH-tail Kelp\t SEAL", false},
	{"fold case sensitive failure", `(?i)sketch.{1,2}(?-i:Tail)`, "ſKetch🌿tail", true},
	{"disjoint runs", `marker\s+\S+@tail`, "marker \tvalue@tail", false},
	{"separated runs", `marker\s+\S+@tail`, "marker \tvalue value@tail", true},
	{"whitespace", `alfa\s+bravo\s+charlie`, "alfa" + strings.Repeat(" \t", 130) + "bravo\r\n\tcharlie", false},
	{"optional group", `alpha(?:\s+dashed)?\s*bravo.{1,3}charlie`, "alphabravo:charlie alpha\n dashed\tbravo:charlie", false},
	{"alternated chains", `(?:alpha|bravo).{1,4}charlie|delta\s+echo`, "bravo---charlie delta \t echo alpha echo", false},
	{"two old anchor windows", `alpha.{1,80}bravo.{1,80}charlie`, "alpha" + strings.Repeat("-", 80) + "bravo" + strings.Repeat("-", 80) + "charlie", false},
	{"zero width context", `(?m)^\balpha\s+bravo\b$|\bcharlie\s+delta\b\z`, "alpha\tbravo\n~", false},
	{"large rune class", `alpha[a\x{D800}]{2,4}bravo`, "alphaaabravo", false},
	{"malformed utf8", `alpha[\x{FFFD}x]bravo`, "alpha\xffbravo", false},
}

func TestResponseLiteralChainParity(t *testing.T) {
	padding := strings.Repeat("~", responseMemoMinBytes)
	for _, fixture := range responseChainFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			p := memoTestPattern(fixture.name, fixture.expression)
			patterns := []*compiledPattern{p}
			pf := newResponsePreFilter(patterns)
			text := padding + "\n" + fixture.text + padding
			positions := newMatchingView(text, responseMatchingProgram(pf))
			view := &responsePreFilterView{positions: positions}
			ranges, applied := pf.chainRanges(text, view, patterns, []int{0}, nil).patternWindows(p)
			want := matchPatternsAgainst(patterns, text)
			if !applied || (len(ranges) == 0) != fixture.empty || (len(want) == 0) != fixture.empty {
				t.Fatalf("fixture did not exercise chain: applied=%t ranges=%d full matches=%d", applied, len(ranges), len(want))
			}
			if got := matchPatternsPreFilteredWithMemo(pf, patterns, text, view); !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestResponseLiteralChainGapVacuity(t *testing.T) {
	fixture := responseChainFixtures[0]
	p := memoTestPattern(fixture.name, fixture.expression)
	patterns := []*compiledPattern{p}
	pf := newResponsePreFilter(patterns)
	text := strings.Repeat("~", responseMemoMinBytes) + fixture.text
	view := newMatchingView(text, responseMatchingProgram(pf))
	plan := pf.chains[p.re]
	if plan == nil {
		t.Fatal("expected a derived chain")
	}
	check := func() bool {
		ranges, decided := plan.ranges(view, 0, nil, &responseChainScratch{})
		return decided && reflect.DeepEqual(matchResponseChainWindows(p.re, text, ranges, nil, false), p.re.FindAllStringIndex(text, -1))
	}
	if !check() {
		t.Fatal("positive control must agree with the full matcher")
	}
	plan.branches[0].stages[1].gap.ascii.fixed--
	if check() {
		t.Fatal("the oracle did not detect a one-byte underestimate")
	}
	t.Log("oracle detected a missed match after shrinking the derived gap by one byte")
}

func TestResponseLiteralChainIncompleteLists(t *testing.T) {
	p := memoTestPattern("capped", `alpha.{0,2}bravo`)
	patterns := []*compiledPattern{p}
	pf := newResponsePreFilter(patterns)
	program := responseMatchingProgram(pf)
	prefix := strings.Repeat("alpha!!", responseMatchingMaxLiteralHits+1)
	for _, suffix := range []string{"~", "alpha!bravo"} {
		text := prefix + suffix
		view := &responsePreFilterView{positions: newMatchingView(text, program)}
		if got, want := matchPatternsPreFilteredWithMemo(pf, patterns, text, view), matchPatternsAgainst(patterns, text); !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
		if _, complete := view.positions.positions("alpha"); complete {
			t.Fatal("dense list did not hit its cap")
		}
	}
}

func FuzzResponseLiteralChainParity(f *testing.F) {
	patterns := make([]*compiledPattern, len(responseChainFixtures))
	for i, fixture := range responseChainFixtures {
		patterns[i] = memoTestPattern(fixture.name, fixture.expression)
		f.Add(uint8(i), fixture.text, "~")
	}
	filter := newResponsePreFilter(patterns)
	program := responseMatchingProgram(filter)
	padding := strings.Repeat("~", regexpWindowMinText)
	f.Fuzz(func(t *testing.T, index uint8, left, right string) {
		if len(left)+len(right) > 8192 {
			t.Skip("bounded fuzz input")
		}
		p := patterns[int(index)%len(patterns)]
		text := left + padding + right
		view := newMatchingView(text, program)
		plan := filter.chains[p.re]
		if plan == nil {
			t.Fatal("fixture requires a chain")
		}
		ranges, ok := plan.ranges(view, responseMaxWindowRun(text), nil, &responseChainScratch{})
		if !ok {
			return
		}
		got := matchResponseChainWindows(p.re, text, ranges, nil, false)
		want := p.re.FindAllStringIndex(text, -1)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: got %v, want %v", p.re, got, want)
		}
	})
}

func TestResponseLiteralChainCrossesWindowSeam(t *testing.T) {
	p := memoTestPattern("cross seam", `alpha.{8}bravo.{8}charlie`)
	patterns := []*compiledPattern{p}
	filter := newResponsePreFilter(patterns)
	text := strings.Repeat("~", responseMemoMinBytes-10) + "alpha--------bravo--------charlie" + strings.Repeat("~", responseMemoMinBytes)
	positions := newMatchingView(text, responseMatchingProgram(filter))
	view := &responsePreFilterView{positions: positions}
	windows, applied := filter.chainRanges(text, view, patterns, []int{0}, nil).patternWindows(p)
	if !applied || len(windows) != 1 || windows[0].start >= responseMemoMinBytes || windows[0].end <= responseMemoMinBytes {
		t.Fatalf("expected one chain window straddling %d, got %v", responseMemoMinBytes, windows)
	}
	got := matchPatternsPreFilteredWithMemo(filter, patterns, text, view)
	if want := matchPatternsAgainst(patterns, text); len(want) != 1 || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want one full match %+v", got, want)
	}
}

func TestResponseLiteralChainArtificialEdgeAndCaptures(t *testing.T) {
	p := memoTestPattern("captures", `(?P<value>alpha)\z|(?P<inner>bravo)`)
	text := "~~~alpha~~~bravo~~~"
	slice := regexpWindowRange{3, 8}
	for _, captures := range []bool{false, true} {
		got := matchResponseChainWindows(p.re, text, []regexpWindowRange{slice}, nil, captures)
		if want := responseRegexpLocations(p.re, text, captures); len(want) != 1 || !reflect.DeepEqual(got, want) {
			t.Fatalf("artificial edge must retry whole regex: got %v, want %v", got, want)
		}
		got = matchResponseChainWindows(p.re, text, []regexpWindowRange{{10, 17}}, nil, captures)
		if want := responseRegexpLocations(p.re, text, captures); !reflect.DeepEqual(got, want) {
			t.Fatalf("window must retain match and capture coordinates: got %v, want %v", got, want)
		}
	}
}

func TestResponseLiteralChainWindowMemoIdentity(t *testing.T) {
	memo := &responseChainWindowMemo{}
	first := memoTestPattern("first", `alpha`)
	other := memoTestPattern("other", `bravo`)
	memo.add(first.re, "ordinary")
	if !memo.contains(first.re, "ordinary") || memo.contains(other.re, "ordinary") ||
		memo.contains(first.re, "Ordinary") || memo.contains(first.re, "ordinary!") {
		t.Fatal("window miss must be keyed by exact regexp and text identity")
	}
}

func TestResponseLiteralGateSkipsUnusedIndex(t *testing.T) {
	pattern := memoTestPattern("Two markers", `alfa.{1,4}bravo`)
	patterns := []*compiledPattern{pattern}
	filter := newResponsePreFilter(patterns)
	text := strings.Repeat("neutral;", responseMemoMinBytes)
	view := &responsePreFilterView{positions: newMatchingView(text, responseMatchingProgram(filter))}
	if view.positions == nil || filter.chains[pattern.re] == nil || filter.gates[0] == nil {
		t.Fatal("fixture needs both a gate and a chain plan")
	}
	if got := matchPatternsPreFilteredWithMemo(filter, patterns, text, view); len(got) != 0 || view.positions.ready {
		t.Fatalf("gate-rejected pattern returned %d matches or built its index: %t", len(got), view.positions.ready)
	}
}

func TestResponseSparseDeltaSkipsWholeViewGate(t *testing.T) {
	pattern := memoTestPattern("Two markers", `alfa.{1,4}bravo`)
	patterns := []*compiledPattern{pattern}
	filter := newResponsePreFilter(patterns)
	padding := strings.Repeat("~", responseMemoMinBytes)
	parent, child := padding+"neutral;", padding+"common;"
	edits, _, ok := responseDeltaEdits(parent, child)
	if !ok || len(edits) == 0 || pattern.re.MatchString(parent) {
		t.Fatal("fixture requires a non-identical child and a negative parent")
	}
	key, _ := responseNegativePatternKey(pattern)
	view := &responsePreFilterView{
		positions: newMatchingView(child, responseMatchingProgram(filter)),
		delta:     newResponseDeltaView(map[responseNegativeKey]struct{}{key: {}}, parent, edits),
	}
	if got := matchPatternsPreFilteredWithMemo(filter, patterns, child, view); len(got) != 0 || view.ready || view.positions.ready {
		t.Fatalf("sparse negative used the whole view: matches=%d gate=%t index=%t", len(got), view.ready, view.positions.ready)
	}
}

// A pattern with more candidate windows than the chain budget must decline
// the window plan rather than collect them all, and the full matcher it falls
// back to must still return every match. The budget is lowered so a small,
// sparse text reaches it before any other limit.
func TestResponseLiteralChainCandidateBudget(t *testing.T) {
	p := memoTestPattern("candidate budget", `alpha.{1,3}bravo`)
	patterns := []*compiledPattern{p}
	pf := newResponsePreFilter(patterns)
	const pairs = 12
	text := strings.Repeat("alpha-bravo"+strings.Repeat("~", responseMemoMinBytes), pairs)
	plan := func() bool {
		positions := newMatchingView(text, responseMatchingProgram(pf))
		view := &responsePreFilterView{positions: positions}
		_, applied := pf.chainRanges(text, view, patterns, []int{0}, nil).patternWindows(p)
		return applied
	}
	if !plan() {
		t.Fatal("sparse fixture did not use a window plan under the default budget")
	}
	saved := responseChainMaxCandidates
	responseChainMaxCandidates = pairs / 2
	t.Cleanup(func() { responseChainMaxCandidates = saved })
	if plan() {
		t.Fatal("chain planner kept a window plan past the candidate budget")
	}
	positions := newMatchingView(text, responseMatchingProgram(pf))
	view := &responsePreFilterView{positions: positions}
	want := matchPatternsAgainst(patterns, text)
	if len(want) != pairs {
		t.Fatalf("full matches = %d, want %d", len(want), pairs)
	}
	if got := matchPatternsPreFilteredWithMemo(pf, patterns, text, view); !reflect.DeepEqual(got, want) {
		t.Fatalf("fallback matches differ: got %d, want %d", len(got), len(want))
	}
}
