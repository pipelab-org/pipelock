// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestBatchLaneSearch(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{
		{name: "First", re: regexp.MustCompile(`MARK.*NEVER`)},
		{name: "Second", re: regexp.MustCompile(`MARK.*NEVER`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := reassemblyBang(hex.EncodeToString([]byte("MARK NEVER MARK NEVER")))
	budget := &assembledBudget{}
	scan := assembledScan{p: p, text: text, budget: budget}
	scan.searchLane(0, 0, 0)
	if len(scan.result.findings) != 1 {
		t.Fatal("first pattern did not match")
	}
	used, lane := budget.used, scan.lanes[0][0]
	scan.searchLane(0, 0, 0)
	if len(scan.result.findings) != 1 {
		t.Fatal("same pattern searched twice")
	}
	scan.searchLane(0, 0, 1)
	if budget.used != used || scan.lanes[0][0] != lane || len(scan.result.findings) != 2 {
		t.Fatal("lane materialization or search repeated")
	}
	scan.searchLane(0, 1, 0)
	if len(scan.result.findings) != 2 || scan.lanes[0][1] == lane {
		t.Fatal("phase identity lost")
	}
	other := assembledScan{p: p, text: reassemblyBang(hex.EncodeToString([]byte("MARK NEVER"))), budget: budget}
	other.searchLane(0, 0, 0)
	if len(other.result.findings) != 1 {
		t.Fatal("view identity lost")
	}
	duplicate := assembledScan{p: p, text: text, budget: &assembledBudget{produced: map[assembledIdentity]struct{}{{pattern: 0, value: sha256.Sum256([]byte("MARK NEVER MARK NEVER"))}: {}}}}
	duplicate.searchLane(0, 0, 0)
	if len(duplicate.result.findings) != 0 {
		t.Fatal("same value produced twice")
	}
	exhausted := assembledScan{p: p, text: text, budget: &assembledBudget{used: maxDecodeTotalBytes}}
	exhausted.searchLane(0, 0, 0)
	if !exhausted.result.incomplete || exhausted.lanes[0][0] != nil || len(exhausted.result.findings) != 0 {
		t.Fatal("partial lane accepted")
	}
	exhausted.searchLane(0, 0, 1)
	if !exhausted.result.incomplete || exhausted.lanes[0][0] != nil || len(exhausted.result.findings) != 0 {
		t.Fatal("exhausted allowance resumed matching")
	}
}

func TestBatchWholeLaneContext(t *testing.T) {
	for _, expr := range []string{`MARK.*NEVER`, `\bMARK.*NEVER`, `\BMARK.*NEVER`, `(?m)^MARK.*NEVER`, `\AMARK.*NEVER`, `(?:X|)\bMARK.*NEVER`, `MARK.*NEVER\z`, `\x{FFFD}{16}`} {
		pattern := &compiledPattern{name: "Configured context", re: regexp.MustCompile(expr)}
		p, err := newReassemblyPlan([]*compiledPattern{pattern})
		if err != nil {
			t.Fatal(err)
		}
		for _, plain := range []string{"MARK NEVER", "xMARK NEVER", "x\nMARK NEVER", "éMARK NEVER", "\xffMARK NEVER", strings.Repeat("\ufffd", 15), strings.Repeat("\ufffd", 16), strings.Repeat("\xff", 16)} {
			for codec, enc := range reassemblyEncodings(plain) {
				for phase := range enc.quantum {
					t.Run(fmt.Sprintf("%s/%x/%s/%d", expr, plain, enc.name, phase), func(t *testing.T) {
						body := strings.Repeat(string(reassemblyCodecs[codec].alphabet[0])+"!", phase) + reassemblyBang(enc.text)
						scan := assembledScan{p: p, text: body, budget: &assembledBudget{}}
						scan.searchLane(codec, phase, 0)
						view := scan.lanes[codec][phase].view
						start, end, want := pattern.firstAcceptedSpan(view, nil)
						actual := assembledLayer(p, body, &assembledBudget{}, 0)
						if want && !slices.ContainsFunc(actual.findings, func(m TextDLPMatch) bool { return m.valueIdentity == sha256.Sum256([]byte(view[start:end])) }) {
							t.Fatal("raw terminal lost exact-lane context", actual)
						}

						if scan.result.incomplete || (len(scan.result.findings) > 0) != want {
							t.Fatalf("whole-view context changed: got=%v want=%v", scan.result.findings, want)
						}
						if want && scan.result.findings[0].valueIdentity != sha256.Sum256([]byte(view[start:end])) {
							t.Fatal("accepted span changed")
						}
					})
				}
			}
		}
	}
}

func TestBatchOverlapAcrossPhases(t *testing.T) {
	full := reassemblyTestPlan(t)
	id := slices.IndexFunc(full.patterns, func(p *compiledPattern) bool { return p.name == "Bitcoin WIF Private Key" })
	pattern := full.patterns[id]
	input := "K" + wifTestVectors[0]
	accepted := 0
	for _, loc := range pattern.re.FindAllStringIndex(input, -1) {
		if _, _, ok := pattern.acceptedSpan(input, loc[0], loc[1]); ok {
			accepted++
		}
	}
	start, end, ok := pattern.firstAcceptedSpan(input, nil)
	if accepted != 0 || !ok || start != 1 || end != 52 {
		t.Fatal("overlap control absent", accepted, start, end, ok)
	}
	p, err := newReassemblyPlan([]*compiledPattern{pattern})
	if err != nil {
		t.Fatal(err)
	}
	for codec, enc := range reassemblyEncodings(input) {
		for phase := range enc.quantum {
			t.Run(fmt.Sprintf("%s/%d", enc.name, phase), func(t *testing.T) {
				body := strings.Repeat(string(reassemblyCodecs[codec].alphabet[0])+"!", phase) + reassemblyBang(enc.text)
				r := reassemblyTerminal(p, body, &assembledBudget{produced: make(map[assembledIdentity]struct{})})
				if r.incomplete || !slices.ContainsFunc(r.findings, func(m TextDLPMatch) bool { return m.valueIdentity == sha256.Sum256([]byte(wifTestVectors[0])) }) {
					t.Fatal("overlapping accepted candidate lost", r)
				}
			})
		}
	}
}

func TestBatchDistinctValues(t *testing.T) {
	pattern := &compiledPattern{name: "Distinct record", re: regexp.MustCompile(`MARK[0-9]{4}`)}
	p, err := newReassemblyPlan([]*compiledPattern{pattern})
	if err != nil {
		t.Fatal(err)
	}
	first, second := "MARK1234", "MARK5678"
	for codec, enc := range reassemblyEncodings(first + " " + second) {
		for phase := range enc.quantum {
			t.Run(fmt.Sprintf("%s/%d", enc.name, phase), func(t *testing.T) {
				body := strings.Repeat(string(reassemblyCodecs[codec].alphabet[0])+"!", phase) + reassemblyBang(enc.text)
				budget := &assembledBudget{produced: map[assembledIdentity]struct{}{{pattern: 0, value: sha256.Sum256([]byte(first))}: {}}}
				result := reassemblyTerminal(p, body, budget)
				if result.incomplete || !slices.ContainsFunc(result.findings, func(m TextDLPMatch) bool { return m.valueIdentity == sha256.Sum256([]byte(second)) }) {
					t.Fatal("already-produced value hid a distinct accepted value", result)
				}
			})
		}
	}
}

// Repeated cues, successful tails, assertions and Unicode must all share one
// complete lane. Sizes stay bounded so this invariant runs in the normal suite.
func TestReassemblyReplayLinear(t *testing.T) {
	full := reassemblyTestPlan(t)
	jwt := full.patterns[slices.IndexFunc(full.patterns, func(p *compiledPattern) bool { return p.name == "JWT Token" })]
	for _, tc := range []struct{ name, expr, cue, tail string }{
		{"unfinished", jwt.re.String(), "eyJ", ""},
		{"positive tail", jwt.re.String(), "eyJ", " " + dlpAgentTrafficFixtures(t)["JWT Token"]},
		{"unicode", jwt.re.String(), "eyJé", ""},
		{"word boundary", `(?s)\bMARK.*NEVER`, "NEVER", ""},
		{"line boundary", `(?ms)^MARK.*NEVER`, "NEVER", ""},
		{"unbounded prefix", `(?s).*MARK.*NEVER`, "NEVER", ""},
		{"long anchor", `(?s).*LONG_MARK.*Z`, "LONG_MARK", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := newReassemblyPlan([]*compiledPattern{{name: "Replay record", re: regexp.MustCompile(tc.expr)}})
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range []int{128, 256, 512, 1024} {
				plain := strings.Repeat(tc.cue, n) + tc.tail
				budget := &assembledBudget{}
				scan := assembledScan{p: p, text: reassemblyBang(hex.EncodeToString([]byte(plain))), budget: budget}
				scan.searchLane(0, 0, 0)
				if scan.result.incomplete || budget.used != len(plain) || scan.lanes[0][0].view != plain {
					t.Fatal("lane replay is not linear", n, budget.used, len(plain))
				}
				lane := scan.lanes[0][0]
				findings := len(scan.result.findings)
				for range n {
					scan.searchLane(0, 0, 0)
				}
				if len(scan.result.findings) != findings || scan.checked[0][0]&1 == 0 {
					t.Fatal("pattern search was not retained")
				}
				if budget.used != len(plain) || scan.lanes[0][0] != lane {
					t.Fatal("lane materialized twice")
				}
				t.Logf("repeats=%d decoded_bytes=%d charged_bytes=%d", n, len(plain), budget.used)
			}
		})
	}
}

func TestReassemblyNearAllowance(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Quota record", re: regexp.MustCompile(`(?s).*MARK.*NEVER`)}})
	if err != nil {
		t.Fatal(err)
	}
	plain := "NEVER" + strings.Repeat("q", 64)
	text := reassemblyBang(reassemblyEncodings(plain)[1].text)
	budget := &assembledBudget{used: maxDecodeTotalBytes - 5}
	result := assembledLayer(p, text, budget, 0)
	if !result.incomplete || budget.used != maxDecodeTotalBytes || len(result.findings) != 0 {
		t.Fatal("partial lane matched or exceeded allowance", budget, result)
	}
}

func TestReassemblyUnicodeShapeRun(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Folded record", re: regexp.MustCompile(`(?i)[A-Z]{16}`)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, folded := range []string{"\u017f", "\u212a"} {
		for _, complete := range []bool{false, true} {
			value := folded
			if complete {
				value = strings.Repeat("A", 7) + folded + strings.Repeat("B", 8)
			}
			plain := strings.Repeat("\x00", 128) + value + strings.Repeat("\x00", 128)
			for codec, enc := range reassemblyEncodings(plain) {
				for phase := range enc.quantum {
					body := strings.Repeat(string(reassemblyCodecs[codec].alphabet[0])+"!", phase) + reassemblyBang(enc.text)
					budget := &assembledBudget{}
					result := assembledLayer(p, body, budget, 0)
					found := len(result.findings) > 0
					if result.incomplete || found != complete {
						t.Fatalf("fold=%q complete=%v codec=%d phase=%d: %+v", folded, complete, codec, phase, result)
					}
					if charges := budget.charged[body]; !complete && charges != nil && len(charges.lanes[codec][phase]) != 0 {
						t.Fatalf("isolated folded rune admitted its decoded lane: fold=%q codec=%d phase=%d", folded, codec, phase)
					}
				}
			}
		}
	}
}

func TestReassemblyShapeCarry(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Carry record", re: regexp.MustCompile(`(?i)[A-Z]{16}`)}})
	if err != nil {
		t.Fatal(err)
	}
	value := strings.Repeat("A", 16)
	for _, padding := range []int{1, 8, 15, 16, 17, 31} {
		for codec, enc := range reassemblyEncodings(strings.Repeat("@", padding) + value) {
			for phase := range enc.quantum {
				body := strings.Repeat(string(reassemblyCodecs[codec].alphabet[0])+"!", phase) + reassemblyBang(enc.text)
				result := assembledLayer(p, body, &assembledBudget{}, 0)
				if result.incomplete || !slices.ContainsFunc(result.findings, func(m TextDLPMatch) bool { return m.valueIdentity == sha256.Sum256([]byte(value)) }) {
					t.Fatal("rejected partial cue hid a valid tail", padding, codec, phase, result)
				}
			}
		}
	}
}

func BenchmarkReassemblyShapeScreen(b *testing.B) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Shape record", re: regexp.MustCompile(`(?i)[A-Z]{16}`)}})
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{maxReassembledTokenLen / 4, maxReassembledTokenLen / 2, maxReassembledTokenLen, 2 * maxReassembledTokenLen} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			text := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("@", size))))
			b.SetBytes(int64(len(text)))
			for b.Loop() {
				result := assembledLayer(p, text, &assembledBudget{}, 0)
				if result.incomplete || len(result.findings) != 0 {
					b.Fatal("partial class cues changed decision", result)
				}
			}
		})
	}
}

func TestReassemblyShapeMinimum(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Minimum record", re: regexp.MustCompile(`(?i)[A-Z]{16}`)}})
	if err != nil {
		t.Fatal(err)
	}
	for codec, enc := range reassemblyEncodings(strings.Repeat("\x00", 128) + strings.Repeat("A", 15) + strings.Repeat("\x00", 128)) {
		for phase := range enc.quantum {
			body := strings.Repeat(string(reassemblyCodecs[codec].alphabet[0])+"!", phase) + reassemblyBang(enc.text)
			budget := &assembledBudget{}
			result := assembledLayer(p, body, budget, 0)
			if result.incomplete || len(result.findings) > 0 {
				t.Fatal("short class run changed decision", codec, phase, result)
			}
			if charges := budget.charged[body]; charges != nil && len(charges.lanes[codec][phase]) != 0 {
				t.Fatal("short class run admitted its lane", codec, phase)
			}
		}
	}
}
