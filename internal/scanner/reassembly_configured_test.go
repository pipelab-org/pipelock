// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0
package scanner

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestConfiguredShapePhases(t *testing.T) {
	for _, tc := range []struct{ expr, value string }{
		{`[0-9]{16}`, "1234567812345678"},
		{`[0-9]{16,20}`, "123456781234567890"},
		{`[G-P]{16}`, strings.Repeat("N", 16)},
		{`(?:[0-9]{16}|[G-P]{16})`, strings.Repeat("N", 16)},
		// Adding digits to RuneError exceeds the uniform-junk admission limit.
		{`[0-9\x{FFFD}]{17}`, strings.Repeat("\ufffd", 17)},
		{`[0-9\x{FFFD}]{17}`, strings.Repeat("\xff", 17)},
		{`\x{FFFD}{16}`, strings.Repeat("\ufffd", 16)},
		{`\x{FFFD}{16}`, strings.Repeat("\xff", 16)},
		{`(?:ABC|\x{FFFD}){16}`, strings.Repeat("\xff", 16)},
	} {
		p, err := newReassemblyPlan([]*compiledPattern{{name: "Configured bounded", re: regexp.MustCompile(tc.expr)}})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.assembled.shapes) == 0 {
			t.Fatal("configured screen absent", tc.expr)
		}
		for codec, enc := range reassemblyEncodings(" " + tc.value + " ") {
			for phase := range enc.quantum {
				name := fmt.Sprintf("%s/%s/%d", tc.expr, enc.name, phase)
				t.Run(name, func(t *testing.T) {
					body := strings.Repeat(string(reassemblyCodecs[codec].alphabet[0])+"!", 4200+phase) + reassemblyBang(enc.text)
					r := reassemblyTerminal(p, body, &assembledBudget{})
					found := slices.ContainsFunc(r.findings, func(m TextDLPMatch) bool {
						return m.PatternName == "Configured bounded" && m.hasValueIdentity && m.valueIdentity == sha256.Sum256([]byte(tc.value))
					})
					if !found || r.incomplete {
						t.Fatalf("configured phase missed %s: result=%+v", name, r)
					}
				})
			}
		}
	}
	patterns := make([]*compiledPattern, 7+1)
	for i := range patterns {
		patterns[i] = &compiledPattern{name: fmt.Sprintf("Configured digits %d", i), re: regexp.MustCompile(`[0-9]{16}`)}
	}
	p, err := newReassemblyPlan(patterns)
	if err != nil {
		t.Fatal(err)
	}
	r := reassemblyTerminal(p, reassemblyBang(reassemblyEncodings("1234567812345678")[1].text), &assembledBudget{produced: make(map[assembledIdentity]struct{})})
	if len(r.findings) != len(patterns) || r.incomplete {
		t.Fatal("configured registry lost entries", len(r.findings))
	}
	for _, expr := range []string{`[0-9]{16,}`, `[0-9]*`, `[0-9]+`, `(?s:.*)`} {
		p, err := newReassemblyPlan([]*compiledPattern{{name: "Configured existing grammar", re: regexp.MustCompile(expr)}})
		if err != nil {
			t.Fatal("existing grammar must remain accepted", expr, err)
		}
		if len(p.assembled.shapes) != 0 {
			t.Fatal("grammar without finite replay and positive bound gained a screen", expr)
		}
	}
}

func TestConfiguredRuneErrorBytes(t *testing.T) {
	pattern := &compiledPattern{name: "Configured invalid text", re: regexp.MustCompile(`[0-9\x{FFFD}]{17}`)}
	p, err := newReassemblyPlan([]*compiledPattern{pattern})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.assembled.shapes) != 1 {
		t.Fatal("RuneError grammar has no automatic screen")
	}

	for _, value := range []string{strings.Repeat("\ufffd", 17), strings.Repeat("\xff", 17)} {
		if !pattern.re.MatchString(value) {
			t.Fatal("Go regexp positive control failed")
		}
		body := reassemblyBang(reassemblyEncodings(value)[0].text)
		r := reassemblyTerminal(p, body, &assembledBudget{})
		found := slices.ContainsFunc(r.findings, func(m TextDLPMatch) bool {
			return m.PatternName == pattern.name && m.valueIdentity == sha256.Sum256([]byte(value))
		})
		if !found || r.incomplete {
			t.Fatalf("RuneError byte semantics lost: input_bytes=%d", len(value))
		}
	}
}

func TestConfiguredRuneErrorContext(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Configured replacement", re: regexp.MustCompile(`\x{FFFD}{16}`)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{15, 16} {
		plain := strings.Repeat("\x00", 256) + strings.Repeat("\ufffd", count) + strings.Repeat("\x00", 256)
		body := reassemblyBang(reassemblyEncodings(plain)[0].text)
		scan := assembledScan{p: p, text: body, budget: &assembledBudget{}}
		scan.searchLane(0, 0, 0)
		detected := len(scan.result.findings) > 0
		if scan.result.incomplete {
			t.Fatal("tiny confirmation exhausted allowance")
		}
		if detected != (count == 16) {
			t.Fatalf("count=%d detected=%v", count, detected)
		}
	}
}
