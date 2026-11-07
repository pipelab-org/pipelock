// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestSelectiveDetection(t *testing.T) {
	p := reassemblyTestPlan(t)
	fixtures := dlpAgentTrafficFixtures(t)
	fixtures["Bitcoin WIF Private Key"] = wifTestVectors[0]
	for id, pattern := range p.patterns {
		plain, ok := fixtures[pattern.name]
		if !ok {
			t.Fatalf("no fixture: %s", pattern.name)
		}
		if !pattern.re.MatchString(plain) {
			t.Fatalf("fixture regex: %s", pattern.name)
		}
		loc := pattern.re.FindStringIndex(plain)
		if _, _, ok = pattern.acceptedSpan(plain, loc[0], loc[1]); !ok {
			t.Fatalf("fixture validator: %s", pattern.name)
		}
		covered := true
		if admitted := p.assembled.verify[id] != nil || slices.ContainsFunc(p.assembled.shapes, func(s *assembledShape) bool { return s.id == id }); admitted != covered {
			t.Fatalf("admission %s: %v != %v", pattern.name, admitted, covered)
		}
		for _, enc := range reassemblyEncodings(" " + plain + " ") {
			for phase := range enc.quantum {
				t.Run(fmt.Sprintf("%s/%s/%d", pattern.name, enc.name, phase), func(t *testing.T) {
					t.Parallel()
					// Each codec keeps a long-view witness; the other phases
					// test alignment without repeating that whole prefix.
					prefix := enc.quantum + phase
					if phase == 0 {
						prefix = 4200
					}
					body := strings.Repeat("a!", prefix) + reassemblyBang(enc.text)
					r := reassemblyTerminal(p, body, &assembledBudget{})
					found := slices.ContainsFunc(r.findings, func(m TextDLPMatch) bool { return m.PatternName == pattern.name })
					if found != covered || r.incomplete {
						t.Errorf("got=%s covered=%v", reassemblyDecision(r), covered)
					}
				})
			}
		}
	}
	for _, plain := range []string{
		"N" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27),
		"mfa." + strings.Repeat("a", 83) + "\u212a",
		"M" + strings.Repeat("a", 23) + "." + strings.Repeat("\u212a", 6) + "." + strings.Repeat("\u017f", 27),
		" a\u017f\u212a" + strings.Repeat("a", 32) + " ",
	} {
		for _, enc := range reassemblyEncodings(plain) {
			for phase := range enc.quantum {
				r := reassemblyTerminal(p, strings.Repeat("a!", 4200+phase)+reassemblyBang(enc.text), &assembledBudget{})
				if len(r.findings) == 0 || r.incomplete {
					t.Errorf("unicode %q %s/%d: %s", plain, enc.name, phase, reassemblyDecision(r))
				}
			}
		}
	}
	{
		for _, plain := range []string{
			" GB85" + "ABCDEFGHIJKLMNOPQR ",
			" 4111" + "111111111112 4111" + "111111111111 ",
			strings.Repeat("4111"+"111111111112 ", 20) + "4111" + "111111111111 ",
			" GB83" + "WEST12345698765432 GB82" + "WEST12345698765432 ",
			strings.Repeat("z", 300) + wifTestVectors[0],
		} {
			for _, enc := range reassemblyEncodings(plain) {
				r := reassemblyTerminal(p, reassemblyBang(enc.text), &assembledBudget{})
				if len(r.findings) == 0 || r.incomplete {
					t.Errorf("structural %s: %s", enc.name, reassemblyDecision(r))
				}
			}
		}
	}
}

func TestSelectiveBoundaries(t *testing.T) {
	p := reassemblyTestPlan(t)
	for _, plain := range []string{
		"mfa." + strings.Repeat("a", 83),
		"MFA." + strings.Repeat("a", 84),
		"P" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27),
		"M" + strings.Repeat("a", 22) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27),
		"M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 5) + "." + strings.Repeat("c", 27),
		"M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 7) + "." + strings.Repeat("c", 27),
		"M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 26),
		" SK" + strings.Repeat("a", 31) + " ",
		" SK" + strings.Repeat("a", 33) + " ",
		"xSK" + strings.Repeat("a", 32) + " ",
		" SK" + strings.Repeat("a", 31) + "g ",
	} {
		for _, enc := range reassemblyEncodings(plain) {
			r := reassemblyTerminal(p, reassemblyBang(enc.text), &assembledBudget{})
			if len(r.findings) > 0 || r.incomplete {
				t.Errorf("malformed %q %s: %s", plain, enc.name, reassemblyDecision(r))
			}
		}
	}
}

func TestSelectiveResiduals(t *testing.T) {
	for _, tc := range []struct{ name, expr, plain string }{
		{"configured-short-M", `(?-i:M)[a-z0-9]{23}`, "M" + strings.Repeat("a", 23)},
		{"preset-Ethereum-Address", `(?i)0x[0-9a-fA-F]{40}\b`, "0x" + strings.Repeat("a", 40) + " "},
	} {
		pattern := &compiledPattern{name: tc.name, re: regexp.MustCompile(tc.expr)}
		if !pattern.re.MatchString(tc.plain) {
			t.Fatal("invalid residual positive control")
		}
		p, err := newReassemblyPlan([]*compiledPattern{pattern})
		if err != nil {
			t.Fatal(err)
		}
		for _, enc := range reassemblyEncodings(tc.plain) {
			for phase := range enc.quantum {
				name := fmt.Sprintf("%s/%s/phase%d", tc.name, enc.name, phase)
				body := strings.Repeat("a!", 4200+phase) + reassemblyBang(enc.text)
				r := reassemblyTerminal(p, body, &assembledBudget{})
				if len(r.findings) == 0 || r.incomplete {
					t.Errorf("configured recovery lost %s: %s", name, reassemblyDecision(r))
				}
			}
		}
	}
}
