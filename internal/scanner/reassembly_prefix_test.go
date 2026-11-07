// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"testing"
)

func TestReassemblyMandatoryPrefixes(t *testing.T) {
	for _, tc := range []struct{ expr, value string }{
		{`\bMARK[0-9]{4}\b`, "MARK1234"},
		{`\BMARK[0-9]+END`, "MARK1234END"},
		{`(?m)^MARK[0-9]+$`, "MARK1234"},
		{`(?:MARK|OTHER)[0-9]{2,4}END`, "OTHER1234END"},
		{`MARK(?:X)?END`, "MARKXEND"},
		{`MARK(?:X)*END`, "MARKXXXEND"},
		{`MARK(?:X)+END`, "MARKXXXEND"},
		{`MARK(?:X.*Y){2}END`, "MARKXaYXbYEND"},
		{`MARK(?:X){0,2}END`, "MARKXXEND"},
		{`MARK.*END`, "MARK\xffEND"},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			tree, err := syntax.Parse(tc.expr, syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			control := tc.value
			if strings.HasPrefix(tc.expr, `\B`) {
				control = "x" + control
			}
			if !regexp.MustCompile(tc.expr).MatchString(control) {
				t.Fatal("full-match control absent")
			}
			prefix, _ := assembledMandatoryPrefix(tree)
			if !regexp.MustCompile("^(?:" + prefix.String() + ")").MatchString(tc.value) {
				t.Fatal("mandatory prefix excluded a full match", prefix, tc.value)
			}
		})
	}
	for _, expr := range []string{`[0-9]{16}`, `MARK(?:A|B).*END`, `MARK` + strings.Repeat(`A{1000}`, 5)} {
		tree, err := syntax.Parse(expr, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		if verify, _ := assembledPrefixVerifier(tree, []string{"END"}); verify != nil {
			t.Fatal("non-leading cue gained prefix admission", expr)
		}
	}
}

func TestReassemblyCompleteKeywordCues(t *testing.T) {
	tree, err := syntax.Parse(`(?:api(?:key|_key)|passw(?:ord|d))=[A-Z]{20}`, syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	got := reassemblyCueAnchors(tree)
	for _, want := range []string{"apikey=", "api_key=", "password=", "passwd="} {
		if !slices.Contains(got, want) {
			t.Fatal("factored keyword lost complete cue", got, want)
		}
	}
	if slices.Contains(got, "api") || slices.Contains(got, "passw") {
		t.Fatal("keyword fragments admitted a lane", got)
	}
}

func TestReassemblyPrefixRejectsIncompleteCredentials(t *testing.T) {
	full := reassemblyTestPlan(t)
	for _, tc := range []struct{ name, cue string }{{"AWS Access ID", "A3T"}, {"JWT Token", "eyJ"}} {
		id := slices.IndexFunc(full.patterns, func(p *compiledPattern) bool { return p.name == tc.name })
		p, err := newReassemblyPlan([]*compiledPattern{full.patterns[id]})
		if err != nil {
			t.Fatal(err)
		}
		plain := strings.Repeat("\x00", 128) + tc.cue + strings.Repeat("\x00", 128)
		for codec, enc := range reassemblyEncodings(plain) {
			for phase := range enc.quantum {
				body := strings.Repeat(string(reassemblyCodecs[codec].alphabet[0])+"!", phase) + reassemblyBang(enc.text)
				budget := &assembledBudget{}
				result := assembledLayer(p, body, budget, 0)
				if result.incomplete || len(result.findings) != 0 {
					t.Fatal("incomplete credential changed decision", tc.name, codec, phase, result)
				}
				if charges := budget.charged[body]; charges != nil && len(charges.lanes[codec][phase]) != 0 {
					t.Fatal("short prefix materialized a lane", tc.name, codec, phase)
				}
			}
		}
	}
}

func TestReassemblyPrefixKeepsLateValues(t *testing.T) {
	full := reassemblyTestPlan(t)
	plain := strings.Repeat("A3T\x00eyJ\x00", 1024) + inspectionLimitAWSKey()
	result := reassemblyTerminal(full, reassemblyBang(hex.EncodeToString([]byte(plain))), &assembledBudget{})
	if result.incomplete || !slices.Contains(matchNames(result.findings), "AWS Access ID") {
		t.Fatal("incomplete prefixes hid the valid tail", result)
	}
}

func TestReassemblyPrefixVerifierAdmission(t *testing.T) {
	for _, tc := range []struct {
		expr     string
		literals []string
		admitted bool
	}{
		{`MARK[0-9]{4}`, nil, false},
		{`[0-9]{16}`, []string{"MARK"}, false},
		{`(?:MARK|OTHER)[0-9]{4}`, []string{"MARK"}, false},
		{`MARK.*END`, []string{"END"}, false},
		{strings.Repeat("A", maxReassembledTokenLen+1), []string{strings.Repeat("A", maxReassembledTokenLen+1)}, false},
		{`A.*END`, []string{"A"}, false},
		{`MARK[0-9]{4}`, []string{"MARK"}, true},
	} {
		tree, err := syntax.Parse(tc.expr, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		verify, size := assembledPrefixVerifier(tree, tc.literals)
		if (verify != nil) != tc.admitted || tc.admitted && size <= 0 {
			t.Fatal("prefix admission changed", tc.expr, verify, size)
		}
	}
}
