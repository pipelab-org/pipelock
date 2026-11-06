// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0
package scanner

import (
	"crypto/sha256"
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestAdmissionDefaultArithmetic(t *testing.T) {
	if len(reassemblyTestPlan(t).assembled.unscreened) != 0 {
		t.Fatal("default refusal obligation unexpectedly present")
	}

	for _, p := range config.DefaultDLPPatterns() {
		r, e := syntax.Parse("(?i)"+p.Regex, syntax.Perl)
		if e != nil {
			t.Fatal(e)
		}
		n := assembledJunkExposure * assembledJunkWeight(r)
		t.Logf("ADMISSION name=%q expected=%.12g min=%d", p.Name, n, shapeMinLen(r))
		if math.IsNaN(n) || n > 1 {
			t.Errorf("default fails admission: %s = %g", p.Name, n)
		}
	}
}

var admissionProbePatterns = []string{`[0-9]{16,}`, `[0-9]+`, `[A-Z]{2}[0-9]{1,30}`, `[0-9]{1,16}`, `[0-9]{2}|[0-9]{16}`, `[A-Z]|[0-9]{16}`, `EMP[0-9]{6}`, `(?i)internal-[a-z0-9]{1,40}`, `ACME_[A-Z0-9]{32}`, `[0-9]{16}`, `[A-F0-9]{40}`}

func TestAdmissionProbeArithmetic(t *testing.T) {
	expected := []struct{ admitted, residual, decoder bool }{
		{false, true, false},
		{false, true, false},
		{false, true, false},
		{false, true, false},
		{true, true, false},
		{true, true, false},
		{true, false, true},
		{true, false, true},
		{true, false, true},
		{true, false, false},
		{true, false, false},
	}
	if len(expected) != len(admissionProbePatterns) {
		t.Fatal("admission row inventory changed")
	}
	for index, expr := range admissionProbePatterns {
		tree, e := syntax.Parse("(?i)"+expr, syntax.Perl)
		if e != nil {
			t.Fatal(e)
		}
		admitted, residual := assembledAdmittedTree(tree)

		want := expected[index]
		decoder := admitted != nil && assembledRawAdmits(admitted)
		if (admitted != nil) != want.admitted || residual != want.residual || decoder != want.decoder {
			t.Fatalf("admission row %q changed: selected=%v residual=%v decoder=%v", expr, admitted, residual, decoder)
		}
		selected := ""
		if admitted != nil {
			selected = admitted.String()
		}
		t.Logf("PROBE regex=%q expected=%.12g admitted=%q residual=%v", expr, assembledJunkExposure*assembledJunkWeight(tree), selected, residual)
	}
}

func TestAdmissionConfiguredDetection(t *testing.T) {
	for _, tc := range []struct{ expr, value string }{
		{`[0-9]{16}`, "1234567812345678"},
		{`ACME_[A-Z0-9]{32}`, "ACME_" + strings.Repeat("Q7", 16)},
		{`[A-F0-9]{40}`, strings.Repeat("a1", 20)},
		{`EMP[0-9]{6}`, "EMP123456"},
		{`(?i)internal-[a-z0-9]{1,40}`, "internal-ab123"},
		{`[0-9]{2}|[0-9]{16}`, "1234567812345678"},
		{`[A-Z]|[0-9]{16}`, "1234567812345678"},
	} {
		p, e := newReassemblyPlan([]*compiledPattern{{name: "Configured admitted", re: regexp.MustCompile("(?i)" + tc.expr)}})
		if e != nil {
			t.Fatal(e)
		}
		for codec, enc := range reassemblyEncodings(" " + tc.value + " ") {
			for phase := range enc.quantum {
				t.Run(fmt.Sprintf("%s/%s/%d", tc.expr, enc.name, phase), func(t *testing.T) {
					body := strings.Repeat(string(reassemblyCodecs[codec].alphabet[0])+"!", 4200+phase) + reassemblyBang(enc.text)
					r := reassemblyTerminal(p, body, &assembledBudget{})
					target := sha256.Sum256([]byte(tc.value))
					found := slices.ContainsFunc(r.findings, func(m TextDLPMatch) bool {
						return m.PatternName == "Configured admitted" && m.hasValueIdentity && m.valueIdentity == target
					})
					if !found || r.incomplete {
						t.Fatalf("admitted pattern missed: %+v", r)
					}
				})
			}
		}
	}
}

func TestAdmissionSyntaxArithmetic(t *testing.T) {
	for _, tc := range []struct {
		expr string
		want float64
	}{
		{`a`, 1.0 / 256},
		{`(?i:a)`, 2.0 / 256},
		{`[0-9]`, 10.0 / 256},
		{`(?i:[A-Z])`, 52.0/256 + 1.0/(256*256) + 1.0/(256*256*256)},
		{`a|bc`, 1.0/256 + 1.0/(256*256)},
		{`a{2,3}`, 1.0 / (256 * 256)},
		{`a*`, 1},
		{`a+`, 1.0 / 256},
		{`a?`, 1},
		{`\ba`, 1.0 / 256},
		{`(?s:.)`, 1},
		{`.`, 255.0 / 256},
		{`[^\n]`, 255.0 / 256},
		{`(?s:.*)`, 1},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			tree, e := syntax.Parse(tc.expr, syntax.Perl)
			if e != nil {
				t.Fatal(e)
			}
			got := assembledJunkWeight(tree)
			// These masses are dyadic fractions, exact in binary float64.
			if got != tc.want {
				t.Fatalf("got %.16g want %.16g", got, tc.want)
			}
		})
	}
	if assembledJunkWeight(&syntax.Regexp{Op: syntax.OpNoMatch}) != 0 {
		t.Fatal("no-match has weight")
	}
	if !math.IsInf(assembledJunkWeight(&syntax.Regexp{}), 1) {
		t.Fatal("unknown syntax admitted")
	}
	if assembledJunkRune(-1) != 1 {
		t.Fatal("invalid scalar admitted selectively")
	}
}

func TestAdmissionBranchIsolation(t *testing.T) {
	for _, expr := range []string{`[A-Z]|[0-9]{16}`, `[A-Z]|MARK[0-9]+`} {
		p, e := newReassemblyPlan([]*compiledPattern{{name: "Partial record", re: regexp.MustCompile(expr)}})
		if e != nil {
			t.Fatal(e)
		}
		terminal := p.assembled.terminalPattern(0, p.patterns[0])
		if terminal == nil || terminal.re.MatchString("A") || !p.patterns[0].re.MatchString("A") {
			t.Fatal("branch language was not isolated")
		}
		if p.assembled.admitted[0] == nil {
			t.Fatal("terminal still uses declined alternative")
		}
	}
	p, e := newReassemblyPlan([]*compiledPattern{{name: "Residual record", re: regexp.MustCompile(`[0-9]+`)}})
	if e != nil {
		t.Fatal(e)
	}
	if p.assembled.terminalPattern(0, p.patterns[0]) != nil {
		t.Fatal("residual reaches escape consumer")
	}
}

func TestAdmissionResidualNoTerminal(t *testing.T) {
	p, e := newReassemblyPlan([]*compiledPattern{{name: "Residual only", re: regexp.MustCompile(`[0-9]+`)}})
	if e != nil {
		t.Fatal(e)
	}
	budget := &assembledBudget{}
	result := reassemblyTerminal(p, strings.Repeat("a!", maxDecodeTotalBytes+1), budget)
	if p.assembled.nestedHex || len(result.findings) != 0 || result.incomplete || budget.used != 0 {
		t.Fatal("declined plan performed terminal decoding", budget.used, result)
	}
}

func TestAdmissionMixedScreenSupport(t *testing.T) {
	tree, e := syntax.Parse(`MARK[0-9]+|[0-9]{16}`, syntax.Perl)
	if e != nil {
		t.Fatal(e)
	}
	selected, residual := assembledAdmittedTree(tree)
	if selected == nil || !residual || selected.String() != `[0-9]{16}` {
		t.Fatal("unsupported mixed screen joined", selected, residual)
	}
}

func TestAdmissionAlternativeSum(t *testing.T) {
	tree, e := syntax.Parse(`(?i:[A-H]{4}|[J-Q]{4})`, syntax.Perl)
	if e != nil {
		t.Fatal(e)
	}
	for _, branch := range assembledShapeBranches(tree) {
		if assembledJunkExposure*assembledJunkWeight(branch) > 1 {
			t.Fatal("single-branch positive control failed")
		}
	}
	selected, residual := assembledAdmittedTree(tree)
	if selected != nil || !residual {
		t.Fatal("alternatives exceeded the aggregate admission limit")
	}
}
