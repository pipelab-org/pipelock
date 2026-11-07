// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestReassemblyNestedEscapes(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Nested record", re: regexp.MustCompile(`MARK[0-9]{4}`)}, {name: "Residual record", re: regexp.MustCompile(`[0-9]+`)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, escaped := range []string{"&#77;&#65;&#82;&#75;1234", `\u004d\u0041\u0052\u004b1234`} {
		text := hex.EncodeToString([]byte(escaped))
		result := assembledNestedHexAdmitted(p, text, &assembledBudget{})
		if result.incomplete || !slices.Contains(matchNames(result.findings), "Nested record") {
			t.Fatal("nested escape lost a credential", escaped, result)
		}
		budget := &assembledBudget{used: maxDecodeTotalBytes - (2*len(escaped) - 1) - 1}
		result = assembledNestedHexAdmitted(p, text, budget)
		if !result.incomplete || budget.used != maxDecodeTotalBytes || len(result.findings) != 0 {
			t.Fatal("escape crossed the shared allowance", result, budget.used)
		}
	}
	exhausted := assembledNestedHexAdmitted(p, "001122", &assembledBudget{used: maxDecodeTotalBytes})
	if !exhausted.incomplete || len(exhausted.findings) != 0 {
		t.Fatal("partial outer view reached matching")
	}
}

func TestReassemblyHexViewAccounting(t *testing.T) {
	for _, text := range []string{"", "a", "00", "0!1A-bCdEfgh", strings.Repeat("ab!", 20)} {
		stripped := strings.Map(func(r rune) rune {
			if strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return r
			}
			return -1
		}, text)
		var want [2]string
		for phase := range want {
			if phase >= len(stripped) {
				continue
			}
			raw := stripped[phase:]
			raw = raw[:len(raw)&^1]
			data, err := hex.DecodeString(raw)
			if err != nil {
				t.Fatal(err)
			}
			want[phase] = string(data)
		}
		budget := &assembledBudget{}
		got := assembledHexViews(text, budget)
		if got != want || budget.incomplete || budget.used != len(want[0])+len(want[1]) {
			t.Fatal("hex phases or charges changed", got, want, budget.used)
		}
	}
	budget := &assembledBudget{used: maxDecodeTotalBytes - 1}
	if got := assembledHexViews("001122", budget); got != [2]string{} || !budget.incomplete || budget.used != maxDecodeTotalBytes {
		t.Fatal("outer lane crossed the byte boundary")
	}
	budget = &assembledBudget{used: maxDecodeTotalBytes - 1}
	if got := assembledHexViews("00", budget); got != [2]string{"\x00", ""} || budget.incomplete || budget.used != maxDecodeTotalBytes {
		t.Fatal("exact outer-byte allowance refused")
	}
}

func TestReassemblyNestedPatternPartition(t *testing.T) {
	p := reassemblyTestPlan(t)
	text := reassemblyBang(hex.EncodeToString([]byte(`\u0034` + "111" + "111111111111")))
	for _, set := range []textDLPPatternSet{textDLPAllPatterns, textDLPNonCardPatterns, textDLPCardPatterns} {
		result := reassemblyTerminal(p, text, &assembledBudget{patterns: set})
		found := slices.ContainsFunc(result.findings, func(m TextDLPMatch) bool { return m.genericCard })
		if result.incomplete || found != (set != textDLPNonCardPatterns) {
			t.Fatal("nested card partition changed", set, result)
		}
	}
}
