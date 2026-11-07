// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"testing"
)

func TestReassemblyLiteralAdmission(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Long literal", re: regexp.MustCompile(`PREFIX_COMPLETE[0-9]{4}`)}})
	if err != nil {
		t.Fatal(err)
	}
	budget := &assembledBudget{used: maxDecodeTotalBytes}
	body := reassemblyBang(hex.EncodeToString([]byte("PREFIX_WRONG1234")))
	result := assembledLayer(p, body, budget, 0)
	if result.incomplete || len(result.findings) > 0 || budget.used != maxDecodeTotalBytes {
		t.Fatal("partial literal spent allowance", result)
	}
	positive := reassemblyBang(hex.EncodeToString([]byte("PREFIX_COMPLETE1234")))
	result = assembledLayer(p, positive, budget, 0)
	if !result.incomplete || len(result.findings) > 0 {
		t.Fatal("full literal skipped exhausted allowance", result)
	}
}

func TestReassemblyValidatorContinuation(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Checked record", re: regexp.MustCompile(`MARK[0-9]{4}`), validate: func(s string) bool { return s == "MARK1234" }}})
	if err != nil {
		t.Fatal(err)
	}
	for _, enc := range reassemblyEncodings("MARK9999 MARK1234") {
		result := reassemblyTerminal(p, reassemblyBang(enc.text), &assembledBudget{})
		if result.incomplete || !slices.ContainsFunc(result.findings, func(m TextDLPMatch) bool {
			return m.hasValueIdentity && m.valueIdentity == sha256.Sum256([]byte("MARK1234"))
		}) {
			t.Fatal("rejected candidate hid accepted value", enc.name, result)
		}
	}
}
