// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func reassemblySplit(s, sep string) string { return strings.Join(strings.Split(s, ""), sep) }
func reassemblyEncodings(value string) []struct {
	name, text string
	quantum    int
} {
	b := []byte(value)
	return []struct {
		name, text string
		quantum    int
	}{{"hex", hex.EncodeToString(b), 2}, {"base64", base64.StdEncoding.EncodeToString(b), 4}, {"base64url", base64.URLEncoding.EncodeToString(b), 4}, {"base32", base32.StdEncoding.EncodeToString(b), 8}, {"base32hex", base32.HexEncoding.EncodeToString(b), 8}}
}

func reassemblyBang(s string) string { return reassemblySplit(s, "!") }
func reassemblyDecision(r reassemblyResult) string {
	if len(r.findings) > 0 {
		return "DETECT"
	}
	if r.incomplete {
		return "REFUSE"
	}
	return "MISS"
}

func reassemblyTestPlan(t testing.TB) *reassemblyPlan {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := newReassemblyPlan(sc.dlpPatterns)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func reassemblyTerminal(p *reassemblyPlan, text string, budget *assembledBudget) reassemblyResult {
	result := assembledLayer(p, text, budget, 0)
	if p.assembled.nestedHex && !budget.incomplete && assembledOuterAdmits(p, text, 0) {
		more := assembledNestedHexAdmitted(p, text, budget)
		assembledMerge(&result, more)
	}
	return result
}
