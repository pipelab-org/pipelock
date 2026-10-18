// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A string card past the field walk must be the same finding the walk reports
// inside the budget. Numeric leaves stay on the typed card path.
func TestA2AOverflowStringCardMatchesInBudgetWalk(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionWarn
	card := cardtest.Number()
	encoded := base64.StdEncoding.EncodeToString([]byte(card))
	for _, probe := range []string{card, encoded} {
		for _, count := range []int{100, 10500} {
			got := ScanA2ARequestBody(context.Background(), []byte(a2aWideBody(count, probe)), sc, cfg)
			if !hasNamedDLP(got.DLPFindings, "Credit Card Number") || scanner.OnlyInformational(got.DLPFindings) {
				t.Fatalf("count=%d encoded=%v: string card lost or downgraded: action=%s clean=%v err=%s", count, probe != card, got.Action, got.Clean, got.ScanError)
			}
		}
	}
}

func hasNamedDLP(matches []scanner.TextDLPMatch, name string) bool {
	for _, match := range matches {
		if match.PatternName == name {
			return true
		}
	}
	return false
}
