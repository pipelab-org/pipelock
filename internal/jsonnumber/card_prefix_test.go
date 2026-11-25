// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/carddlp"
	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestCardCandidatePrefix(t *testing.T) {
	card := cardtest.Number()
	for _, tail := range []string{" 1", "-3", " 12/28", "/1"} {
		found := carddlp.Visit(cardtest.Grouped(card, "-")+tail, false, func(c carddlp.Candidate) bool { return c.Digits == card })
		if !found {
			t.Errorf("card swallowed by %q", tail)
		}
	}
	if carddlp.Visit(card+"2", false, func(carddlp.Candidate) bool { return true }) {
		t.Fatal("cut a contiguous digit group")
	}
}

func TestIsShippedCardPattern(t *testing.T) {
	if !IsShippedCardPattern(ShippedCardPattern) || IsShippedCardPattern(`\b\d{4}(?:[ ]?\d){11,15}\b`) {
		t.Fatal("shipped card rule identity is wrong")
	}
}
