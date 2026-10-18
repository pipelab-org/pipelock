// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package projectscan

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

// The project scan keeps its own pattern loop; it must still accept a card
// followed by another numeric field, as runtime scanning does.
func TestProjectScanTrailingDigitCard(t *testing.T) {
	patterns, err := compileDLPPatterns()
	if err != nil {
		t.Fatal(err)
	}
	var card *compiledDLP
	for i := range patterns {
		if patterns[i].name == patternCreditCard {
			card = &patterns[i]
		}
	}
	if card == nil || !card.cardPrefixRetry {
		t.Fatal("shipped card rule did not enable prefix retry")
	}
	for _, tt := range cardtest.TrailingDigitCases() {
		if got := card.matches(tt.Text); got == tt.Clean {
			t.Fatalf("%s: matches=%v want=%v", tt.Name, got, !tt.Clean)
		}
	}
}
