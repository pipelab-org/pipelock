// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
)

func TestDLPKeywordsInvalidPercentRecovery(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"account " + "33333333%zz33333333", true},
		{"account " + "33333333%zz%33" + "3333333", true},
		{"reference " + "33333333%zz33333333", false},
		{"account" + strings.Repeat(" ", 100) + "33333333%zz33333333", false},
	} {
		result := sc.ScanTextForDLP(t.Context(), tc.text)
		if got := keywordFound(result); got != tc.want || HasInspectionLimit(result.Matches) {
			t.Fatalf("text=%q finding=%v want=%v: %+v", tc.text, got, tc.want, result)
		}
	}
}
