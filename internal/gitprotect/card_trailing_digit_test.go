// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package gitprotect

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// scan-diff shares the scanner's accepted-span policy, so a card followed by
// another numeric field is found in an added line exactly as at runtime.
func TestScanDiffTrailingDigitCard(t *testing.T) {
	patterns := CompileDLPPatterns(config.Defaults().DLP.Patterns)
	for _, tt := range cardtest.TrailingDigitCases() {
		t.Run(tt.Name, func(t *testing.T) {
			diff := "diff --git a/pay.txt b/pay.txt\n--- a/pay.txt\n+++ b/pay.txt\n@@ -0,0 +1 @@\n+" + tt.Text + "\n"
			result, err := ScanDiff(diff, patterns)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, f := range result.Findings {
				found = found || f.Pattern == "Credit Card Number"
			}
			if found == tt.Clean {
				t.Fatalf("card finding=%v want=%v findings=%+v", found, !tt.Clean, result.Findings)
			}
		})
	}
}
