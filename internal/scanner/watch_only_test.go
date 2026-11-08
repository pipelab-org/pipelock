// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import "testing"

func TestWatchOnlyRetainsCoreInspectionClassification(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
	}{
		{"decode limit", urlInspectionLimitReason},
		{"query count limit", querySubsequenceLimitReason},
		{"credential", "core DLP match: AWS Access ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := Result{Scanner: ScannerCoreDLP, Reason: tc.reason}
			if !IsCoreCriticalResult(result) {
				t.Fatal("legacy floor changed")
			}
			result.Allowed = true
			if IsCoreCriticalResult(result) {
				t.Fatal("allowed credential audience classified as block")
			}
		})
	}
}
