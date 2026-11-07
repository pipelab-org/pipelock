// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import "testing"

func TestWatchOnlyCoreCredentialClassification(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		credential   bool
	}{
		{"decode limit", urlInspectionLimitReason, false},
		{"query count limit", querySubsequenceLimitReason, false},
		{"credential", "core DLP match: AWS Access ID", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := Result{Scanner: ScannerCoreDLP, Reason: tc.reason}
			if !IsCoreCriticalResult(result) {
				t.Fatal("legacy floor changed")
			}
			if IsCoreCredentialResult(result) != tc.credential {
				t.Fatal("watch classification differs")
			}
			result.Allowed = true
			if IsCoreCredentialResult(result) {
				t.Fatal("allowed credential audience classified as block")
			}
		})
	}
}
