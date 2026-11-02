// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package compatest

import "testing"

// The shared cases must exercise both decisions and the failed-query path, or
// a parity test built on them could pass without covering the contract.
func TestReferCasesCoverContract(t *testing.T) {
	names := map[string]bool{}
	var allowed, denied, queryErr bool
	for _, tc := range ReferCases() {
		if tc.Name == "" || names[tc.Name] {
			t.Fatalf("case name %q is empty or repeated", tc.Name)
		}
		names[tc.Name] = true
		if tc.ABI < 5 {
			t.Fatalf("%s: ABI %d is below Guard's minimum", tc.Name, tc.ABI)
		}
		allowed = allowed || tc.Allowed
		denied = denied || !tc.Allowed
		if tc.QueryErr != nil {
			queryErr = true
			if tc.Allowed || tc.Fixed&0x4 == 0 {
				t.Fatalf("%s: a failed query must deny even with the fix bit set", tc.Name)
			}
		}
	}
	if !allowed || !denied || !queryErr {
		t.Fatalf("cases cover allowed=%v denied=%v queryErr=%v", allowed, denied, queryErr)
	}
}
