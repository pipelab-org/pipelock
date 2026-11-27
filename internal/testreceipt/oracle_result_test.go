// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package testreceipt

import "testing"

func TestNestedReceiptProbeResult(t *testing.T) {
	zero := 0
	for _, tc := range []struct {
		name      string
		directory bool
		location  string
		wantErr   bool
	}{
		{"whole directory", true, "", true},
		{"selected child", true, "child", false},
		{"selected file", false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := receiptProbeResultError(0, &zero, "VALID", "nested", tc.directory, tc.location)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %t", err, tc.wantErr)
			}
		})
	}
}
