//go:build enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import "testing"

func TestVendorFieldNames(t *testing.T) {
	for _, tc := range []struct {
		body   string
		reject bool
	}{
		{`{"status":"active","metadata":{"a":1,"A":2}}`, false},
		{`{"Status":"active","future":true}`, false},
		{`{"status":"active","Status":"inactive"}`, true},
	} {
		var out struct {
			Status   string         `json:"status"`
			Metadata map[string]int `json:"metadata"`
		}
		if err := decodeVendorJSON([]byte(tc.body), &out); (err != nil) != tc.reject {
			t.Fatalf("reject=%v: %v", tc.reject, err)
		}
		if tc.reject && out.Status != "" {
			t.Fatal("rejected response populated target")
		}
	}
}
