// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import "testing"

func TestLicenseJSONFieldNames(t *testing.T) {
	for _, tc := range []struct {
		body   string
		reject bool
	}{
		{`{"exp":1,"future":{"a":1,"A":2}}`, false},
		{`{"Exp":1}`, true},
		{`{"exp":1,"Exp":2}`, true},
	} {
		var value License
		if err := decodeLicenseJSON([]byte(tc.body), &value); (err != nil) != tc.reject {
			t.Fatalf("reject=%v: %v", tc.reject, err)
		}
		if tc.reject && value.ExpiresAt != 0 {
			t.Fatal("rejected claims populated target")
		}
	}
}
