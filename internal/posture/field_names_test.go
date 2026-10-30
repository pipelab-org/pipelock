// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"encoding/json"
	"testing"
)

func TestCapsuleFieldNames(t *testing.T) {
	for _, tc := range []struct {
		body   string
		reject bool
	}{
		{`{"evidence":{"containment":{"boundary_verified":true}}}`, false},
		{`{"evidence":{"containment":{"Boundary_verified":true}}}`, true},
		{`{"evidence":{"containment":{"boundary_verified":false,"Boundary_verified":true}}}`, true},
	} {
		var target Capsule
		if err := json.Unmarshal([]byte(tc.body), &target); (err != nil) != tc.reject {
			t.Fatalf("reject=%v: %v", tc.reject, err)
		}
	}
}
