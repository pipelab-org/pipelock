// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import "testing"

func TestPayloadFieldNames(t *testing.T) {
	type details struct {
		Value string `json:"value"`
	}
	for _, tc := range []struct {
		body   string
		reject bool
	}{
		{`{"value":"ok"}`, false}, {`{"Value":"ok"}`, true}, {`{"value":"ok","Value":"other"}`, true},
	} {
		var target details
		if err := decodeStrict([]byte(tc.body), &target); (err != nil) != tc.reject {
			t.Fatalf("reject=%v: %v", tc.reject, err)
		}
		if tc.reject && target.Value != "" {
			t.Fatal("rejected raw payload populated target")
		}
	}
}
