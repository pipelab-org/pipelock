// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminBodyFieldNames(t *testing.T) {
	for _, tc := range []struct {
		body   string
		reject bool
	}{
		{``, false},
		{`{"tier":"normal"}`, false},
		{`{"Tier":"normal"}`, false},
		{`{"tier":"normal","TIER":"hard"}`, true},
	} {
		var target struct {
			Tier string `json:"tier"`
		}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(tc.body))
		if err := decodeJSONBody(r, &target); (err != nil) != tc.reject {
			t.Fatalf("reject=%v: %v", tc.reject, err)
		}
		if tc.reject && target.Tier != "" {
			t.Fatal("rejected body populated target")
		}
	}
}
