// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanRequestFieldNames(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
		deny   bool
	}{
		{`{"kind":"dlp","input":{"text":"hello"}}`, http.StatusOK, false},
		{`{"Kind":"dlp","Input":{"Text":"hello"}}`, http.StatusOK, false},
		{`{"kind":"dlp","input":{"text":"hello","Text":"other"}}`, http.StatusBadRequest, false},
		{`{"Kind":"tool_call","Input":{"tool_name":"report","arguments":[1e10001]}}`, http.StatusOK, true},
		{`{"kind":"tool_call","Kind":"dlp","input":{"tool_name":"report","arguments":[1e10001]}}`, http.StatusBadRequest, false},
	} {
		h := newTestHandler(t)
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+testToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("status=%d want %d", w.Code, tc.status)
		}
		if tc.status == http.StatusOK {
			var response Response
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Status != StatusCompleted || (response.Decision == DecisionDeny) != tc.deny {
				t.Fatalf("status=%s decision=%s", response.Status, response.Decision)
			}
		}
	}
}
