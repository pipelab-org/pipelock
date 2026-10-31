// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestToggleFieldNames(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"active":false}`, http.StatusOK},
		{`{"Active":false}`, http.StatusOK},
		{`{"active":true,"Active":false}`, http.StatusBadRequest},
		{`{"ACTIVE":true,"Active":false}`, http.StatusBadRequest},
	} {
		cfg := testConfig()
		cfg.KillSwitch.APIToken = testAPIToken
		c := New(cfg)
		c.SetAPI(true)
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/killswitch", strings.NewReader(tc.body))
		r.Header.Set("Authorization", testBearer123)
		w := httptest.NewRecorder()
		NewAPIHandler(c).HandleToggle(w, r)
		if w.Code != tc.status {
			t.Fatalf("status=%d want %d", w.Code, tc.status)
		}
		active := c.IsActiveHTTP(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch", nil)).Active
		if active != (tc.status == http.StatusBadRequest) {
			t.Fatal("request changed retained state incorrectly")
		}
	}
}
