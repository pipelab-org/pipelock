// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
)

// TestScanToolCallPolicyMatchesArgumentValues checks that tool_call scans
// match the tool policy on the argument values, as the MCP proxy does, and
// on the object keys as well.
func TestScanToolCallPolicyMatchesArgumentValues(t *testing.T) {
	h := newTestHandler(t)
	h.policyCfg = policy.New(config.MCPToolPolicy{
		Enabled: true,
		Action:  config.ActionBlock,
		Rules: []config.ToolPolicyRule{
			{Name: "Anchored Command", ToolPattern: `^bash$`, ArgPattern: `^rm -rf /srv/data$`, Action: config.ActionBlock},
			{Name: "Key Text", ToolPattern: `^bash$`, ArgPattern: `^command$`, Action: config.ActionBlock},
		},
	})
	tests := []struct {
		args string
		want []string
	}{
		{`{"command":"rm -rf /srv/data"}`, []string{"POLICY-Anchored Command", "POLICY-Key Text"}},
		{`{"rm -rf /srv/data":""}`, []string{"POLICY-Anchored Command"}},
		{`{"command":"ls -la"}`, []string{"POLICY-Key Text"}},
		{`{"cmd":"ls -la"}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.args, func(t *testing.T) {
			body := `{"kind":"tool_call","input":{"tool_name":"bash","arguments":` + tt.args + `}}`
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+testToken)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var resp Response
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range resp.Findings {
				if strings.HasPrefix(f.RuleID, "POLICY-") {
					got = append(got, f.RuleID)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("policy rules = %v, want %v", got, tt.want)
			}
		})
	}
}
