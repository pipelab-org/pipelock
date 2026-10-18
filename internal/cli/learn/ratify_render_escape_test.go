// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// Rule selectors and rationale are learned from observed agent traffic and
// shown right before the enforce/capture/reject choice.
func TestRenderRatifyRuleEscapesObservedFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		host     string
		path     string
		wantLine string
	}{
		{name: "benign selector unchanged", host: "api.vendor.example", path: "/v1/items", wantLine: "selector: api.vendor.example/v1/items\n"},
		{name: "ansi and cr in host", host: "evil.example\x1b[2K\rapi.vendor.example", path: "/x", wantLine: `selector: evil.example\x1b[2K\rapi.vendor.example/x` + "\n"},
		{name: "backspace and bidi in path", host: "api.vendor.example", path: "/a\b\b\u202Etxt.exe", wantLine: `selector: api.vendor.example/a\x08\x08\u202Etxt.exe` + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := contract.Rule{
				RuleID:      "rule-1",
				Confidence:  "stable",
				WilsonLower: "0.9",
				Selector:    map[string]any{"host": tt.host, "path": tt.path},
			}
			c := contract.Contract{Rules: []contract.Rule{rule}}
			var buf bytes.Buffer
			if err := renderRatifyRule(&buf, c, rule, 0); err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			for _, raw := range []string{"\x1b", "\r", "\b", "\u202e"} {
				if strings.Contains(out, raw) {
					t.Fatalf("rendered rule contains raw %q:\n%q", raw, out)
				}
			}
			if !strings.Contains(out, tt.wantLine) {
				t.Fatalf("rendered rule missing %q:\n%s", tt.wantLine, out)
			}
		})
	}
}
