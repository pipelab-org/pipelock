// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestCheckToolCallJSON(t *testing.T) {
	pc := New(config.MCPToolPolicy{
		Enabled: true,
		Action:  config.ActionWarn,
		Rules: []config.ToolPolicyRule{
			{Name: "Anchored", ToolPattern: `^bash$`, ArgPattern: `^rm -rf /srv/data$`, Action: config.ActionBlock},
			{Name: "Key Text", ToolPattern: `^bash$`, ArgPattern: `^command$`, Action: config.ActionWarn},
		},
	})
	tests := []struct {
		name       string
		raw        string
		withKeys   []string
		wantRules  []string
		wantAction string
	}{
		{"value matched on its own", `{"command":"rm -rf /srv/data"}`, []string{"command", "rm -rf /srv/data"}, []string{"Anchored", "Key Text"}, config.ActionBlock},
		{"key matched", `{"rm -rf /srv/data":""}`, []string{"rm -rf /srv/data", ""}, []string{"Anchored"}, config.ActionBlock},
		{"key text only", `{"command":"ls"}`, []string{"command", "ls"}, []string{"Key Text"}, config.ActionWarn},
		{"no keys", `["ls"]`, []string{"ls"}, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values, truncated := ArgValues(json.RawMessage(tt.raw))
			if truncated {
				t.Fatal("unexpected truncation")
			}
			v := pc.CheckToolCallJSON("bash", values, tt.withKeys, json.RawMessage(tt.raw))
			if !slices.Equal(v.Rules, tt.wantRules) || v.Action != tt.wantAction {
				t.Fatalf("verdict %q %v, want %q %v", v.Action, v.Rules, tt.wantAction, tt.wantRules)
			}
		})
	}
}

func TestMergeVerdicts(t *testing.T) {
	warn := Verdict{Matched: true, Action: config.ActionWarn, Rules: []string{"a", "b"}, Notes: []string{"n1"}}
	block := Verdict{Matched: true, Action: config.ActionBlock, Rules: []string{"b", "c"}, Notes: []string{"n1", "n2"}}
	got := mergeVerdicts(warn, block)
	if got.Action != config.ActionBlock || !slices.Equal(got.Rules, []string{"a", "b", "c"}) || !slices.Equal(got.Notes, []string{"n1", "n2"}) {
		t.Fatalf("merge = %+v", got)
	}
	if got := mergeVerdicts(warn, Verdict{}); got.Action != config.ActionWarn || !slices.Equal(got.Rules, warn.Rules) {
		t.Fatalf("merge with no match = %+v", got)
	}
	if got := mergeVerdicts(Verdict{}, block); got.Action != config.ActionBlock || !slices.Equal(got.Rules, block.Rules) {
		t.Fatalf("merge onto no match = %+v", got)
	}
}

func TestArgValues(t *testing.T) {
	values, truncated := ArgValues(json.RawMessage(`{"command":"rm -rf /tmp/x","b":["-v",{"c":"d"}],"n":5}`))
	if truncated {
		t.Fatal("unexpected truncation")
	}
	if want := []string{"-v", "d", "rm -rf /tmp/x"}; !slices.Equal(values, want) {
		t.Fatalf("values = %q, want %q", values, want)
	}

	deep := strings.Repeat(`{"a":`, 200) + `"x"` + strings.Repeat(`}`, 200)
	if _, truncated := ArgValues(json.RawMessage(deep)); !truncated {
		t.Fatal("deeply nested arguments not reported as truncated")
	}
	if _, truncated := ArgValues(json.RawMessage(`{"a":{"b":"c"}}`)); truncated {
		t.Fatal("shallow arguments reported as truncated")
	}
}
