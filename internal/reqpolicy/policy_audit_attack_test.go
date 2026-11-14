// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"net/http"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func attackMatcher(t *testing.T, parse, opaque string, rules ...config.RequestPolicyRule) *Matcher {
	t.Helper()
	m, err := NewMatcher(&config.RequestPolicy{
		Enabled: true, OnParseError: parse, OnOpaqueOperation: opaque, Rules: rules,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRuleMatchAttackOpaqueDiscriminator(t *testing.T) {
	t.Parallel()
	rule := config.RequestPolicyRule{
		Name: "disc-block", Action: config.ActionBlock,
		Route:         config.RequestPolicyRoute{Hosts: []string{"api.vendor.example"}, Methods: []string{http.MethodPost}},
		Discriminator: &config.RequestPolicyDiscriminator{Field: "action", ValuePatterns: []string{`^delete`}},
	}
	bodies := []struct {
		name string
		raw  string
	}{
		{name: "non_object", raw: "[1]"},
		{name: "duplicate_key", raw: `{"action":"list","action":"deleteAll"}`},
		{name: "key_alias", raw: `{"Action":"deleteAll"}`},
		{name: "non_string", raw: `{"action":1}`},
	}
	for _, body := range bodies {
		t.Run(body.name, func(t *testing.T) {
			t.Parallel()
			m := attackMatcher(t, config.ActionAllow, config.ActionBlock, rule)
			got := m.Evaluate(RequestMeta{
				Host: "api.vendor.example", Method: http.MethodPost,
				JSONBodyParsed: true, JSONBody: jsonBody(t, body.raw),
				JSONDupKeys: topLevelDuplicateKeys(body.raw),
			})
			if got.Action != config.ActionBlock || got.RuleMatch || !got.Enforced() {
				t.Fatalf("opaque discriminator = %+v", got)
			}
		})
	}
}

func TestRuleMatchAttackShadowDoesNotClearEnforced(t *testing.T) {
	t.Parallel()
	route := config.RequestPolicyRule{
		Name: "block-dangerous", Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{Hosts: []string{"api.vendor.example"}, Methods: []string{http.MethodPost}},
	}
	shadow := config.RequestPolicyRule{
		Name: "shadow-disc", Action: config.ActionBlock, Shadow: true,
		Route:         config.RequestPolicyRoute{Hosts: []string{"api.vendor.example"}, Methods: []string{http.MethodPost}},
		Discriminator: &config.RequestPolicyDiscriminator{Field: "action", ValuePatterns: []string{`^delete`}},
	}
	m := attackMatcher(t, config.ActionBlock, config.ActionAllow, route, shadow)
	marked := m.Evaluate(RequestMeta{Host: "api.vendor.example", Method: http.MethodPost})
	unmarked := m.EvaluateUninspectable(RequestMeta{Host: "api.vendor.example", Method: http.MethodPost}, m.OnParseError(), PredDiscriminator)
	got := Stricter(marked, unmarked)
	// A shadow uninspectable block is not an enforced refusal. It must not
	// clear the mark on the enforced route block, or audit mode refuses a
	// request whose only enforced match was inspected.
	if got.Action != config.ActionBlock || !got.Enforced() || !got.RuleMatch || got.RuleName != route.Name {
		t.Fatalf("shadow unmarked cleared the enforced mark: %+v (unmarked=%+v)", got, unmarked)
	}
}

func TestRuleMatchAttackThreeRuleOrders(t *testing.T) {
	t.Parallel()
	orders := [][]string{
		{"enforced", "shadow", "unmarked"},
		{"enforced", "unmarked", "shadow"},
		{"shadow", "enforced", "unmarked"},
		{"shadow", "unmarked", "enforced"},
		{"unmarked", "enforced", "shadow"},
		{"unmarked", "shadow", "enforced"},
	}
	for _, order := range orders {
		order := order
		t.Run(joinOrder(order), func(t *testing.T) {
			t.Parallel()
			rules := map[string]config.RequestPolicyRule{
				"enforced": {
					Name: "block-dangerous", Action: config.ActionBlock,
					Route: config.RequestPolicyRoute{Hosts: []string{"api.vendor.example"}, Methods: []string{http.MethodPost}},
				},
				"shadow": {
					Name: "shadow-block", Action: config.ActionBlock, Shadow: true,
					Route: config.RequestPolicyRoute{Hosts: []string{"api.vendor.example"}, Methods: []string{http.MethodPost}},
				},
				"unmarked": {
					Name: "disc-block", Action: config.ActionBlock,
					Route:         config.RequestPolicyRoute{Hosts: []string{"api.vendor.example"}, Methods: []string{http.MethodPost}},
					Discriminator: &config.RequestPolicyDiscriminator{Field: "action", ValuePatterns: []string{`^delete`}},
				},
			}
			compiled := make([]config.RequestPolicyRule, 0, len(order))
			for _, name := range order {
				compiled = append(compiled, rules[name])
			}
			m := attackMatcher(t, config.ActionAllow, config.ActionBlock, compiled...)
			raw := `[1]`
			got := m.Evaluate(RequestMeta{
				Host: "api.vendor.example", Method: http.MethodPost,
				JSONBodyParsed: true, JSONBody: jsonBody(t, raw),
			})
			if got.Action != config.ActionBlock || !got.Enforced() || got.RuleMatch {
				t.Fatalf("order %v decision=%+v", order, got)
			}
		})
	}
}

func joinOrder(parts []string) string {
	out := parts[0]
	for _, part := range parts[1:] {
		out += "_" + part
	}
	return out
}

func topLevelDuplicateKeys(raw string) map[string]struct{} {
	if raw == `{"action":"list","action":"deleteAll"}` {
		return map[string]struct{}{"action": {}}
	}
	return nil
}

// An exception a parsed body could not be compared with keeps an unmarked
// block. A body that was compared and did not match is a rule match.
func TestRuleMatchAttackAmbiguousException(t *testing.T) {
	t.Parallel()
	route := config.RequestPolicyRoute{Hosts: []string{"api.vendor.example"}, Methods: []string{http.MethodPost}, PathPrefixes: []string{"/v1/move"}}
	field := config.RequestPolicyRule{
		Name: "field-except", Action: config.ActionBlock, Route: route,
		Except: &config.RequestPolicyException{Field: "destinationId", Values: []string{"archive"}},
	}
	exact := config.RequestPolicyRule{
		Name: "exact-except", Action: config.ActionBlock, Route: route,
		Except: &config.RequestPolicyException{Requests: []config.RequestPolicyExactRequest{{
			URL: "https://api.vendor.example/v1/move", Method: http.MethodPost,
			BodySHA256: "0000000000000000000000000000000000000000000000000000000000000000",
			ExpiresAt:  time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339), Owner: "ops", Reason: "approved move",
		}}},
	}
	base := RequestMeta{Host: "api.vendor.example", Method: http.MethodPost, Path: "/v1/move", ContentType: "application/json", JSONBodyParsed: true}
	cases := []struct {
		name      string
		rule      config.RequestPolicyRule
		edit      func(*RequestMeta)
		wantMatch bool
	}{
		{"field mismatch is a rule match", field, func(m *RequestMeta) { m.JSONBody = map[string]any{"destinationId": "purge"} }, true},
		{"field missing is a rule match", field, func(m *RequestMeta) { m.JSONBody = map[string]any{"other": "x"} }, true},
		{"field repeated", field, func(m *RequestMeta) {
			m.JSONBody = map[string]any{"destinationId": "archive"}
			m.JSONDupKeys = map[string]struct{}{"destinationId": {}}
		}, false},
		{"field alias", field, func(m *RequestMeta) {
			m.JSONBody = map[string]any{"destinationId": "archive", "DestinationId": "purge"}
		}, false},
		{"non-object body", field, func(m *RequestMeta) { m.JSONBody = []any{"archive"} }, false},
		{"exact mismatch is a rule match", exact, func(m *RequestMeta) {
			m.JSONBody = map[string]any{"a": "b"}
			m.ExactURL, m.JSONBodySHA256 = "https://api.vendor.example/v1/move", "1111111111111111111111111111111111111111111111111111111111111111"
		}, true},
		{"exact with repeated keys", exact, func(m *RequestMeta) {
			m.JSONBody = map[string]any{"a": "b"}
			m.JSONAmbiguous = true
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			meta := base
			tc.edit(&meta)
			got := attackMatcher(t, config.ActionAllow, config.ActionAllow, tc.rule).Evaluate(meta)
			if got.Action != config.ActionBlock || got.RuleMatch != tc.wantMatch {
				t.Fatalf("Evaluate = %+v, want block with RuleMatch=%t", got, tc.wantMatch)
			}
		})
	}
}
