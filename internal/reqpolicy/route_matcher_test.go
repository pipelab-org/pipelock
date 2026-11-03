// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestRouteMatcherMatchesRuleSemantics(t *testing.T) {
	route := config.RequestPolicyRoute{
		Hosts:        []string{"api.vendor.example"},
		Methods:      []string{"get"},
		PathPrefixes: []string{"/v1/items/"},
		PathPatterns: []string{`^/v1/exports/[^/]+/content$`},
	}
	m, err := NewRouteMatcher(route)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, method, path string
		want               bool
	}{
		{"api.vendor.example", "GET", "/v1/items/42/content", true},
		{"API.Vendor.Example.", "get", "/v1/items/42", true},
		{"api.vendor.example", "GET", "/v1/exports/9/content", true},
		{"api.vendor.example", "GET", "/v1/exports/9/other", false},
		{"api.vendor.example", "POST", "/v1/items/42", false},
		{"api.vendor.example", "GET", "/v2/items/42", false},
		{"other.vendor.example", "GET", "/v1/items/42", false},
		{"api.vendor.example", "GET", "/v1/items/%2e%2e/%2e%2e/v2/x", false}, // normalized before matching
		{"api.vendor.example", "GET", "/v1/items/42;jsessionid=x/content", true},
	} {
		if got := m.Matches(tc.host, tc.method, tc.path); got != tc.want {
			t.Errorf("Matches(%q, %q, %q) = %t, want %t", tc.host, tc.method, tc.path, got, tc.want)
		}
	}
	// The same route inside a rule selects the same requests.
	rules, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{{Name: "parity", Action: config.ActionBlock, Route: route}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/items/42", "/v1/exports/9/content", "/v2/x", "/v1/items/42;p=1/content"} {
		meta := RequestMeta{Host: "api.vendor.example", Method: "GET", Path: path}
		if got, want := m.Matches(meta.Host, meta.Method, meta.Path), rules.Evaluate(meta).Matched(); got != want {
			t.Errorf("path %q: RouteMatcher=%t, rule=%t", path, got, want)
		}
	}
	var nilMatcher *RouteMatcher
	if nilMatcher.Matches("api.vendor.example", "GET", "/v1/items/1") {
		t.Fatal("nil matcher matched")
	}
	if _, err := NewRouteMatcher(config.RequestPolicyRoute{PathPatterns: []string{"("}}); err == nil {
		t.Fatal("an uncompilable pattern was accepted")
	}
}
