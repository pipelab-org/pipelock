// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateExactRequestException(t *testing.T) {
	valid := RequestPolicyExactRequest{URL: "https://api.vendor.example/items/1/invite", Method: "POST", BodySHA256: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Owner: "operator", Reason: "approved access"}
	if err := ValidateRequestPolicyExactRequest(valid); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*RequestPolicyExactRequest)
	}{
		{"invalid URL", func(r *RequestPolicyExactRequest) { r.URL = "https://%" }},
		{"HTTP", func(r *RequestPolicyExactRequest) { r.URL = "http://api.vendor.example/a" }},
		{"userinfo", func(r *RequestPolicyExactRequest) { r.URL = "https://user@api.vendor.example/a" }},
		{"fragment", func(r *RequestPolicyExactRequest) { r.URL += "#f" }},
		{"wildcard", func(r *RequestPolicyExactRequest) { r.URL = "https://*.vendor.example/a" }},
		{"bodyless", func(r *RequestPolicyExactRequest) { r.Method = "GET" }},
		{"bad hash", func(r *RequestPolicyExactRequest) { r.BodySHA256 = strings.Repeat("g", 64) }},
		{"short hash", func(r *RequestPolicyExactRequest) { r.BodySHA256 = "aa" }},
		{"uppercase hash", func(r *RequestPolicyExactRequest) { r.BodySHA256 = strings.Repeat("A", 64) }},
		{"bad expiry", func(r *RequestPolicyExactRequest) { r.ExpiresAt = "tomorrow" }},
		{"owner", func(r *RequestPolicyExactRequest) { r.Owner = "" }},
		{"reason", func(r *RequestPolicyExactRequest) { r.Reason = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			tc.edit(&r)
			if err := ValidateRequestPolicyExactRequest(r); err == nil {
				t.Fatal("invalid approval accepted")
			}
		})
	}
	e := &RequestPolicyException{Requests: []RequestPolicyExactRequest{valid}}
	if err := validateRequestPolicyException("r", e); err != nil {
		t.Fatal(err)
	}
	e.Values = []string{"other"}
	if err := validateRequestPolicyException("r", e); err == nil {
		t.Fatal("mixed exception modes accepted")
	}
	e.Values = nil
	e.Requests[0].Method = "GET"
	if err := validateRequestPolicyException("r", e); err == nil {
		t.Fatal("invalid request accepted")
	}
}

func TestExactRequestExceptionLifecycle(t *testing.T) {
	r := RequestPolicyExactRequest{URL: "https://api.vendor.example/items/1/invite", Method: "POST", BodySHA256: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Owner: "operator", Reason: "approved access"}
	base := Defaults()
	base.RequestPolicy = RequestPolicy{Enabled: true, OnParseError: ActionBlock, OnOpaqueOperation: ActionBlock, Rules: []RequestPolicyRule{{Name: "sharing", Action: ActionBlock, Route: RequestPolicyRoute{Hosts: []string{"api.vendor.example"}, Methods: []string{"POST"}, PathPrefixes: []string{"/items/"}}, Except: &RequestPolicyException{Requests: []RequestPolicyExactRequest{r}}}}}
	if _, err := base.ValidateWithWarnings(); err != nil {
		t.Fatal(err)
	}
	clone := base.Clone()
	clone.RequestPolicy.Rules[0].Except.Requests[0].BodySHA256 = strings.Repeat("b", 64)
	if base.RequestPolicy.Rules[0].Except.Requests[0] != r {
		t.Fatal("clone changed original approval")
	}
	if base.CanonicalPolicyHash() == clone.CanonicalPolicyHash() {
		t.Fatal("approval change absent from policy hash")
	}
	for _, tc := range []struct {
		name string
		edit func(*Config)
		warn bool
	}{
		{"unchanged", func(*Config) {}, false},
		{"new digest", func(c *Config) { c.RequestPolicy.Rules[0].Except.Requests[0].BodySHA256 = strings.Repeat("b", 64) }, true},
		{"extended", func(c *Config) {
			c.RequestPolicy.Rules[0].Except.Requests[0].ExpiresAt = time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
		}, true},
		{"shortened", func(c *Config) {
			c.RequestPolicy.Rules[0].Except.Requests[0].ExpiresAt = time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
		}, false},
		{"revoked", func(c *Config) { c.RequestPolicy.Rules[0].Except = nil }, false},
		{"expired", func(c *Config) {
			c.RequestPolicy.Rules[0].Except.Requests[0].ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			updated := base.Clone()
			tc.edit(updated)
			var warnings []ReloadWarning
			appendExactRequestReloadWarnings(&warnings, base.RequestPolicy, updated.RequestPolicy)
			if (len(warnings) > 0) != tc.warn {
				t.Fatalf("warnings=%v want warning=%v", warnings, tc.warn)
			}
		})
	}
	var warnings []ReloadWarning
	appendExactRequestReloadWarnings(&warnings, RequestPolicy{}, base.RequestPolicy)
	if len(warnings) != 0 {
		t.Fatal("enabling a deny policy is a downgrade")
	}
}

func TestCanonicalExactRequestURL(t *testing.T) {
	valid := []struct {
		name string
		in   string
		want string
	}{
		{"already canonical", "https://api.vendor.example/items/1/invite", "https://api.vendor.example/items/1/invite"},
		{"uppercase scheme and host", "HTTPS://API.Vendor.EXAMPLE/Items", "https://api.vendor.example/Items"},
		{"default port elided", "https://api.vendor.example:443/a", "https://api.vendor.example/a"},
		{"nondefault port kept", "https://api.vendor.example:8443/a", "https://api.vendor.example:8443/a"},
		{"root path", "https://api.vendor.example/", "https://api.vendor.example/"},
		{"IPv6 brackets rebuilt", "https://[2001:DB8::1]/a", "https://[2001:db8::1]/a"},
		{"IPv6 default port elided", "https://[2001:db8::1]:443/a", "https://[2001:db8::1]/a"},
		{"IPv6 nondefault port kept", "https://[2001:DB8::1]:8443/a", "https://[2001:db8::1]:8443/a"},
		{"escaped slash spelling kept", "https://api.vendor.example/a%2Fb%2fc", "https://api.vendor.example/a%2Fb%2fc"},
		{"percent case kept", "https://api.vendor.example/%7euser/%7Euser", "https://api.vendor.example/%7euser/%7Euser"},
		{"dot segments kept", "https://api.vendor.example/a/../b/./c", "https://api.vendor.example/a/../b/./c"},
		{"query order and spelling kept", "https://api.vendor.example/a?b=2&a=%7e1&a=%7E1&a=1", "https://api.vendor.example/a?b=2&a=%7e1&a=%7E1&a=1"},
		{"explicit empty query kept", "https://api.vendor.example/a?", "https://api.vendor.example/a?"},
		{"valueless query kept", "https://api.vendor.example/a?flag", "https://api.vendor.example/a?flag"},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CanonicalExactRequestURL(tc.in)
			if !ok || got != tc.want {
				t.Fatalf("CanonicalExactRequestURL(%q) = %q, %v; want %q, true", tc.in, got, ok, tc.want)
			}
			again, ok := CanonicalExactRequestURL(got)
			if !ok || again != got {
				t.Fatalf("not idempotent: %q -> %q, %v", got, again, ok)
			}
		})
	}

	invalid := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"malformed", "https://%"},
		{"HTTP", "http://api.vendor.example/a"},
		{"relative", "/a"},
		{"no scheme", "api.vendor.example/a"},
		{"userinfo", "https://user@api.vendor.example/a"},
		{"userinfo with password", "https://user:pw@api.vendor.example/a"},
		{"opaque", "https:api.vendor.example/a"},
		{"fragment", "https://api.vendor.example/a#frag"},
		{"no path", "https://api.vendor.example"},
		{"no path with query", "https://api.vendor.example?x=1"},
		{"empty host", "https:///a"},
		{"port only host", "https://:443/a"},
	}
	for _, tc := range invalid {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			if got, ok := CanonicalExactRequestURL(tc.in); ok || got != "" {
				t.Fatalf("CanonicalExactRequestURL(%q) = %q, %v; want empty, false", tc.in, got, ok)
			}
		})
	}
}
