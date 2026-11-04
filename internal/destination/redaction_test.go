// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"strings"
	"testing"
)

func TestRedactURLContent(t *testing.T) {
	t.Parallel()
	// Built at runtime so no credential-shaped literal sits in source.
	secret := "payload" + "canary"
	cases := []struct {
		raw      string
		keepPath bool
		want     string
	}{
		{"", false, ""},
		{"https://user:" + secret + "@api.vendor.example:8443/" + secret + "?q=" + secret + "#" + secret, false, "https://api.vendor.example:8443"},
		{"https://api.vendor.example/v1/items?q=" + secret, true, "https://api.vendor.example/v1/items"},
		{"api.vendor.example:443", false, "api.vendor.example:443"},
		{"localhost:8080", false, "localhost:8080"},
		{"litellm:4000", false, "[redacted-url]"},
		{"data:123", false, "[redacted-url]"},
		{"ftp://files.vendor.example/" + secret, false, "[redacted-url]"},
		{"https://[::1]:443/" + secret, false, "https://[::1]:443"},
		{"https://[fe80::1%25eth0]/", false, "[redacted-url]"},
		{"https://api.vendor.example:0/", false, "[redacted-url]"},
		{"https://api.vendor.example:99999/", false, "[redacted-url]"},
		{"https://api.vendor.example:/", false, "[redacted-url]"},
		{"https://bad_label.vendor.example/", false, "[redacted-url]"},
		{"https://-bad.vendor.example/", false, "[redacted-url]"},
		{"https://" + strings.Repeat("a", 64) + ".example/", false, "[redacted-url]"},
	}
	for _, tc := range cases {
		if got := RedactURLContent(tc.raw, tc.keepPath); got != tc.want {
			t.Errorf("RedactURLContent(%q, %v) = %q, want %q", tc.raw, tc.keepPath, got, tc.want)
		}
		if strings.Contains(RedactURLContent(tc.raw, false), secret) {
			t.Errorf("RedactURLContent(%q) kept request content", tc.raw)
		}
	}
}

func TestRedactURLTarget(t *testing.T) {
	t.Parallel()
	secret := "payload" + "canary"
	cases := []struct{ raw, want string }{
		{"mcp://tools-server/tools/list", "mcp://tools-server"},
		{"https://api.vendor.example/" + secret + "?q=" + secret, "https://api.vendor.example"},
		{"wss://api.vendor.example:8443/socket?" + secret, "wss://api.vendor.example:8443"},
		{"/fetch?url=" + secret, "[redacted-url]"},
		{"%zz", "[redacted-url]"},
		{"https://[fe80::1%25eth0]/" + secret, "[redacted-url]"},
	}
	for _, tc := range cases {
		got := RedactURLTarget(tc.raw)
		if got != tc.want {
			t.Errorf("RedactURLTarget(%q) = %q, want %q", tc.raw, got, tc.want)
		}
		if strings.Contains(got, secret) {
			t.Errorf("RedactURLTarget(%q) kept request content: %q", tc.raw, got)
		}
	}
}
