// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOAuthAuthorizationEndpointConfig(t *testing.T) {
	for _, tt := range []struct {
		name, setting string
		count         int
		invalid       bool
	}{
		{name: "omitted"},
		{name: "null", setting: "oauth_authorization_endpoints: null"},
		{name: "blank", setting: "oauth_authorization_endpoints:"},
		{name: "empty", setting: "oauth_authorization_endpoints: []"},
		{name: "false is not a grant", setting: "oauth_authorization_endpoints: false", invalid: true},
		{name: "true is not a grant", setting: "oauth_authorization_endpoints: true", invalid: true},
		{name: "exact endpoint", setting: "oauth_authorization_endpoints:\n      - host: auth.vendor.example\n        path: /oauth/authorize", count: 1},
		{name: "wildcard", setting: "oauth_authorization_endpoints:\n      - host: '*.vendor.example'\n        path: /oauth/authorize", invalid: true},
		{name: "invalid path", setting: "oauth_authorization_endpoints:\n      - host: auth.vendor.example\n        path: /../authorize", invalid: true},
		{name: "duplicate", setting: "oauth_authorization_endpoints:\n      - host: auth.vendor.example\n        path: /oauth/authorize\n      - host: auth.vendor.example\n        path: /oauth/authorize", invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			data := "mode: balanced\nfetch_proxy:\n  monitoring:\n    " + tt.setting + "\n"
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if tt.invalid {
				if err == nil {
					t.Fatal("invalid grant accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.FetchProxy.Monitoring.OAuthAuthorizationEndpoints) != tt.count {
				t.Fatal("wrong effective grants")
			}
		})
	}
}

func TestOAuthAuthorizationEndpointPolicyLifecycle(t *testing.T) {
	old := Defaults()
	if err := old.Validate(); err != nil {
		t.Fatal(err)
	}
	active := old.Clone()
	active.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = []OAuthAuthorizationEndpoint{{Host: "auth.vendor.example", Path: "/oauth/authorize", Reason: "native client", Owner: "operator", Expires: time.Now().UTC().AddDate(0, 0, 2).Format(time.DateOnly)}}
	if err := active.Validate(); err != nil {
		t.Fatal(err)
	}
	hasWarning := func(a, b *Config, want bool) {
		t.Helper()
		found := false
		for _, w := range ValidateReload(a, b) {
			if w.Field == "fetch_proxy.monitoring.oauth_authorization_endpoints" && w.Disposition != ReloadWarningDispositionAdvisory {
				found = true
			}
		}
		if found != want {
			t.Fatalf("rejecting reload warning=%v want %v", found, want)
		}
	}
	hasWarning(old, active, true)
	hasWarning(active, active.Clone(), false)
	hasWarning(active, old, false)
	if old.CanonicalPolicyHash() == active.CanonicalPolicyHash() {
		t.Fatal("grant missing from policy identity")
	}
	metadata := active.Clone()
	metadata.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[0].Reason = "new explanation"
	if active.CanonicalPolicyHash() != metadata.CanonicalPolicyHash() {
		t.Fatal("metadata changed policy identity")
	}
	clone := active.Clone()
	clone.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[0].Host = "other.vendor.example"
	if active.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[0].Host != "auth.vendor.example" {
		t.Fatal("clone shares grants")
	}
	extended := active.Clone()
	extended.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[0].Expires = time.Now().UTC().AddDate(0, 0, 3).Format(time.DateOnly)
	hasWarning(active, extended, true)
	expired := active.Clone()
	expired.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[0].Expires = time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	warnings, err := expired.LapseExpiredScannerExceptions(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(expired.FetchProxy.Monitoring.OAuthAuthorizationEndpoints) != 0 || len(warnings) == 0 {
		t.Fatal("expired grant retained without diagnostics")
	}
	if expired.CanonicalPolicyHash() != old.CanonicalPolicyHash() {
		t.Fatal("lapsed grant changes effective identity")
	}
	invalid := active.Clone()
	invalid.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[0].Expires = "invalid"
	if _, err := invalid.LapseExpiredScannerExceptions(time.Now()); err == nil {
		t.Fatal("invalid expiry silently lapsed")
	}
	// Config loading and reload both use the same list, including unchanged and
	// revoked lists. No boolean enables a global exception.
	path := filepath.Join(t.TempDir(), "reload.yaml")
	for _, host := range []string{"auth.vendor.example", "auth.vendor.example", ""} {
		setting := "oauth_authorization_endpoints: []"
		if host != "" {
			setting = fmt.Sprintf("oauth_authorization_endpoints:\n      - host: %s\n        path: /oauth/authorize", host)
		}
		if err := os.WriteFile(path, []byte("mode: balanced\nfetch_proxy:\n  monitoring:\n    "+setting+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if (len(got.FetchProxy.Monitoring.OAuthAuthorizationEndpoints) > 0) != (host != "") {
			t.Fatal("reload list mismatch")
		}
	}
}

func TestOAuthAuthorizationEndpointValidation(t *testing.T) {
	for _, tt := range []struct {
		name  string
		entry OAuthAuthorizationEndpoint
	}{
		{"missing host", OAuthAuthorizationEndpoint{Path: "/oauth/authorize"}},
		{"host port", OAuthAuthorizationEndpoint{Host: "auth.vendor.example:8443", Path: "/oauth/authorize"}},
		{"bad expiry", OAuthAuthorizationEndpoint{Host: "auth.vendor.example", Path: "/oauth/authorize", Expires: "forever"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NormalizeOAuthAuthorizationEndpoints([]OAuthAuthorizationEndpoint{tt.entry}); err == nil || !strings.Contains(err.Error(), "oauth_authorization_endpoints") {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}

func TestOAuthAuthorizationEndpointOrderAndIdentity(t *testing.T) {
	a := Defaults()
	a.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = []OAuthAuthorizationEndpoint{{Host: "auth.vendor.example", Path: "/oauth/authorize"}, {Host: "login.vendor.example", Path: "/authorize"}}
	b := a.Clone()
	b.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[0], b.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[1] = b.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[1], b.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[0]
	if a.CanonicalPolicyHash() != b.CanonicalPolicyHash() {
		t.Fatal("endpoint order changes policy identity")
	}
	changed := a.Clone()
	changed.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[0].Path = "/other"
	if a.CanonicalPolicyHash() == changed.CanonicalPolicyHash() {
		t.Fatal("endpoint path missing from identity")
	}
}
