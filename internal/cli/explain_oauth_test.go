// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/url"
	"strings"
	"testing"
)

// An operator who adds a native OAuth grant and then explains the blocked
// authorization URL must see the verdict live GET traffic receives, not a block
// whose hint asks for the grant they already have.
func TestExplainCmd_NativeOAuthGrant(t *testing.T) {
	t.Parallel()
	state := "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789"
	authorize := func(redirect string) string {
		q := url.Values{"response_type": {"code"}, "client_id": {"native-client"}, "redirect_uri": {redirect}, "state": {state}}
		return "https://auth.vendor.example/oauth/authorize?" + q.Encode()
	}
	granted := writeConfig(t, "fetch_proxy:\n  monitoring:\n    oauth_authorization_endpoints:\n      - host: auth.vendor.example\n        path: /oauth/authorize\n")
	ungranted := writeConfig(t, "fetch_proxy:\n  monitoring:\n    oauth_authorization_endpoints: []\n")
	for _, tc := range []struct {
		name, config, target string
		allowed, note        bool
	}{
		{"granted loopback", granted, authorize("http://127.0.0.1:49152/callback"), true, true},
		{"no grant", ungranted, authorize("http://127.0.0.1:49152/callback"), false, false},
		{"granted remote callback", granted, authorize("https://app.vendor.example/callback"), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, _ := decodeExplainJSON(t, "--config", tc.config, tc.target)
			if report.Allowed != tc.allowed {
				t.Fatalf("allowed = %v, want %v: %s %s", report.Allowed, tc.allowed, report.Scanner, report.Reason)
			}
			notes := strings.Join(report.Notes, " ")
			if got := strings.Contains(notes, "Explained as GET") && strings.Contains(notes, "refused by entropy"); got != tc.note {
				t.Fatalf("GET note = %v, want %v: %s", got, tc.note, notes)
			}
		})
	}
}
