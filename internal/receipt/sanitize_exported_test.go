// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"net/url"
	"strings"
	"testing"
)

// SanitizeTarget and CleanOrRedacted are the exported pre-sign sanitization
// boundary that internal/contract/proxydecision reuses instead of duplicating
// this logic (#676), plus internal/cli explain rendering. Production callers stamp their results into a SIGNED payload, so the guarantee those
// callers depend on is that the returned value is DLP-clean under the same
// predicate they passed in. These tests assert that property directly rather
// than asserting a fixed output string, which would only restate the
// implementation.

// exportedClean adapts dlpLike to the plain func(string) bool that the
// exported wrappers accept. true means clean.
func exportedClean(secrets ...string) func(string) bool {
	return dlpLike(secrets...)
}

func TestSanitizeTargetExportedOutputIsClean(t *testing.T) {
	t.Parallel()

	const secret = "AKIA" + "IOSFODNN7EXAMPLE"
	// A host label cannot carry uppercase, so the host case needs the lowered
	// form AND the predicate has to flag it. Without both, the raw target is
	// already clean, the sanitizer does nothing, and the subtest passes while
	// the secret survives. That exact subtest was vacuous before this guard.
	lowered := strings.ToLower(secret)

	tests := []struct {
		name string
		// target is the input. secretForm is the byte sequence that must not
		// survive; empty means the case is a deliberately-clean control.
		target     string
		secretForm string
	}{
		{"userinfo credential", "https://user:" + secret + "@api.vendor.example/v1/things", secret},
		{"query value secret", "https://api.vendor.example/v1?token=" + secret, secret},
		{"secret split across query values", "https://api.vendor.example/v1?a=" + secret[:10] + "&b=" + secret[10:], secret},
		{"path segment secret", "https://api.vendor.example/v1/" + secret + "/read", secret},
		{"fragment secret", "https://api.vendor.example/v1#" + secret, secret},
		{"secret in host label", "https://" + lowered + ".vendor.example/v1", lowered},
		{"connect authority carrying secret", secret + ".vendor.example:443", secret},
		{"mcp tool name carrying secret", "@vendor/" + secret, secret},
		{"connect authority", "api.vendor.example:443", ""},
		{"mcp tool name", "@vendor/integrity_checker", ""},
		{"clean destination is preserved", "https://api.vendor.example", ""},
		{"empty target", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			clean := exportedClean(secret, lowered)

			// Establish the case is meaningful before trusting its result. A
			// secret-bearing input the predicate reports as already clean
			// exercises nothing, and the assertions below would pass anyway.
			if tt.secretForm != "" && clean(tt.target) {
				t.Fatalf("fixture is vacuous: raw target %q is already clean under the predicate, so this case tests nothing", tt.target)
			}

			got := SanitizeTarget(tt.target, clean)

			if !clean(got) {
				t.Fatalf("SanitizeTarget(%q) = %q, which is NOT DLP-clean; a signed receipt would carry the secret", tt.target, got)
			}
			if tt.secretForm != "" && strings.Contains(got, tt.secretForm) {
				t.Fatalf("SanitizeTarget(%q) = %q, still contains the secret verbatim", tt.target, got)
			}
			if tt.secretForm == "" && got != tt.target {
				t.Fatalf("SanitizeTarget(%q) = %q, want a clean target preserved byte for byte", tt.target, got)
			}
		})
	}
}

func TestSanitizeTargetExportedDropsCleanURLContent(t *testing.T) {
	t.Parallel()
	secret := strings.Join([]string{"unrecognized", "credential"}, "-")
	target := "https://" + url.UserPassword("user", secret).String() +
		"@api.vendor.example:8443/" + secret + "?key=" + secret + "#" + secret
	for _, clean := range []func(string) bool{nil, func(string) bool { return true }} {
		got := SanitizeTarget(target, clean)
		if got != "https://api.vendor.example:8443" || strings.Contains(got, secret) {
			t.Fatalf("URL content survived: %q", got)
		}
	}
}

func TestCleanOrRedactedExported(t *testing.T) {
	t.Parallel()

	const secret = "AKIA" + "IOSFODNN7EXAMPLE"

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"clean rule label is preserved", "dlp.aws_access_key_id", "dlp.aws_access_key_id"},
		{"label echoing matched bytes is redacted", "matched " + secret, redactedTarget},
		{"bare secret is redacted", secret, redactedTarget},
		{"empty value is clean", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			clean := exportedClean(secret)
			got := CleanOrRedacted(tt.value, clean)

			if got != tt.want {
				t.Fatalf("CleanOrRedacted(%q) = %q, want %q", tt.value, got, tt.want)
			}
			if !clean(got) {
				t.Fatalf("CleanOrRedacted(%q) = %q, which is NOT DLP-clean", tt.value, got)
			}
		})
	}
}

// Same deliberate fail-direction as SanitizeTarget's nil case: redaction off
// means the non-URL field is signed as sent.
func TestCleanOrRedactedExportedNilPredicatePassesThrough(t *testing.T) {
	t.Parallel()

	values := []string{"AKIA" + "IOSFODNN7EXAMPLE", "dlp.aws_access_key_id", ""}
	for _, value := range values {
		if got := CleanOrRedacted(value, nil); got != value {
			t.Errorf("CleanOrRedacted(%q, nil) = %q, want the value unchanged when redaction is off", value, got)
		}
	}
}

// The target field also carries MCP protocol URLs. Its value is reduced using
// the same authority validation as audit logs without changing its scheme.
func TestSanitizeTargetProtocolDestinations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ target, want string }{
		{"mcp://tools.vendor.example:8443/tool?arg=value#fragment", "mcp://tools.vendor.example:8443"},
		{"wss://api.vendor.example:9443/socket?ref=value", "wss://api.vendor.example:9443"},
		{"https://[2001:db8::1]:8443/path?ref=value", "https://[2001:db8::1]:8443"},
		{"//api.vendor.example/path?ref=value", "api.vendor.example"},
		{"https://api.vendor.example:70000/path", "[redacted-url]"},
		{"https://api.vendor.example/%zz", "[redacted-url]"},
		{"https://[invalid]:443/path", "[redacted-url]"},
		{"https://" + strings.Repeat("a", 254) + "/path", "[redacted-url]"},
		{"https://has_underscore.example/path", "[redacted-url]"},
		// Diagnostic output reads unsigned logs: relative targets keep their context.
		{"/path?ref=value", "/path?ref=value"},
		// Opaque identifiers and bare authorities hold no URL delimiter.
		{"api.vendor.example:443", "api.vendor.example:443"},
		{"read_file", "read_file"},
		{"tasks/get", "tasks/get"},
		// Operator-named MCP servers are identifiers, not DNS hosts.
		{"mcp://my_server/response", "mcp://my_server/response"},
		{"mcp://my_server/tools/list", "mcp://my_server/tools/list"},
		{"mcp://npx:fs/response", "mcp://npx:fs/response"},
		{"mcp://user:pw@api.vendor.example/response", "mcp://api.vendor.example"},
		{"mcp://srv/extra/response", "mcp://srv"},
		{"mcp://Code Assistant/response", "[redacted-url]"},
		{"mcp:///response", "[redacted-url]"},
		{sessionOpenTarget, sessionOpenTarget},
		{sessionHeartbeatTarget, sessionHeartbeatTarget},
		{sessionCloseTarget, sessionCloseTarget},
	} {
		t.Run(tc.target, func(t *testing.T) {
			if got := SanitizeTarget(tc.target, nil); got != tc.want {
				t.Fatalf("target=%q want=%q", got, tc.want)
			}
		})
	}
}

// A signed target must never keep request content. Inbound server-side request
// URLs are origin-form ("/fetch?url=..."): no scheme or host precedes the path,
// so the whole value is request content and reduces to the marker.
func TestSanitizeSignedTargetReducesRelativeURLs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ target, want string }{
		{"/fetch?url=https%3A%2F%2Fapi.vendor.example%2F%3Fref%3Dvalue", "[redacted-url]"},
		{"/v1/hooks/opaque-segment", "[redacted-url]"},
		{"api.vendor.example/path?ref=value", "[redacted-url]"},
		{"api.vendor.example/path#fragment", "[redacted-url]"},
		// A scheme with no authority names no destination.
		{"https:/opaque-segment", "[redacted-url]"},
		{"https:/opaque/segment", "[redacted-url]"},
		{"mcp:/opaque-segment", "[redacted-url]"},
		{"https:opaque-segment/more", "[redacted-url]"},
		{"HTTP:opaque-segment", "[redacted-url]"},
		{"wss:opaque-segment", "[redacted-url]"},
		{"https:", "[redacted-url]"},
		// Values url.Parse rejects are classified from their scheme text.
		{"https:/%zz", "[redacted-url]"},
		{"wss:%zz/more", "[redacted-url]"},
		{"mcp:/%zz", "[redacted-url]"},
		{"server:%zz", "server:%zz"},
		// Colon-bearing identifiers parse as opaque, not path-absolute.
		{"server:read_file", "server:read_file"},
		{"localhost:8080", "localhost:8080"},
		// Absolute URLs, identifiers and exempt shapes behave as SanitizeTarget does.
		{"https://api.vendor.example/path?ref=value", "https://api.vendor.example"},
		{"api.vendor.example:443", "api.vendor.example:443"},
		{"read_file", "read_file"},
		{"tasks/get", "tasks/get"},
		{"mcp://my_server/tools/list", "mcp://my_server/tools/list"},
		{sessionOpenTarget, sessionOpenTarget},
	} {
		t.Run(tc.target, func(t *testing.T) {
			if got := SanitizeSignedTarget(tc.target, nil); got != tc.want {
				t.Fatalf("target=%q want=%q", got, tc.want)
			}
		})
	}
}

// Signed targets keep scheme, host and port, so a secret in the retained host
// depends on the DLP predicate the production emitters pass.
func TestSanitizeSignedTargetAppliesPredicateToRetainedHost(t *testing.T) {
	t.Parallel()
	clean := func(s string) bool { return !strings.Contains(s, "secret") }
	for _, tc := range []struct{ target, want string }{
		{"https://secret-host.example/path?ref=value", "[redacted-target]"},
		{"secret-host.example:443", "[redacted-target]"},
		{"https://api.vendor.example/secret-path", "https://api.vendor.example"},
	} {
		if got := SanitizeSignedTarget(tc.target, clean); got != tc.want {
			t.Fatalf("SanitizeSignedTarget(%q) = %q, want %q", tc.target, got, tc.want)
		}
	}
}
