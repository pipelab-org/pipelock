// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const protocolChecker = `
prompt_injection_detection:
  checkers:
    local:
      type: protocol
      endpoint: http://127.0.0.1:9000/check
      allow_loopback_http: true
      revision: {checker: c/v1, model: m/v1, adapter: a/v1}
      timeout_ms: 1000
      max_request_bytes: 65536
      max_response_bytes: 4096
  surfaces:
    mcp_tool_result: {checker: local, mode: block}
`

const jevChecker = `
prompt_injection_detection:
  checkers:
    jev:
      type: jev
      model: jev-1.14.0
      api_key_env: JEV_TEST_KEY
      threshold: 0.8
      timeout_ms: 2000
      max_request_bytes: 65536
      max_response_bytes: 4096
      send_content_off_host: true
  surfaces:
    mcp_tool_description: {checker: jev, mode: warn}
`

func TestInjectionCheckersValid(t *testing.T) {
	cfg, err := LoadBytes([]byte(protocolChecker))
	if err != nil {
		t.Fatal(err)
	}
	sp := cfg.InjectionPolicy().For(InjectionSurfaceMCPToolResult)
	if sp.Checker != "local" || !sp.External() || sp.Mode != InjectionModeBlock {
		t.Fatalf("binding = %+v", sp)
	}
	if cc, ok := cfg.InjectionPolicy().Checker("local"); !ok || cc.SendsOffHost() {
		t.Fatalf("loopback checker = %+v ok=%v", cc, ok)
	}
	if !strings.Contains(cfg.PromptInjectionNotice(), "External injection checkers decide mcp_tool_result by local in block mode") {
		t.Fatalf("notice = %q", cfg.PromptInjectionNotice())
	}
	t.Setenv("JEV_TEST_KEY", "set")
	jev, err := LoadBytes([]byte(jevChecker))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jev.PromptInjectionNotice(), "Injection checker jev sends content from mcp_tool_description to api.typesafe.ai") {
		t.Fatalf("off-host disclosure = %q", jev.PromptInjectionNotice())
	}
	// An external checker's mode is not capped by the global wording switch.
	off := strings.Replace(protocolChecker, "prompt_injection_detection:\n", "prompt_injection_detection:\n  enabled: false\n", 1)
	if _, err := LoadBytes([]byte(off)); err != nil {
		t.Fatalf("external block with wording disabled rejected: %v", err)
	}
}

func TestInjectionCheckersRejects(t *testing.T) {
	r := func(from, to string) string { return strings.Replace(protocolChecker, from, to, 1) }
	j := func(from, to string) string { return strings.Replace(jevChecker, from, to, 1) }
	caFile := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(caFile, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ name, yaml, want string }{
		{"name_basic", r("    local:", "    basic:"), "cannot be \"basic\""},
		{"name_upper", r("    local:", "    Local:"), "checker names"},
		{"type", r("type: protocol", "type: other"), "must be protocol or jev"},
		{"timeout", r("timeout_ms: 1000", "timeout_ms: 0"), "timeout_ms"},
		{"request", r("max_request_bytes: 65536", "max_request_bytes: 99999999999"), "max_request_bytes"},
		{"response", r("max_response_bytes: 4096", "max_response_bytes: 0"), "max_response_bytes"},
		{"no_endpoint", r("      endpoint: http://127.0.0.1:9000/check\n", ""), "endpoint: required"},
		{"query", r("/check", "/check?x=1"), "query"},
		{"http_remote", r("http://127.0.0.1:9000/check", "http://checker.vendor.example/check"), "plain http"},
		{"http_no_optin", r("      allow_loopback_http: true\n", ""), "plain http"},
		{"peer_without_socket", r("      allow_loopback_http: true\n", "      allow_loopback_http: true\n      peer_uid: 0\n"), "peer_uid: requires unix_socket"},
		{"socket_relative", r("      endpoint: http://127.0.0.1:9000/check\n      allow_loopback_http: true\n", "      endpoint: http://localhost/check\n      unix_socket: run/c.sock\n"), "absolute path"},
		{"socket_host", r("      endpoint: http://127.0.0.1:9000/check\n      allow_loopback_http: true\n", "      endpoint: http://checker/check\n      unix_socket: /run/c.sock\n"), "http://localhost"},
		{"ca_on_http", r("      allow_loopback_http: true\n", "      allow_loopback_http: true\n      ca_file: /etc/ca.pem\n"), "ca_file: applies only to https"},
		{"ca_bad", r("http://127.0.0.1:9000/check\n      allow_loopback_http: true", "https://127.0.0.1:9000/check\n      ca_file: "+caFile), "no PEM certificates"},
		{"auth_env_name", r("      allow_loopback_http: true\n", "      allow_loopback_http: true\n      authorization_env: 1BAD\n"), "authorization_env"},
		{"no_revision", r("      revision: {checker: c/v1, model: m/v1, adapter: a/v1}\n", ""), "revision"},
		{"partial_revision", r("adapter: a/v1", "adapter: \"\""), "revision"},
		{"bad_score", r("      timeout_ms: 1000", "      score: {scale: s, calibration_id: c, min: 1, max: 0}\n      timeout_ms: 1000"), "score"},
		{"protocol_threshold", r("      timeout_ms: 1000", "      threshold: 0.5\n      timeout_ms: 1000"), "apply only to type jev"},
		{"remote_no_consent", r("http://127.0.0.1:9000/check\n      allow_loopback_http: true", "https://checker.vendor.example/check"), "send_content_off_host"},
		{"unknown_surface_checker", r("{checker: local, mode: block}", "{checker: missing, mode: block}"), "unknown checker"},
		{"watch_unknown", r("{checker: local, mode: block}", "{mode: block, watch: missing}"), "watch \"missing\": unknown checker"},
		{"watch_same", r("{checker: local, mode: block}", "{checker: local, mode: block, watch: local}"), "must differ"},
		{"watch_basic", r("{checker: local, mode: block}", "{checker: local, mode: block, watch: basic}"), "unknown checker"},
		{"jev_unpinned", j("model: jev-1.14.0", "model: jev-latest"), "moving aliases"},
		{"jev_preview", j("model: jev-1.14.0", "model: jev-preview"), "moving aliases"},
		{"jev_no_model", j("      model: jev-1.14.0\n", ""), "model: required"},
		{"jev_no_key", j("      api_key_env: JEV_TEST_KEY\n", ""), "api_key_env"},
		{"jev_threshold", j("threshold: 0.8", "threshold: 1.5"), "threshold"},
		{"jev_no_threshold", j("      threshold: 0.8\n", ""), "threshold"},
		{"jev_consent", j("      send_content_off_host: true\n", ""), "send_content_off_host"},
		{"jev_consent_false", j("send_content_off_host: true", "send_content_off_host: false"), "send_content_off_host"},
		{"jev_http", j("      model: jev-1.14.0", "      endpoint: http://api.vendor.example/v1\n      model: jev-1.14.0"), "must be https"},
		{"jev_revision", j("      model: jev-1.14.0", "      revision: {checker: c, model: m, adapter: a}\n      model: jev-1.14.0"), "do not apply to type jev"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadBytes([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestInjectionCheckersConsentForms(t *testing.T) {
	remote := strings.Replace(protocolChecker, "http://127.0.0.1:9000/check\n      allow_loopback_http: true", "https://checker.vendor.example/check", 1)
	for _, tt := range []struct {
		form string
		ok   bool
	}{
		{"", false},
		{"      send_content_off_host:\n", false},
		{"      send_content_off_host: null\n", false},
		{"      send_content_off_host: false\n", false},
		{"      send_content_off_host: true\n", true},
	} {
		y := strings.Replace(remote, "      timeout_ms: 1000", tt.form+"      timeout_ms: 1000", 1)
		if _, err := LoadBytes([]byte(y)); (err == nil) != tt.ok {
			t.Fatalf("form %q: err=%v", tt.form, err)
		}
	}
}

func TestInjectionCheckersHashAndWarnings(t *testing.T) {
	base, err := LoadBytes([]byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JEV_TEST_KEY", "value-one")
	a, err := LoadBytes([]byte(jevChecker))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JEV_TEST_KEY", "value-two")
	b, err := LoadBytes([]byte(jevChecker))
	if err != nil {
		t.Fatal(err)
	}
	if a.CanonicalPolicyHash() != b.CanonicalPolicyHash() || a.InjectionPolicy().Digest() != b.InjectionPolicy().Digest() {
		t.Fatal("credential value entered the policy hash")
	}
	if a.CanonicalPolicyHash() == base.CanonicalPolicyHash() {
		t.Fatal("checker definition did not change the hash")
	}
	for _, change := range [][2]string{
		{"threshold: 0.8", "threshold: 0.7"},
		{"model: jev-1.14.0", "model: jev-1.13.0"},
		{"api_key_env: JEV_TEST_KEY", "api_key_env: JEV_OTHER"},
		{"timeout_ms: 2000", "timeout_ms: 3000"},
		{"max_response_bytes: 4096", "max_response_bytes: 8192"},
	} {
		c, err := LoadBytes([]byte(strings.Replace(jevChecker, change[0], change[1], 1)))
		if err != nil {
			t.Fatal(err)
		}
		if c.CanonicalPolicyHash() == a.CanonicalPolicyHash() || c.InjectionPolicy().Digest() == a.InjectionPolicy().Digest() {
			t.Fatalf("%s did not change the hash", change[1])
		}
		if ws := ValidateReload(a, c); !hasField(ws, "prompt_injection_detection.checkers.jev") {
			t.Fatalf("%s: no reload warning: %+v", change[1], ws)
		}
	}
	// Unset credential and unused definition warn, never fail.
	if err := os.Unsetenv("JEV_TEST_KEY"); err != nil {
		t.Fatal(err)
	}
	unused := strings.Replace(jevChecker, "    mcp_tool_description: {checker: jev, mode: warn}\n", "    mcp_tool_result: {mode: block}\n", 1)
	cfg, err := LoadBytes([]byte(unused))
	if err != nil {
		t.Fatal(err)
	}
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatal(err)
	}
	var unset, unreferenced bool
	for _, w := range warnings {
		unset = unset || strings.Contains(w.Message, "JEV_TEST_KEY is not set")
		unreferenced = unreferenced || strings.Contains(w.Message, "no surface selects or watches it")
		if strings.Contains(w.Message, "value-") {
			t.Fatal("warning leaked a credential value")
		}
	}
	if !unset || !unreferenced {
		t.Fatalf("warnings = %+v", warnings)
	}
	// Clone does not alias checker definitions.
	clone := a.Clone()
	*clone.PromptInjectionDetection.Checkers["jev"].Threshold = 0.1
	if *a.PromptInjectionDetection.Checkers["jev"].Threshold != 0.8 {
		t.Fatal("clone aliases checker threshold")
	}
}

func hasField(ws []ReloadWarning, field string) bool {
	for _, w := range ws {
		if w.Field == field {
			return true
		}
	}
	return false
}
