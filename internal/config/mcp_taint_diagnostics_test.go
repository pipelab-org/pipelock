// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"strings"
	"testing"
)

func TestMCPTaintDiagnostics_ConfigAndReload(t *testing.T) {
	for _, tc := range []struct {
		name, body, recorder string
	}{
		{"omitted", "", "no session taint recorder"},
		{"null", "taint: {enabled: null}\nsession_profiling: {enabled: null}\nmcp_session_binding: {listener_require_state_token: null}\n", "no session taint recorder"},
		{"false", "taint: {enabled: false}\nsession_profiling: {enabled: false}\nmcp_session_binding: {listener_require_state_token: false}\n", "taint is disabled"},
		{"true", "taint: {enabled: true}\nsession_profiling: {enabled: true}\nmcp_session_binding: {listener_require_state_token: true}\n", "invocation-scoped recorder"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			before := cfg.CanonicalPolicyHash()
			for _, phase := range []string{"first_load", "unrelated_reload", "changed_reload", "restored_reload"} {
				wantRecorder := tc.recorder
				switch phase {
				case "unrelated_reload":
					cfg.Logging.Format = "json"
				case "changed_reload":
					cfg.Taint.Enabled = false
					wantRecorder = "taint is disabled"
				case "restored_reload":
					cfg, err = LoadBytes([]byte(tc.body))
					if err != nil {
						t.Fatal(err)
					}
				}
				_, err := cfg.ValidateWithWarnings()
				if err != nil {
					t.Fatal(err)
				}
				want := map[string][]string{
					"taint.mcp_recorder": {wantRecorder, "config-only"},
					"taint.mcp_listener": {"authenticated principal", "legacy", "2026-07-28", "request-local only", "NOT active", "verified caller identity", "shared listener bearer"},
					"taint.mcp_origin":   {"origin is undeclared", "internal_generated", "no corresponding CLI flag", "taint.trusted_mcp_servers", "future clean observations only"},
					"taint.mcp_recovery": {"inline terminal approval is unavailable", "runtime trust grants are rejected for all", "taint.trust_overrides", "record no origin URL", "pipelock run applies it on reload", "reads taint config only at startup"},
				}
				if cfg.MCPSessionBinding.ListenerRequireStateToken != nil && *cfg.MCPSessionBinding.ListenerRequireStateToken {
					want["taint.mcp_listener"] = append(want["taint.mcp_listener"], "listener_require_state_token requires verified caller identity")
				}
				for _, w := range cfg.MCPTaintDiagnostics() {
					if strings.Contains(w.Message, "persistent") {
						t.Errorf("%s implies restart persistence", w.Field)
					}
					for _, fragment := range want[w.Field] {
						if !strings.Contains(w.Message, fragment) {
							t.Errorf("%s %s missing %q: %s", phase, w.Field, fragment, w.Message)
						}
					}
					delete(want, w.Field)
				}
				if len(want) != 0 {
					t.Fatalf("%s diagnostics never ran: %v", phase, want)
				}
			}
			if cfg.CanonicalPolicyHash() != before {
				t.Fatal("diagnostics changed policy identity")
			}
		})
	}
	var absent *Config
	if absent.MCPTaintDiagnostics() != nil {
		t.Fatal("nil config produced diagnostics")
	}
}

func TestMCPTaintDiagnostics_RecoveryParity(t *testing.T) {
	cfg := Defaults()
	var guidance string
	for _, d := range cfg.MCPTaintDiagnostics() {
		if d.Field == "taint.mcp_recovery" {
			guidance = d.Message
		}
	}
	docs, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	// Doctor, explain and the dashboard serve this canonical guidance. The docs
	// must retain the same paragraph without implying a runtime log producer.
	if guidance != MCPTaintRecoveryGuidance || guidance == "" || !strings.Contains(string(docs), guidance) {
		t.Fatal("configuration recovery guidance and docs differ")
	}
	for _, want := range []string{"Every MCP session", "runtime trust grants are rejected for all", "action-scoped taint.trust_overrides entry without source_match", "pipelock run applies it on reload", "standalone pipelock mcp proxy reads taint config only at startup"} {
		if !strings.Contains(guidance, want) {
			t.Errorf("recovery omitted %q", want)
		}
	}
}

func TestMCPTaintDiagnostics_DocsPreserveHeadlessAndHTTPOverrideScope(t *testing.T) {
	docs, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(string(docs)), " ")
	start := strings.Index(text, "### Common taint decisions")
	end := strings.Index(text, "### Trust overrides")
	if start < 0 || end <= start {
		t.Fatal("common taint documentation missing")
	}
	section := text[start:end]
	for _, want := range []string{
		"the agent sends chat requests through the forward proxy",
		"When taint policy returns `decision: \"ask\"`, Pipelock can only prompt an operator if it was started with an interactive terminal.",
		"The prompt appears in the terminal running Pipelock and accepts allow/block input.",
		"In headless deployments such as Docker or Kubernetes, there is no terminal to ask, so `ask` fails closed and blocks; configure an allowlist, a narrow trust override, or `taint.policy: permissive` during tuning, then retry the request.",
		"Configured overrides accept risk only within their matching scope and expiry (for MCP, only the action scope can match)",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("common taint guidance omitted %q", want)
		}
	}
	headless := strings.Index(section, "When taint policy returns")
	mcp := strings.Index(section, MCPTaintRecoveryGuidance)
	if headless < 0 || mcp <= headless {
		t.Error("generic headless guidance must precede the unchanged MCP-specific paragraph")
	}
}
