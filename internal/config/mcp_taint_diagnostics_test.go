// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestMCPTaintDiagnostics_ConfigAndReload(t *testing.T) {
	for _, tc := range []struct {
		name, body, recorder string
	}{
		{"omitted", "", "no persistent taint recorder"},
		{"null", "taint: {enabled: null}\nsession_profiling: {enabled: null}\nmcp_session_binding: {listener_require_state_token: null}\n", "no persistent taint recorder"},
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
					"taint.mcp_recovery": {"inline terminal approval is unavailable", "admin invocation task/trust grants are rejected", "taint.trust_overrides", "recorded origin URL", "mutable identity sessions"},
				}
				if cfg.MCPSessionBinding.ListenerRequireStateToken != nil && *cfg.MCPSessionBinding.ListenerRequireStateToken {
					want["taint.mcp_listener"] = append(want["taint.mcp_listener"], "listener_require_state_token requires verified caller identity")
				}
				for _, w := range cfg.MCPTaintDiagnostics() {
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
