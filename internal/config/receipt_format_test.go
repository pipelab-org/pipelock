// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestLoadReceiptFormat(t *testing.T) {
	for _, tc := range []struct {
		name, fields, other, want, wantErr string
		useDeferDefault                    bool
	}{
		{name: "omitted"},
		{name: "null", fields: "  receipt_format: null\n"},
		{name: "blank", fields: "  receipt_format:\n"},
		{name: "explicit legacy", fields: "  receipt_format: legacy\n", want: ReceiptFormatLegacy},
		{name: "explicit v3", fields: "  receipt_format: v3\n", want: ReceiptFormatV3},
		{name: "invalid", fields: "  receipt_format: other\n", wantErr: "must be omitted, legacy, or v3"},
		{name: "multiple chains", fields: "  receipt_format: v3\n  receipt_chains: 2\n", wantErr: "requires at most one"},
		{name: "manager default", fields: "  receipt_format: v3\n", useDeferDefault: true, wantErr: "does not yet support deferred holds"},
		{name: "manager", fields: "  receipt_format: v3\n", other: "defer:\n  enabled: true\n", wantErr: "does not yet support deferred holds"},
		{name: "policy action", fields: "  receipt_format: v3\n", other: "mcp_tool_policy:\n  action: defer\n", wantErr: "does not yet support deferred holds"},
		{name: "policy rule", fields: "  receipt_format: v3\n", other: "mcp_tool_policy:\n  rules:\n    - action: defer\n", wantErr: "does not yet support deferred holds"},
		{name: "redirect action", fields: "  receipt_format: v3\n", other: "mcp_tool_policy:\n  action: redirect\n", wantErr: "does not yet support redirect rules"},
		{name: "dashboard snapshot", fields: "  receipt_format: v3\n", other: "dashboard_snapshot:\n  enabled: true\n", wantErr: "dashboard_snapshot requires receipt_format: legacy"},
		{name: "evidence health", fields: "  receipt_format: v3\n  evidence_health:\n    enabled: true\n", wantErr: "flight_recorder.evidence_health requires receipt_format: legacy"},
		{name: "anchor", fields: "  receipt_format: v3\n  anchor:\n    local_log: evidence.log\n", wantErr: "flight_recorder.anchor requires receipt_format: legacy"},
		{name: "redirect rule", fields: "  receipt_format: v3\n", other: "mcp_tool_policy:\n  rules:\n    - action: redirect\n", wantErr: "does not yet support redirect rules"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := tc.other
			if !tc.useDeferDefault && !strings.HasPrefix(other, "defer:") {
				other += "defer:\n  enabled: false\n"
			}
			cfg, err := LoadBytes([]byte("flight_recorder:\n  enabled: true\n  dir: evidence\n  signing_key_path: signer.key\n" + tc.fields + other))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadBytes error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantEffective := tc.want
			if wantEffective == "" {
				wantEffective = ReceiptFormatLegacy
			}
			if got := cfg.FlightRecorder.EffectiveReceiptFormat(); got != wantEffective {
				t.Fatalf("effective receipt format = %q, want %q", got, wantEffective)
			}
			if got := cfg.FlightRecorder.ReceiptFormat; got != tc.want {
				t.Fatalf("receipt format = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateReceiptV3RequiresRecorder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove func(*FlightRecorder)
	}{
		{"enabled", func(fr *FlightRecorder) { fr.Enabled = false }},
		{"directory", func(fr *FlightRecorder) { fr.Dir = "" }},
		{"signing key", func(fr *FlightRecorder) { fr.SigningKeyPath = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Defer.Enabled = false
			cfg.FlightRecorder.Enabled = true
			cfg.FlightRecorder.Dir = t.TempDir()
			cfg.FlightRecorder.SigningKeyPath = "signer.key"
			tc.remove(&cfg.FlightRecorder)
			if err := cfg.ValidateReceiptV3(); err == nil || !strings.Contains(err.Error(), "requires flight_recorder.enabled, dir, and signing_key_path") {
				t.Fatalf("ValidateReceiptV3 error = %v", err)
			}
		})
	}
}

func TestValidateReceiptV3AgentPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy MCPToolPolicy
		want   string
	}{
		{"redirect action", MCPToolPolicy{Action: ActionRedirect}, ".action"},
		{"defer action", MCPToolPolicy{Action: ActionDefer}, ".action"},
		{"redirect rule", MCPToolPolicy{Rules: []ToolPolicyRule{{Action: ActionRedirect}}}, ".rules[0].action"},
		{"defer rule", MCPToolPolicy{Rules: []ToolPolicyRule{{Action: ActionDefer}}}, ".rules[0].action"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Defer.Enabled = false
			cfg.FlightRecorder.Enabled = true
			cfg.FlightRecorder.Dir = t.TempDir()
			cfg.FlightRecorder.SigningKeyPath = "signer.key"
			cfg.Agents = map[string]AgentProfile{"test": {MCPToolPolicy: &tc.policy}}
			want := "agents.test.mcp_tool_policy" + tc.want
			if err := cfg.ValidateReceiptV3(); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("ValidateReceiptV3 error = %v, want %s", err, want)
			}
		})
	}
}
