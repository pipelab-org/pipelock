// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestHooksBundleIntegrity(t *testing.T) {
	for _, tc := range []struct {
		name, mode, override string
		broken, deny         bool
	}{
		{"strict", "strict", "", true, true},
		{"strict blank", "strict", "  allow_degraded:\n", true, true},
		{"strict null", "strict", "  allow_degraded: null\n", true, true},
		{"strict false", "strict", "  allow_degraded: false\n", true, true},
		{"strict override", "strict", "  allow_degraded: true\n", true, false},
		{"balanced", "balanced", "", true, false},
		{"optional absent", "strict", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			rulesDir := filepath.Join(dir, "rules")
			if tc.broken {
				if err := os.MkdirAll(filepath.Join(rulesDir, "broken-bundle"), 0o750); err != nil {
					t.Fatal(err)
				}
			}
			cfg := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(cfg, []byte("version: 1\napi_allowlist: [api.vendor.example]\nmode: "+tc.mode+"\nrules:\n  rules_dir: "+rulesDir+"\n"+tc.override), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, host := range []string{"claude", "claude-exit", "cursor"} {
				t.Run(host, func(t *testing.T) {
					cmd := ClaudeCmd()
					args := []string{"hook", "--config", cfg}
					input := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
					if host == "claude-exit" {
						args = append(args, "--exit-code")
					}
					if host == "cursor" {
						cmd = CursorCmd()
						input = `{"hook_event_name":"beforeShellExecution","command":"ls"}`
					}
					var out, stderr strings.Builder
					cmd.SetOut(&out)
					cmd.SetErr(&stderr)
					cmd.SetIn(strings.NewReader(input))
					cmd.SetArgs(args)
					err := cmd.Execute()
					if host == "claude-exit" {
						want := 0
						if tc.deny {
							want = 2
						}
						if (err == nil && want != 0) || (err != nil && cliutil.ExitCodeOf(err) != want) {
							t.Fatalf("exit=%v want %d: %s", err, want, stderr.String())
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					var denied bool
					var reason string
					if host == "cursor" {
						var r cursorResponse
						if err := json.Unmarshal([]byte(out.String()), &r); err != nil {
							t.Fatal(err)
						}
						denied = r.Permission == decisionDeny
						reason = r.UserMessage
					} else {
						var r claudeCodeResponse
						if err := json.Unmarshal([]byte(out.String()), &r); err != nil {
							t.Fatal(err)
						}
						denied = r.HookSpecificOutput.PermissionDecision == decisionDeny
						reason = r.HookSpecificOutput.PermissionDecisionReason
					}
					if denied != tc.deny {
						t.Fatalf("denied=%v want %v: %s", denied, tc.deny, out.String())
					}
					if tc.deny && !strings.Contains(reason, "rule bundle integrity failure") {
						t.Fatalf("wrong denial: %s", reason)
					}
					if tc.broken && !strings.Contains(stderr.String(), "broken-bundle") {
						t.Fatalf("missing bundle diagnostic: %s", stderr.String())
					}
				})
			}
		})
	}
}
