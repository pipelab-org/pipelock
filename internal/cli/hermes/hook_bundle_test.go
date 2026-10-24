// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookBundleIntegrity(t *testing.T) {
	for _, tc := range []struct {
		name, mode, override string
		broken, file, deny   bool
	}{
		{"strict", "strict", "", true, false, true},
		{"strict blank", "strict", "  allow_degraded:\n", true, false, true},
		{"strict null", "strict", "  allow_degraded: null\n", true, false, true},
		{"strict false", "strict", "  allow_degraded: false\n", true, false, true},
		{"strict override", "strict", "  allow_degraded: true\n", true, false, false},
		{"balanced", "balanced", "", true, false, false},
		{"optional absent", "strict", "", false, false, false},
		{"optional unavailable", "strict", "", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			rulesDir := filepath.Join(dir, "rules")
			if tc.broken {
				if err := os.MkdirAll(filepath.Join(rulesDir, "broken-bundle"), 0o750); err != nil {
					t.Fatal(err)
				}
			}
			if tc.file {
				// An unreadable rules store is an availability failure, never an
				// integrity one: the hook warns and scans the available policy.
				if err := os.WriteFile(rulesDir, []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(cfg, []byte("version: 1\napi_allowlist: [api.vendor.example]\nmode: "+tc.mode+"\nrules:\n  rules_dir: "+rulesDir+"\n"+tc.override), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := hookCmd()
			cmd.SetArgs([]string{"--config", cfg})
			cmd.SetIn(strings.NewReader(`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"ls"}}`))
			var out, stderr strings.Builder
			cmd.SetOut(&out)
			cmd.SetErr(&stderr)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			var r HookDecision
			if err := json.Unmarshal([]byte(out.String()), &r); err != nil {
				t.Fatal(err)
			}
			if (r.Decision == "block") != tc.deny {
				t.Fatalf("unexpected decision: %s", out.String())
			}
			if tc.deny && !strings.Contains(out.String(), "rule bundle integrity failure") {
				t.Fatalf("wrong denial: %s", out.String())
			}
			if tc.broken && !strings.Contains(stderr.String(), "broken-bundle") {
				t.Fatalf("missing warning: %s", stderr.String())
			}
			if tc.file && !strings.Contains(stderr.String(), "reading rules directory") {
				t.Fatalf("missing availability warning: %s", stderr.String())
			}
		})
	}
}
