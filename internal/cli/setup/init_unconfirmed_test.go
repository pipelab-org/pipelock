// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCmdUnconfirmedDiscovery(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		name := "human"
		if jsonOutput {
			name = "json"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			content := fmt.Sprintf(`{"mcpServers":{"wrapped":{"command":%q,"args":["mcp","proxy","--","node","server.js"]}}}`, self)
			if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			cmd := InitCmd()
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			args := []string{
				"--scan-home", home, "--output", filepath.Join(home, "init.yaml"),
				"--dry-run", "--skip-canary", "--skip-validate", "--no-auditor",
			}
			if jsonOutput {
				args = append(args, "--json")
			}
			cmd.SetArgs(args)
			// Init's existing scope is local setup, not routing verification.
			// Unconfirmed discovery must remain visible without changing that scope.
			if err := cmd.Execute(); err != nil {
				t.Fatalf("init failed: %v\n%s", err, errOut.String())
			}
			if jsonOutput {
				var result initResult
				if err := json.Unmarshal(out.Bytes(), &result); err != nil {
					t.Fatalf("invalid JSON: %v\n%s", err, out.String())
				}
				if result.Discover == nil || result.Discover.Protected != 0 || result.Discover.Unconfirmed != 1 || result.Discover.ServersFound != 1 {
					t.Fatalf("unexpected discovery summary: %+v", result.Discover)
				}
				return
			}
			for _, want := range []string{
				"1 server(s) have wrappers in checked files; actual client launches are unconfirmed.",
				"Protected:          0", "Unconfirmed:        1",
			} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("missing %q in output:\n%s", want, out.String())
				}
			}
		})
	}
}
