// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// splitRows are commands that must match their rule on every path: the
// rule, and whether the cursor preset leaves the rule at its warn default.
var splitRows = []struct {
	name, cmd, rule string
	presetWarns     bool
}{
	{"git clean -f -d", "git clean -f -d", ruleGit, false},
	{"git clean -d -f", "git clean -d -f", ruleGit, false},
	{"push a plus ref", "git push origin +main", ruleGit, false},
	{"npm i", "npm i left-pad", rulePkgInstall, true},
	{"pnpm add", "pnpm add left-pad", rulePkgInstall, true},
	{"mkfs -t", "mkfs -t ext4 /dev/sdb1", ruleDiskWipe, false},
	{"wipefs", "wipefs -a /dev/sdb", ruleDiskWipe, false},
	{"base64 to /bin/sh", "echo Zm9v | base64 -d | /bin/sh", ruleEncoded, false},
	{"chmod -R a+rwx", "chmod -R a+rwx /srv", rulePermissions, true},
	// The usual spellings, for the preset's warn default.
	{"npm install", "npm install left-pad", rulePkgInstall, true},
	{"chmod -R 777", "chmod -R 777 /srv", rulePermissions, true},
}

// TestSplitSpellings_ProxyRequest checks each row as the MCP proxy sees it, a
// tools/call line, with the rules the hooks use by default, with the strict
// preset and with the cursor preset.
func TestSplitSpellings_ProxyRequest(t *testing.T) {
	preset := func(name string) *Config {
		t.Helper()
		path, err := filepath.Abs(filepath.Join("..", "..", "..", "configs", name))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		pc := New(cfg.MCPToolPolicy)
		if pc == nil {
			t.Fatalf("%s tool policy is disabled", name)
		}
		return pc
	}
	configs := []struct {
		name   string
		pc     *Config
		preset bool
	}{
		{"default", New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()}), false},
		{"strict", preset("strict.yaml"), false},
		{"cursor", preset("cursor.yaml"), true},
	}
	for _, c := range configs {
		for _, tt := range splitRows {
			t.Run(c.name+"/"+tt.name, func(t *testing.T) {
				line, err := json.Marshal(map[string]any{
					"jsonrpc": "2.0", "id": 1, "method": "tools/call",
					"params": map[string]any{"name": "run_command", "arguments": map[string]string{"command": tt.cmd}},
				})
				if err != nil {
					t.Fatal(err)
				}
				v := c.pc.CheckRequest(line)
				want := config.ActionBlock
				if c.preset && tt.presetWarns {
					want = config.ActionWarn
				}
				if !v.Matched || !slices.Contains(v.Rules, tt.rule) || v.Action != want {
					t.Fatalf("verdict %v %q %v, want %s with action %s", v.Matched, v.Action, v.Rules, tt.rule, want)
				}
			})
		}
	}
	// Control: a benign twin matches nothing under any config.
	for _, c := range configs {
		line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"git clean -n -d"}}}`)
		if v := c.pc.CheckRequest(line); v.Matched {
			t.Fatalf("%s: dry-run clean matched %v", c.name, v.Rules)
		}
	}
}
