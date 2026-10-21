// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"os"
	"path/filepath"
	"testing"
)

// The clients read config keys case-sensitively. A case-variant key they
// ignore must not shadow the real one, or an unwrapped server reports as
// wrapped by this executable.
func TestCaseVariantKeysDoNotShadowRealEntry(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	wrapper := "'" + self + "'"

	tomlCases := []struct {
		name        string
		content     string
		wantServers int
		wantCommand string
		wantState   ProtectionStatus
	}{
		{
			name:        "variant top-level table is a different key",
			content:     "[mcp_servers.x]\ncommand = 'sh'\n[MCP_SERVERS.x]\ncommand = " + wrapper + "\nargs = ['mcp', 'proxy', '--', 'sh']\n",
			wantServers: 1, wantCommand: "sh", wantState: Unprotected,
		},
		{
			name:        "variant top-level table alone is ignored",
			content:     "[MCP_SERVERS.x]\ncommand = " + wrapper + "\nargs = ['mcp', 'proxy']\n",
			wantServers: 0,
		},
		{
			name:        "variant field does not override command",
			content:     "[mcp_servers.x]\ncommand = 'sh'\nCommand = " + wrapper + "\nargs = ['mcp', 'proxy', '--', 'sh']\n",
			wantServers: 1, wantCommand: "sh", wantState: Unprotected,
		},
		{
			name:        "variant field alone leaves the entry without a command",
			content:     "[mcp_servers.x]\nCommand = " + wrapper + "\nArgs = ['mcp', 'proxy']\n",
			wantServers: 1, wantCommand: "", wantState: Unknown,
		},
		{
			name:        "exact key still wraps",
			content:     "[mcp_servers.x]\ncommand = " + wrapper + "\nargs = ['mcp', 'proxy', '--', 'sh']\n",
			wantServers: 1, wantCommand: self, wantState: ProtectedPipelock,
		},
	}
	for _, tt := range tomlCases {
		t.Run("toml/"+tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			servers, err := parseTOMLConfig(path, clientCodex)
			if err != nil {
				t.Fatal(err)
			}
			if len(servers) != tt.wantServers {
				t.Fatalf("servers = %+v, want %d", servers, tt.wantServers)
			}
			if tt.wantServers == 0 {
				return
			}
			state, _ := classifyServer(servers[0])
			if servers[0].Command != tt.wantCommand || state != tt.wantState {
				t.Fatalf("command = %q state = %s, want %q %s", servers[0].Command, state, tt.wantCommand, tt.wantState)
			}
		})
	}

	jsonCases := []struct {
		name        string
		content     string
		wantCommand string
		wantState   ProtectionStatus
	}{
		{
			name:        "variant field does not override command",
			content:     `{"mcpServers":{"x":{"command":"sh","Command":"` + self + `","args":["mcp","proxy","--","sh"]}}}`,
			wantCommand: "sh", wantState: Unprotected,
		},
		{
			name:        "variant field alone leaves the entry without a command",
			content:     `{"mcpServers":{"x":{"Command":"` + self + `","Args":["mcp","proxy"]}}}`,
			wantCommand: "", wantState: Unknown,
		},
		{
			name:        "exact key still wraps",
			content:     `{"mcpServers":{"x":{"command":"` + self + `","args":["mcp","proxy","--","sh"]}}}`,
			wantCommand: self, wantState: ProtectedPipelock,
		},
	}
	for _, tt := range jsonCases {
		t.Run("json/"+tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			servers, err := parseConfigFile(path, configKeyMCPServers, clientCursor)
			if err != nil || len(servers) != 1 {
				t.Fatalf("servers = %+v, error = %v", servers, err)
			}
			state, _ := classifyServer(servers[0])
			if servers[0].Command != tt.wantCommand || state != tt.wantState {
				t.Fatalf("command = %q state = %s, want %q %s", servers[0].Command, state, tt.wantCommand, tt.wantState)
			}
		})
	}
}

// A malformed entry still fails the whole file rather than reading as clean.
func TestExactKeyDecodersStillRejectWrongTypes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	for _, content := range []string{
		`{"mcpServers":{"x":{"command":5}}}`,
		`{"mcpServers":{"x":{"args":"mcp proxy"}}}`,
		`{"mcpServers":{"x":"command"}}`,
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if servers, err := parseConfigFile(path, configKeyMCPServers, clientCursor); err == nil {
			t.Fatalf("%s: servers = %+v, want an error", content, servers)
		}
	}
}
