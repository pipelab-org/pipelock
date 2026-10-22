// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseTOMLConfig(t *testing.T) {
	tests := []struct {
		name         string
		client       string
		content      string
		wantName     string
		wantCommand  string
		wantURL      string
		wantType     string
		wantWarning  bool
		wantDisabled bool
		wantError    bool
	}{
		{
			name: "Codex stdio with quoted key and env", client: clientCodex,
			content:  "[mcp_servers.\"api.vendor.example\"]\ncommand = 'npx'\nargs = ['-y', 'server']\nenv = { TOKEN = 'secret-value' }\n",
			wantName: "api.vendor.example", wantCommand: "npx", wantType: TransportStdio,
		},
		{
			name: "Grok wrapped stdio", client: clientGrok,
			content:  "[mcp_servers.files]\ncommand = '/opt/pipelock'\nargs = [\n 'mcp', # comment\n 'proxy'\n]\n",
			wantName: "files", wantCommand: "/opt/pipelock", wantType: TransportStdio,
		},
		{
			name: "remote with header warning", client: clientGrok,
			content:  "[mcp_servers.remote]\nurl = 'https://api.vendor.example/mcp?" + "token=secret-value'\nheaders = { Authorization = 'secret-value' }\n",
			wantName: "remote", wantURL: "https://api.vendor.example/mcp?" + "token=secret-value", wantType: TransportHTTP, wantWarning: true,
		},
		{
			name: "Codex HTTP headers", client: clientCodex,
			content:  "[mcp_servers.remote]\nurl = 'https://api.vendor.example/mcp'\nhttp_headers = { Authorization = 'secret-value' }\n",
			wantName: "remote", wantURL: "https://api.vendor.example/mcp", wantType: TransportHTTP, wantWarning: true,
		},
		{
			name: "Codex bearer token warning", client: clientCodex,
			content:  "[mcp_servers.remote]\nurl = 'https://api.vendor.example/mcp'\nbearer_token_env_var = 'MCP_TOKEN'\n",
			wantName: "remote", wantURL: "https://api.vendor.example/mcp", wantType: TransportHTTP, wantWarning: true,
		},
		{
			name: "Codex disabled", client: clientCodex,
			content:  "[mcp_servers.off]\ncommand = 'npx'\nenabled = false\n",
			wantName: "off", wantCommand: "npx", wantType: TransportStdio, wantDisabled: true, wantWarning: true,
		},
		{
			name: "Codex explicit enabled", client: clientCodex,
			content:  "[mcp_servers.on]\ncommand = 'npx'\nenabled = true\n",
			wantName: "on", wantCommand: "npx", wantType: TransportStdio,
		},
		{
			name: "unsupported type does not override URL", client: clientGrok,
			content:  "[mcp_servers.remote]\nurl = 'https://api.vendor.example/mcp'\ntype = 'stdio'\n",
			wantName: "remote", wantURL: "https://api.vendor.example/mcp", wantType: TransportHTTP,
		},
		{
			name: "invalid Codex enabled type", client: clientCodex,
			content:   "[mcp_servers.bad]\ncommand = 'npx'\nenabled = 'false'\n",
			wantError: true,
		},
		{
			name: "invalid args type", client: clientCodex,
			content:   "[mcp_servers.bad]\ncommand = 'npx'\nargs = [1, true]\n",
			wantError: true,
		},
		{
			name: "invalid TOML hides sensitive source", client: clientGrok,
			content:   "[mcp_servers.bad]\ncommand = 'secret-value\n",
			wantError: true,
		},
		{
			name: "wrong MCP table shape", client: clientCodex,
			content:   "mcp_servers = 'secret-value'\n",
			wantError: true,
		},
		{
			name: "wrong MCP entry shape", client: clientGrok,
			content:   "[mcp_servers]\nbad = 'secret-value'\n",
			wantError: true,
		},
		{
			name: "wrong env value type", client: clientCodex,
			content:   "[mcp_servers.bad]\ncommand = 'npx'\nenv = { TOKEN = 1 }\n",
			wantError: true,
		},
		{
			name: "duplicate key", client: clientCodex,
			content:   "[mcp_servers.bad]\ncommand = 'npx'\ncommand = 'node'\n",
			wantError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			servers, err := parseTOMLConfig(path, tt.client)
			if tt.wantError {
				if err == nil || !strings.Contains(err.Error(), errInvalidTOMLMCPConfig.Error()) || strings.Contains(err.Error(), "secret-value") {
					t.Fatalf("error = %v, want sanitized TOML error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(servers) != 1 {
				t.Fatalf("servers = %+v, want one", servers)
			}
			s := servers[0]
			if s.Client != tt.client || s.ServerName != tt.wantName || s.Command != tt.wantCommand || s.URL != tt.wantURL || s.Transport != tt.wantType || s.Args == nil || s.Disabled != tt.wantDisabled {
				t.Fatalf("server = %+v", s)
			}
			if (len(s.ParseWarnings) > 0) != tt.wantWarning {
				t.Fatalf("warnings = %v", s.ParseWarnings)
			}
			if strings.Contains(strings.Join(s.ParseWarnings, " "), "secret-value") {
				t.Fatal("warning leaked header value")
			}
			if tt.name == "Codex stdio with quoted key and env" && s.Env["TOKEN"] != "secret-value" {
				t.Fatalf("env not decoded: %+v", s.Env)
			}
		})
	}
}

func TestDiscoverTOMLClientsAndErrors(t *testing.T) {
	home := t.TempDir()
	for _, dir := range []string{".codex", ".grok"} {
		if err := os.Mkdir(filepath.Join(home, dir), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("[mcp_servers.raw]\ncommand = 'npx'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".grok", "config.toml"), []byte("[mcp_servers.bad]\nargs = [1]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.TotalServers != 1 || report.Summary.ParseErrors != 1 || report.Summary.Unprotected != 1 || report.Summary.TotalClients != 2 {
		t.Fatalf("summary = %+v", report.Summary)
	}
	if report.Servers[0].Client != clientCodex || report.Clients[1].Client != clientGrok {
		t.Fatalf("clients = %+v, servers = %+v", report.Clients, report.Servers)
	}
}

// TestDiscoverDisabledCodexServersStayCounted proves enabled = false does not
// remove an unwrapped Codex server from the protection counts. Codex merges
// config layers: a trusted project's .codex/config.toml holding only
// enabled = true, or a -c override, starts the server again, and discover does
// not read those layers. Excluding the entry made discover exit 0 and assess
// score 100 while Codex launched the unwrapped server.
func TestDiscoverDisabledCodexServersStayCounted(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".codex")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	content := "[mcp_servers.off]\ncommand = 'npx'\nenabled = false\n[mcp_servers.on]\ncommand = 'node'\nenabled = true\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Servers) != 2 || report.Summary.TotalServers != 2 || report.Summary.Disabled != 1 || report.Summary.Unprotected != 2 {
		t.Fatalf("summary = %+v", report.Summary)
	}
	foundDisabled := false
	for _, server := range report.Servers {
		if server.ServerName == "off" {
			foundDisabled = true
			if server.Protection != Unprotected || !server.Disabled || server.Risk == "" {
				t.Fatalf("disabled server = %+v", server)
			}
			if !slices.Contains(server.ParseWarnings, warnCodexDisabledStillCounted) {
				t.Fatalf("disabled server does not explain why it is counted: %+v", server.ParseWarnings)
			}
		}
	}
	if !foundDisabled {
		t.Fatalf("disabled server missing from inventory: %+v", report.Servers)
	}
}

func TestBuildSummarySOPSSubset(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	servers := []MCPServer{
		{Command: "sops", Args: []string{"exec-env", "secrets.yaml", "exec " + self + " mcp proxy"}, Protection: Unprotected},
		{Command: "/usr/bin/sops", Args: []string{"exec-env", "--background"}, Protection: Unprotected},
		{Command: "sops", Args: []string{"exec-env", "secrets.yaml", "exec /usr/bin/true mcp proxy"}, Protection: Unprotected},
		{Command: "sops", Args: []string{"exec-file", "secrets.yaml"}, Protection: Unprotected},
		{Command: "npx", Protection: Unprotected},
		{Command: "sops", Args: []string{"exec-env", "secrets.yaml", "exec " + self + " mcp proxy"}, Protection: ProtectedPipelock},
	}
	s := buildSummary(nil, servers)
	if s.Unprotected != 5 || s.SOPSExecEnv != 1 {
		t.Fatalf("summary = %+v, want one recognized sops wrapper among five unprotected", s)
	}
	sharedJSON, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sharedJSON), "sops_exec_env") {
		t.Fatalf("shared summary JSON leaked discover-only count: %s", sharedJSON)
	}
}

func TestParseTOMLConfigMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.toml")
	if _, err := parseTOMLConfig(path, clientCodex); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v, want missing file", err)
	}
}

func TestParseTOMLConfigNoServers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{name: "empty", content: ""},
		{name: "unrelated settings", content: "model = 'example'\n[cli]\nauto_update = false\n"},
		{name: "empty table", content: "[mcp_servers]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			servers, err := parseTOMLConfig(path, clientGrok)
			if err != nil || len(servers) != 0 {
				t.Fatalf("servers = %+v, error = %v", servers, err)
			}
		})
	}
}
