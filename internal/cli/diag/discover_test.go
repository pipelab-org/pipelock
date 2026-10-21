// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/discover"
)

func TestDiscoverCmd_JSONEmptyHome(t *testing.T) {
	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--json", "--home", t.TempDir()})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	// Should produce valid JSON with zero servers
	var report discover.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}
	if report.Summary.TotalServers != 0 {
		t.Errorf("expected 0 servers, got %d", report.Summary.TotalServers)
	}
}

func TestDiscoverCmd_SOPSSubsetInHumanAndJSON(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".codex"), 0o750); err != nil {
		t.Fatal(err)
	}
	content := "[mcp_servers.nested]\ncommand = 'sops'\nargs = ['exec-env', 'secrets.yaml', 'exec /opt/pipelock mcp proxy']\n"
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "human", args: []string{"--home", home}},
		{name: "JSON", args: []string{"--json", "--home", home}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			cmd := DiscoverCmd()
			cmd.SetOut(&output)
			cmd.SetErr(&bytes.Buffer{})
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetArgs(tc.args)
			var exitErr *cliutil.ExitError
			if err := cmd.Execute(); !errors.As(err, &exitErr) || exitErr.Code != 1 {
				t.Fatalf("Execute() error = %v, want exit 1", err)
			}
			if tc.name == "human" {
				if !strings.Contains(output.String(), "Unprotected:           1") || !strings.Contains(output.String(), "via sops exec-env:   1") {
					t.Fatalf("human summary = %s", output.String())
				}
				return
			}
			var report discover.Report
			if err := json.Unmarshal(output.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			var raw struct {
				Summary struct {
					SOPSExecEnv int `json:"sops_exec_env"`
				} `json:"summary"`
			}
			if err := json.Unmarshal(output.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			if report.Summary.Unprotected != 1 || raw.Summary.SOPSExecEnv != 1 {
				t.Fatalf("JSON summary = %+v", report.Summary)
			}
		})
	}
}

func TestDiscoverCmd_TOMLRedactsSecrets(t *testing.T) {
	home := t.TempDir()
	for _, tc := range []struct {
		dir     string
		content string
	}{
		{dir: ".codex", content: "[mcp_servers.local]\ncommand = 'npx'\nenv = { API_TOKEN = 'secret-env-value' }\n"},
		{dir: ".grok", content: "[mcp_servers.remote]\nurl = 'https://api.vendor.example/mcp?" + "token=secret-url-value'\nheaders = { Authorization = 'secret-header-value' }\n"},
	} {
		dir := filepath.Join(home, tc.dir)
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&output)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--json", "--home", home})
	var exitErr *cliutil.ExitError
	if err := cmd.Execute(); !errors.As(err, &exitErr) || exitErr.Code != 1 {
		t.Fatalf("Execute() error = %v, want exit 1", err)
	}
	for _, secret := range []string{"secret-env-value", "secret-url-value", "secret-header-value"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("JSON output leaked %q: %s", secret, output.String())
		}
	}
	var report discover.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Summary.TotalServers != 2 || report.Summary.Unprotected != 2 {
		t.Fatalf("summary = %+v", report.Summary)
	}
}

func TestDiscoverCmd_JSONWithServers(t *testing.T) {
	home := t.TempDir()

	content := `{"mcpServers":{
		"brain":{"command":"pipelock","args":["mcp","proxy","--","node","brain.js"]},
		"raw":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]}
	}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--json", "--home", home})

	err := cmd.Execute()

	// Should exit 1 because unprotected servers exist
	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if exitErr.Code != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.Code)
	}

	var report discover.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if report.Summary.TotalServers != 2 {
		t.Errorf("total_servers = %d, want 2", report.Summary.TotalServers)
	}
}

func TestDiscoverCmd_JSONRedactsSensitiveValues(t *testing.T) {
	home := t.TempDir()

	dbURL := "postgresql://postgres:" + "postgres@127.0.0.1:5432/app"
	content := `{"mcpServers":{"db":{
		"command":"npx",
		"args":["-y","@modelcontextprotocol/server-postgres","` + dbURL + `","--token=abc123"],
		"env":{"API_TOKEN":"secret-token","BRAIN_DIR":"/data"}
	}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--json", "--home", home})

	err := cmd.Execute()
	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if exitErr.Code != 1 {
		t.Fatalf("exit code = %d, want 1", exitErr.Code)
	}

	out := stdout.String()
	for _, leaked := range []string{"postgres:postgres", "abc123", "secret-token", `"/data"`} {
		if strings.Contains(out, leaked) {
			t.Fatalf("discover JSON leaked %q in:\n%s", leaked, out)
		}
	}

	var report discover.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(report.Servers) != 1 {
		t.Fatalf("servers = %d, want 1", len(report.Servers))
	}
	if report.Servers[0].Env["API_TOKEN"] != "[REDACTED]" {
		t.Fatalf("env value not redacted: %#v", report.Servers[0].Env)
	}
}

func TestDiscoverCmd_HumanAndGenerateRedactSensitiveValues(t *testing.T) {
	home := t.TempDir()
	dbURL := "postgresql://postgres:" + "postgres@127.0.0.1:5432/app"
	content := `{"mcpServers":{"db":{
		"command":"npx",
		"args":["-y","@modelcontextprotocol/server-postgres","` + dbURL + `","--password=hunter2"],
		"env":{"API_TOKEN":"secret-token"}
	}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--generate", "--home", home})

	err := cmd.Execute()
	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if exitErr.Code != 1 {
		t.Fatalf("exit code = %d, want 1", exitErr.Code)
	}

	output := buf.String()
	for _, leaked := range []string{"postgres:postgres", "hunter2", "secret-token"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("discover output leaked %q in:\n%s", leaked, output)
		}
	}
	if !strings.Contains(output, "[REDACTED]") && !strings.Contains(output, "%5BREDACTED%5D") {
		t.Fatalf("discover output did not show redaction marker:\n%s", output)
	}
}

func TestDiscoverCmd_HumanOutput(t *testing.T) {
	home := t.TempDir()
	content := protectedDiscoveryConfig(t)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--home", home})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("Pipelock Discovery")) {
		t.Error("expected 'Pipelock Discovery' header")
	}
	if !bytes.Contains([]byte(output), []byte("All servers are protected")) {
		t.Errorf("expected 'All servers are protected', got:\n%s", output)
	}
}

func TestDiscoverCmd_ExitCodeZeroAllProtected(t *testing.T) {
	home := t.TempDir()
	content := protectedDiscoveryConfig(t)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--home", home})
	err := cmd.Execute()
	if err != nil {
		t.Errorf("expected nil error (exit 0), got %v", err)
	}
}

func protectedDiscoveryConfig(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve current executable: %v", err)
	}
	return fmt.Sprintf(`{"mcpServers":{"brain":{"command":%q,"args":["mcp","proxy","--","node","brain.js"]}}}`, self)
}

func TestDiscoverCmd_ExitCodeOneUnprotected(t *testing.T) {
	home := t.TempDir()
	content := `{"mcpServers":{"raw":{"command":"npx","args":["-y","@mcp/server-fs"]}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--home", home})
	err := cmd.Execute()

	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if exitErr.Code != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.Code)
	}
}

func TestDiscoverCmd_GenerateFlag(t *testing.T) {
	home := t.TempDir()
	content := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--generate", "--home", home})
	_ = cmd.Execute() // exit 1 expected

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("Wrapper suggestions")) {
		t.Errorf("expected wrapper suggestions, got:\n%s", output)
	}
	if !bytes.Contains([]byte(output), []byte("pipelock")) {
		t.Error("suggestion should mention pipelock")
	}
}

func TestDiscoverCmd_NoConfigs(t *testing.T) {
	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--home", t.TempDir()})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("No AI agent configs found")) {
		t.Errorf("expected 'No AI agent configs found', got:\n%s", output)
	}
}

func TestDiscoverCmd_MalformedConfigExitOne(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{broken`), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--home", home})
	err := cmd.Execute()

	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError for malformed config, got %v", err)
	}
	if exitErr.Code != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.Code)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("PARSE ERROR")) {
		t.Errorf("expected PARSE ERROR in output, got:\n%s", output)
	}
}

func TestDiscoverCmd_ProjectPathInOutput(t *testing.T) {
	home := t.TempDir()
	content := `{
		"projects": {
			"/home/user/myproject": {
				"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--home", home})
	_ = cmd.Execute() // exit 1 expected

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("/home/user/myproject")) {
		t.Errorf("expected project path in output, got:\n%s", output)
	}
}

func TestDiscoverCmd_ProjectPathInGenerate(t *testing.T) {
	home := t.TempDir()
	content := `{
		"projects": {
			"/home/user/myproject": {
				"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--generate", "--home", home})
	_ = cmd.Execute() // exit 1 expected

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("project: /home/user/myproject")) {
		t.Errorf("expected project path in wrapper suggestion, got:\n%s", output)
	}
}

func TestDiscoverCmd_PartialParseFailureSurfaced(t *testing.T) {
	home := t.TempDir()
	content := `{
		"mcpServers": {"global": {"command": "pipelock", "args": ["mcp", "proxy", "--", "node", "s.js"]}},
		"projects": {
			"/good": {"mcpServers": {"s1": {"command": "node", "args": ["a.js"]}}},
			"/bad": "not_an_object"
		}
	}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--json", "--home", home})
	_ = cmd.Execute()

	var report discover.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}

	// Should have 3 servers: global + s1 from /good + placeholder for /bad
	if report.Summary.TotalServers != 3 {
		t.Errorf("total_servers = %d, want 3", report.Summary.TotalServers)
	}

	// Find the placeholder server
	found := false
	for _, s := range report.Servers {
		if s.ServerName == "(malformed project)" {
			found = true
			if len(s.ParseWarnings) == 0 {
				t.Error("expected parse_warnings on placeholder server")
			}
			if s.ProjectPath != "/bad" {
				t.Errorf("placeholder ProjectPath = %q, want /bad", s.ProjectPath)
			}
		}
	}
	if !found {
		t.Error("expected placeholder server for malformed project entry")
	}
}

func TestDiscoverCmd_MalformedConfigJSON(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{broken`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := DiscoverCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--json", "--home", home})
	_ = cmd.Execute()

	var report discover.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if report.Summary.ParseErrors != 1 {
		t.Errorf("parse_errors = %d, want 1", report.Summary.ParseErrors)
	}
	if report.Clients[0].ParseError == "" {
		t.Error("expected non-empty parse_error on client")
	}
}

func TestServerDescription(t *testing.T) {
	tests := []struct {
		name   string
		server discover.MCPServer
		want   string
	}{
		{
			name: "command with args",
			server: discover.MCPServer{
				Command: "npx",
				Args:    []string{"-y", "@example/server"},
			},
			want: "npx -y @example/server",
		},
		{
			name: "command without args",
			server: discover.MCPServer{
				Command: "my-server",
			},
			want: "my-server",
		},
		{
			name: "url only",
			server: discover.MCPServer{
				URL: "https://api.example.com/mcp",
			},
			want: "https://api.example.com/mcp",
		},
		{
			name:   "unknown (empty)",
			server: discover.MCPServer{},
			want:   "(unknown)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := serverDescription(tc.server); got != tc.want {
				t.Errorf("serverDescription() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDiscoverCmd_ClaudeConfigDirSources proves the CLI boundary owns override
// resolution: --home ignores the running user's CLAUDE_CONFIG_DIR, while an
// explicit --claude-config-dir is always inspected.
func TestDiscoverCmd_ClaudeConfigDirSources(t *testing.T) {
	altDir := t.TempDir()
	content := `{"mcpServers":{"alt":{"command":"node","args":["alt.js"]}}}`
	if err := os.WriteFile(filepath.Join(altDir, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(discover.EnvClaudeConfigDir, altDir)
	t.Setenv(discover.EnvCodexHome, "") // an operator's own value must not add servers

	run := func(args ...string) discover.Report {
		t.Helper()
		var buf, errBuf bytes.Buffer
		cmd := DiscoverCmd()
		cmd.SetOut(&buf)
		cmd.SetErr(&errBuf)
		cmd.SetArgs(append([]string{"--json"}, args...))
		_ = cmd.Execute() // exit code 1 is expected when servers are unprotected
		var report discover.Report
		// The report is the first JSON value; an unprotected result also
		// returns exit code 1, whose message may follow it.
		if err := json.NewDecoder(&buf).Decode(&report); err != nil {
			t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
		}
		return report
	}

	t.Setenv("HOME", t.TempDir())
	if got := run(); got.Summary.TotalServers != 1 {
		t.Fatalf("default run ignored the ambient CLAUDE_CONFIG_DIR: %+v", got.Summary)
	}
	if got := run("--home", t.TempDir()); got.Summary.TotalServers != 0 {
		t.Fatalf("--home inspected the ambient CLAUDE_CONFIG_DIR: %+v", got.Summary)
	}
	if got := run("--home", t.TempDir(), "--claude-config-dir", altDir); got.Summary.TotalServers != 1 {
		t.Fatalf("--claude-config-dir not inspected: %+v", got.Summary)
	}
}

// TestDiscoverCmd_CodexHomeSource proves the CLI boundary applies the same
// rule to CODEX_HOME: the default run inspects it, --home does not.
func TestDiscoverCmd_CodexHomeSource(t *testing.T) {
	altDir := t.TempDir()
	content := "[mcp_servers.alt]\ncommand = 'node'\nargs = ['alt.js']\n"
	if err := os.WriteFile(filepath.Join(altDir, "config.toml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(discover.EnvCodexHome, altDir)
	t.Setenv(discover.EnvClaudeConfigDir, "")

	run := func(args ...string) discover.Report {
		t.Helper()
		var buf, errBuf bytes.Buffer
		cmd := DiscoverCmd()
		cmd.SetOut(&buf)
		cmd.SetErr(&errBuf)
		cmd.SetArgs(append([]string{"--json"}, args...))
		_ = cmd.Execute() // exit code 1 is expected when servers are unprotected
		var report discover.Report
		if err := json.NewDecoder(&buf).Decode(&report); err != nil {
			t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
		}
		return report
	}

	t.Setenv("HOME", t.TempDir())
	if got := run(); got.Summary.TotalServers != 1 {
		t.Fatalf("default run ignored the ambient CODEX_HOME: %+v", got.Summary)
	}
	if got := run("--home", t.TempDir()); got.Summary.TotalServers != 0 {
		t.Fatalf("--home inspected the ambient CODEX_HOME: %+v", got.Summary)
	}
}
