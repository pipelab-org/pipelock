// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"errors"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestGenerateTOMLWrapperProducesParseableClientEntries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server MCPServer
		want   []string
	}{
		{"Codex stdio", MCPServer{Client: clientCodex, ServerName: "api.vendor.example", Transport: TransportStdio, Command: "npx", Args: []string{"-y", "server"}, Env: map[string]string{"API_KEY": "secret"}}, []string{"mcp", "proxy", flagConfig, "~/.config/pipelock/local.yaml", "--env", "API_KEY", "--", "npx", "-y", "server"}},
		{"Grok HTTP", MCPServer{Client: clientGrok, ServerName: "remote", Transport: TransportHTTP, URL: "https://api.vendor.example/mcp"}, []string{"mcp", "proxy", flagConfig, "~/.config/pipelock/local.yaml", "--upstream", "https://api.vendor.example/mcp"}},
		{"Codex repoint", MCPServer{Client: clientCodex, ServerName: "old", Transport: TransportStdio, Command: "/tmp/old", Args: []string{"mcp", "proxy", "--", "node", "server.js"}}, []string{"mcp", "proxy", "--", "node", "server.js"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			suggestion := generateWrapper(tc.server, "/opt/pipelock")
			_, rest, ok := strings.Cut(suggestion, "  Before:\n")
			if !ok {
				t.Fatalf("no Before snippet: %s", suggestion)
			}
			before, _, ok := strings.Cut(rest, "\n  After:\n")
			if !ok {
				t.Fatalf("no After boundary: %s", suggestion)
			}
			if _, err := toml.Decode(before, &map[string]any{}); err != nil {
				t.Fatalf("invalid Before TOML: %v\n%s", err, before)
			}
			_, after, ok := strings.Cut(suggestion, "  After:\n")
			if !ok {
				t.Fatalf("no After snippet: %s", suggestion)
			}
			var document map[string]any
			if _, err := toml.Decode(after, &document); err != nil {
				t.Fatalf("invalid TOML: %v\n%s", err, after)
			}
			servers, ok := document["mcp_servers"].(map[string]any)
			if !ok {
				t.Fatalf("no mcp_servers table: %+v", document)
			}
			entry, ok := servers[tc.server.ServerName].(map[string]any)
			if !ok || entry["command"] != "/opt/pipelock" {
				t.Fatalf("entry = %+v", entry)
			}
			args, ok := entry["args"].([]any)
			if !ok || len(args) != len(tc.want) {
				t.Fatalf("args = %+v, want %v", entry["args"], tc.want)
			}
			for i, want := range tc.want {
				if args[i] != want {
					t.Fatalf("args[%d] = %v, want %q", i, args[i], want)
				}
			}
			if strings.Contains(after, `"command":`) {
				t.Fatalf("JSON syntax in TOML: %s", after)
			}
		})
	}
}

func TestGenerateWrapperStdio(t *testing.T) {
	server := MCPServer{
		ServerName: kwFilesystem,
		Client:     clientCursor,
		Command:    testCmdNpx,
		Args:       []string{"-y", testServerFilesystemPkg, "/tmp"},
		Transport:  TransportStdio,
		Protection: Unprotected,
	}

	suggestion := generateWrapper(server, "/opt/pipelock")
	if suggestion == "" {
		t.Fatal("expected non-empty suggestion")
	}
	if !strings.Contains(suggestion, wrapperCommand) {
		t.Error("suggestion should contain pipelock")
	}
	if !strings.Contains(suggestion, wrapperArgMCP) {
		t.Error("suggestion should contain mcp")
	}
	if !strings.Contains(suggestion, wrapperArgProxy) {
		t.Error("suggestion should contain proxy")
	}
	if !strings.Contains(suggestion, testCmdNpx) {
		t.Error("suggestion should contain original command")
	}
}

func TestGenerateWrapperHTTP(t *testing.T) {
	server := MCPServer{
		ServerName: "remote",
		Client:     clientCursor,
		URL:        testHTTPMCPURL,
		Transport:  TransportHTTP,
		Protection: Unprotected,
	}

	suggestion := generateWrapper(server, "/opt/pipelock")
	if !strings.Contains(suggestion, "--upstream") {
		t.Error("HTTP suggestion should contain --upstream")
	}
	if !strings.Contains(suggestion, testHTTPMCPURL) {
		t.Error("suggestion should contain original URL")
	}
}

func TestGenerateWrapperUnknown(t *testing.T) {
	server := MCPServer{
		ServerName: "mystery",
		Transport:  "unknown",
		Protection: Unprotected,
	}

	suggestion := generateWrapper(server, "/opt/pipelock")
	if !strings.Contains(suggestion, "no suggestion") {
		t.Error("should indicate no suggestion available")
	}
}

func TestGenerateWrapperStdioWithEnv(t *testing.T) {
	server := MCPServer{
		ServerName: "brain",
		Client:     clientClaudeCode,
		Command:    testCmdNode,
		Args:       []string{testServerJS},
		Env:        map[string]string{"BRAIN_DIR": testDataDir, "API_KEY": secretMarker},
		Transport:  TransportStdio,
		Protection: Unprotected,
	}

	suggestion := generateWrapper(server, "/opt/pipelock")
	if !strings.Contains(suggestion, `"--env"`) {
		t.Error("suggestion should contain --env flags for env vars")
	}
	if !strings.Contains(suggestion, `"API_KEY"`) {
		t.Error("suggestion should contain API_KEY env var name")
	}
	if !strings.Contains(suggestion, `"BRAIN_DIR"`) {
		t.Error("suggestion should contain BRAIN_DIR env var name")
	}
	// Verify --env flags come before the -- separator
	envIdx := strings.Index(suggestion, `"--env"`)
	sepIdx := strings.Index(suggestion, `"--"`)
	if envIdx > sepIdx {
		t.Error("--env flags should appear before -- separator")
	}
}

func TestGenerateWrapperNoArgs(t *testing.T) {
	server := MCPServer{
		ServerName: "simple",
		Client:     clientCursor,
		Command:    "myserver",
		Args:       []string{},
		Transport:  TransportStdio,
		Protection: Unprotected,
	}

	suggestion := generateWrapper(server, "/opt/pipelock")
	if !strings.Contains(suggestion, wrapperCommand) {
		t.Error("suggestion should contain pipelock")
	}
	if !strings.Contains(suggestion, "myserver") {
		t.Error("suggestion should contain original command")
	}
}

func TestGenerateWrapperUnavailableExecutable(t *testing.T) {
	if got := generateWrapper(MCPServer{Transport: TransportStdio, Command: "server"}, ""); !strings.Contains(got, "path is unavailable") {
		t.Fatalf("generateWrapper unavailable executable = %q", got)
	}
	resolver := func() (string, error) { return "/untrusted/partial/path", errors.New("unsupported") }
	if got := generateWrapperForCurrent(MCPServer{Transport: TransportStdio, Command: "server"}, resolver); !strings.Contains(got, "path is unavailable") {
		t.Fatalf("generateWrapper resolver error = %q", got)
	}
}

// TestGenerateWrapperRepointsBrokenWrapper proves a proxy-shaped entry whose
// executable is not this one gets a command repair, not a second wrap that
// would launch the same broken executable as its child.
func TestGenerateWrapperRepointsBrokenWrapper(t *testing.T) {
	server := MCPServer{
		ServerName: "everything",
		Client:     clientCursor,
		Command:    "/tmp/pipelock-dev",
		Args:       []string{wrapperArgMCP, wrapperArgProxy, flagConfig, "/tmp/pipelock.yaml", "--", testCmdNpx, "-y", "server-everything"},
		Transport:  TransportStdio,
		Protection: Unprotected,
	}

	suggestion := generateWrapper(server, "/opt/pipelock")
	if strings.Count(suggestion, "/tmp/pipelock-dev") != 1 {
		t.Fatalf("broken executable should appear only in Before, got:\n%s", suggestion)
	}
	if !strings.Contains(suggestion, `"command": "/opt/pipelock"`) {
		t.Fatalf("suggestion should point command at this executable:\n%s", suggestion)
	}
	if strings.Contains(suggestion, `"--", "/tmp/pipelock-dev"`) {
		t.Fatalf("suggestion double-wraps the broken wrapper:\n%s", suggestion)
	}
}
