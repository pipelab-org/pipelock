// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"errors"
	"strings"
	"testing"
)

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
