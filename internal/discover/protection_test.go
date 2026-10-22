// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyProtection(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	tests := []struct {
		name   string
		server MCPServer
		want   ProtectionStatus
	}{
		{
			name:   "current executable wrapped stdio",
			server: MCPServer{Command: self, Args: []string{wrapperArgMCP, wrapperArgProxy, flagConfig, "local.yaml", "--", testCmdNode, testServerJS}},
			want:   ProtectedPipelock,
		},
		{
			name:   "bare name is not identity proof",
			server: MCPServer{Command: wrapperCommand, Args: []string{wrapperArgMCP, wrapperArgProxy, "--", "uvx", "some-server"}},
			want:   Unprotected,
		},
		{
			name:   "unexpanded path is not identity proof",
			server: MCPServer{Command: "~/.local/bin/pipelock", Args: []string{wrapperArgMCP, wrapperArgProxy, "--", testCmdNode, "s.js"}},
			want:   Unprotected,
		},
		{
			name:   "pipelock command but no mcp arg",
			server: MCPServer{Command: wrapperCommand, Args: []string{"run", flagConfig, "config.yaml"}},
			want:   Unprotected,
		},
		{
			name:   "pipelock command but no proxy arg",
			server: MCPServer{Command: wrapperCommand, Args: []string{wrapperArgMCP, "scan", "file.txt"}},
			want:   Unprotected,
		},
		{
			name:   "bare npx command",
			server: MCPServer{Command: testCmdNpx, Args: []string{"-y", testServerFilesystemPkg}},
			want:   Unprotected,
		},
		{
			name:   "http server",
			server: MCPServer{Transport: TransportHTTP, URL: testHTTPMCPURL},
			want:   Unprotected,
		},
		{
			name:   "empty server",
			server: MCPServer{},
			want:   Unknown,
		},
		{
			name:   "command only, no wrapper",
			server: MCPServer{Command: testCmdNode, Args: []string{testServerJS}},
			want:   Unprotected,
		},
		{
			name:   "foreign windows path is not identity proof",
			server: MCPServer{Command: `C:\Program Files\pipelock.exe`, Args: []string{wrapperArgMCP, wrapperArgProxy, "--", testCmdNode, "s.js"}},
			want:   Unprotected,
		},
		{
			name:   "false positive pipelock-helper",
			server: MCPServer{Command: "/opt/pipelock-helper", Args: []string{wrapperArgMCP, wrapperArgProxy}},
			want:   Unprotected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyProtection(tt.server)
			if got != tt.want {
				t.Errorf("classifyProtection() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProtectionEvidence(t *testing.T) {
	tests := []struct {
		server MCPServer
		want   string
	}{
		{MCPServer{Protection: ProtectedPipelock}, evidenceProtectedPipelock},
		{MCPServer{Protection: ProtectedOther}, evidenceProtectedOther},
		{MCPServer{Protection: Unknown}, evidenceUnknown},
		{MCPServer{Protection: Unprotected}, evidenceNoProxy},
		{MCPServer{Protection: Unprotected, Command: "/nonexistent-pipelock-test/pipelock", Args: []string{"mcp", "proxy"}}, evidenceWrapperMissing},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := protectionEvidence(tt.server)
			if got != tt.want {
				t.Errorf("protectionEvidence() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestClassifyServerForeignReasons proves every proxy-shaped invocation that is
// not this executable stays unprotected, and that its evidence names the
// concrete reason so the operator knows what to repair.
func TestClassifyServerForeignReasons(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir := t.TempDir()
	other := filepath.Join(dir, "pipelock")
	if err := os.WriteFile(other, []byte("not pipelock"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkToSelf := filepath.Join(dir, "self-link")
	linkToOther := filepath.Join(dir, "other-link")
	dangling := filepath.Join(dir, "dangling-link")
	for _, l := range []struct{ target, name string }{
		{self, linkToSelf}, {other, linkToOther}, {filepath.Join(dir, "absent"), dangling},
	} {
		if err := os.Symlink(l.target, l.name); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	proxyArgs := []string{wrapperArgMCP, wrapperArgProxy, "--", testCmdNode, testServerJS}

	tests := []struct {
		name      string
		command   string
		wantState ProtectionStatus
		wantEvid  string
	}{
		{"self", self, ProtectedPipelock, evidenceProtectedPipelock},
		{"symlink to self", linkToSelf, ProtectedPipelock, evidenceProtectedPipelock},
		{"missing absolute path", filepath.Join(dir, "missing", "pipelock-dev"), Unprotected, evidenceWrapperMissing},
		{"dangling symlink", dangling, Unprotected, evidenceWrapperMissing},
		{"different file", other, Unprotected, evidenceWrapperDifferent},
		{"symlink to different file", linkToOther, Unprotected, evidenceWrapperDifferent},
		{"bare name", wrapperCommand, Unprotected, evidenceWrapperRelative},
		{"dot-relative name", "./pipelock", Unprotected, evidenceWrapperRelative},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, evidence := classifyServer(MCPServer{Command: tt.command, Args: proxyArgs})
			if state != tt.wantState || evidence != tt.wantEvid {
				t.Fatalf("classifyServer() = (%q, %q), want (%q, %q)", state, evidence, tt.wantState, tt.wantEvid)
			}
			if got := classifyProtection(MCPServer{Command: tt.command, Args: proxyArgs}); got != state {
				t.Fatalf("classifyProtection() = %q, classifyServer state = %q", got, state)
			}
		})
	}
}

// TestClassifyServerPermissionDeniedIsNotMissing proves an inaccessible path is
// reported as uncheckable, never as absent, and never as protected.
func TestClassifyServerPermissionDeniedIsNotMissing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "pipelock")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- cleanup only: TempDir removal needs write and exec back on the directory.

	state, evidence := classifyServer(MCPServer{Command: target, Args: []string{wrapperArgMCP, wrapperArgProxy}})
	if state != Unprotected || evidence != evidenceWrapperUncheck {
		t.Fatalf("classifyServer() = (%q, %q), want (%q, %q)", state, evidence, Unprotected, evidenceWrapperUncheck)
	}
}
