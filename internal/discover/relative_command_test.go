// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"os"
	"path/filepath"
	"testing"
)

// A relative command resolves against the client's working directory or PATH,
// not discover's. A same-file match in discover's own working directory (for
// example right after building ./pipelock) must not report the entry as
// wrapped by this executable.
func TestRelativeCommandIsNeverThisExecutable(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(self, filepath.Join(dir, "pipelock")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	t.Chdir(dir)

	for _, command := range []string{"pipelock", "./pipelock", filepath.Join("..", filepath.Base(dir), "pipelock")} {
		t.Run(command, func(t *testing.T) {
			s := MCPServer{Command: command, Args: []string{"mcp", "proxy", "--", "node", "server.js"}}
			state, evidence := classifyServer(s)
			if state != Unprotected || evidence != evidenceWrapperRelative {
				t.Fatalf("classifyServer = %s %q, want unprotected %q", state, evidence, evidenceWrapperRelative)
			}
			s.Protection = state
			if got := protectionEvidence(s); got != evidenceWrapperRelative {
				t.Fatalf("protectionEvidence = %q, want %q", got, evidenceWrapperRelative)
			}
		})
	}

	// The absolute path to the same file stays protected.
	state, _ := classifyServer(MCPServer{Command: self, Args: []string{"mcp", "proxy", "--", "node"}})
	if state != ProtectedPipelock {
		t.Fatalf("absolute command state = %s, want %s", state, ProtectedPipelock)
	}
}
