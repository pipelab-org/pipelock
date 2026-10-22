// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcpwrap

import (
	"os"
	"path/filepath"
	"testing"
)

// A relative command resolves against the launching client's directory or
// PATH, not this process's. A same-file match in this process's working
// directory must not classify the entry as this executable, or an installer
// skips an entry that actually runs some other binary.
func TestRelativeCommandIsNeverSelf(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(self, filepath.Join(dir, "pipelock")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	t.Chdir(dir)

	args := []string{subcmdMCP, subcmdProxy, "--", "node", "server.js"}
	for _, command := range []string{"pipelock", "./pipelock", filepath.Join("..", filepath.Base(dir), "pipelock")} {
		t.Run(command, func(t *testing.T) {
			state, reason := ExplainInvocation(command, args)
			if state != WrapperForeign || reason != ForeignRelativePath {
				t.Fatalf("ExplainInvocation = %v, %v, want foreign, relative path", state, reason)
			}
			if got := ClassifyInvocation(command, args); got != WrapperForeign {
				t.Fatalf("ClassifyInvocation = %v, want foreign", got)
			}
			server := map[string]interface{}{FieldCommand: command, FieldArgs: []interface{}{subcmdMCP, subcmdProxy, "--", "node"}}
			if IsWrappedBySelf(server) {
				t.Fatal("IsWrappedBySelf accepted a relative command")
			}
		})
	}

	if got := ClassifyInvocation(self, args); got != WrapperSelf {
		t.Fatalf("absolute command = %v, want self", got)
	}
}
