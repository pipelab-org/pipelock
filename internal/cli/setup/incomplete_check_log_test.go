// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestHooks_LogIncompletePairCheck checks that both hooks write a stderr line
// naming the rules when tool policy reports an incomplete check, and stay
// quiet otherwise.
func TestHooks_LogIncompletePairCheck(t *testing.T) {
	hooks := []struct {
		name  string
		cmd   func() *cobra.Command
		input func(command string) string
	}{
		{"cursor", CursorCmd, func(c string) string {
			return `{"hook_event_name":"beforeShellExecution","command":` + strconv.Quote(c) + `,"cwd":"/tmp","conversation_id":"abc","generation_id":"def"}`
		}},
		{"claude", ClaudeCmd, func(c string) string {
			return `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":` + strconv.Quote(c) + `},"tool_use_id":"t1"}`
		}},
	}
	tests := []struct {
		name    string
		command string
		logged  bool
	}{
		{"delete then extract", "rm old.tar && tar -xf new.tar", true},
		{"list files", "ls -la", false},
	}
	for _, h := range hooks {
		for _, tt := range tests {
			t.Run(h.name+"/"+tt.name, func(t *testing.T) {
				cmd := h.cmd()
				cmd.SetArgs([]string{"hook"})
				cmd.SetIn(bytes.NewReader([]byte(h.input(tt.command))))
				out, errOut := &strings.Builder{}, &strings.Builder{}
				cmd.SetOut(out)
				cmd.SetErr(errOut)
				if err := cmd.Execute(); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				line := "pipelock: incomplete_pair_check (action=warn; rules=Destructive File Delete)"
				if got := strings.Contains(errOut.String(), line); got != tt.logged {
					t.Fatalf("stderr %q: logged=%v, want %v", errOut.String(), got, tt.logged)
				}
				if strings.Contains(out.String(), `"deny"`) {
					t.Fatalf("warn verdict denied: %s", out.String())
				}
			})
		}
	}
}
