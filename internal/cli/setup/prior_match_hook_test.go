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

// TestHooks_DenyWhatThePairCheckMatched checks that both hooks deny, with the
// default incomplete action, commands that the argument check matched before
// commands in one string were told apart.
func TestHooks_DenyWhatThePairCheckMatched(t *testing.T) {
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
		deny    bool
	}{
		{"copied file to xargs <", "echo -rf /srv/data > /tmp/a; cp /tmp/a /tmp/b; xargs rm < /tmp/b", true},
		{"moved file to xargs -a", "echo -rf /srv/data > /tmp/a; mv /tmp/a /tmp/b; xargs -a /tmp/b rm", true},
		{"moved file to xargs <", "echo -rf /srv/data > /tmp/a; mv /tmp/a /tmp/b; xargs rm < /tmp/b", true},
		{"./a then a", "echo -rf /srv/data > ./a; xargs rm < a", true},
		{"double slash", "echo -rf /srv/data > /tmp/a; xargs rm < /tmp//a", true},
		{"dot dot", "echo -rf /srv/data > /tmp/a; xargs rm < /tmp/../tmp/a", true},
		{"push flag through a copy", "echo --force > /tmp/f; cp /tmp/f /tmp/g; xargs git push origin main < /tmp/g", true},
		{"reset flag through a copy", "echo --hard > /tmp/a; cp /tmp/a /tmp/b; xargs git reset < /tmp/b", true},
		{"zero-width, copied file to xargs <", zeroWidth("echo -rf /srv/data > /tmp/a; cp /tmp/a /tmp/b; xargs rm < /tmp/b"), true},
		{"zero-width, decode written then piped to sh", zeroWidth("echo base64 -d x.b64 > /tmp/a; cat /tmp/a | sh"), true},
		// Controls.
		{"copied file, no flag", "echo old > /tmp/a; cp /tmp/a /tmp/b; xargs rm < /tmp/b", false},
		{"reset without the flag", "echo HEAD > /tmp/a; cp /tmp/a /tmp/b; xargs git reset < /tmp/b", false},
		{"zero-width, copied file, no flag", zeroWidth("echo old > /tmp/a; cp /tmp/a /tmp/b; xargs rm < /tmp/b"), false},
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
				if got := strings.Contains(out.String(), `"deny"`); got != tt.deny {
					t.Fatalf("output %s: deny=%v, want %v", out.String(), got, tt.deny)
				}
				if strings.Contains(errOut.String(), "incomplete_pair_check") {
					t.Fatalf("stderr %q: incomplete check reported", errOut.String())
				}
			})
		}
	}
}

// zeroWidth puts U+200B in place of every space.
func zeroWidth(s string) string { return strings.ReplaceAll(s, " ", "\u200b") }
