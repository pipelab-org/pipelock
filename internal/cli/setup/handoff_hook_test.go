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

// hookRow is one command and what both hooks should do with it under the
// default config and under the strict preset: deny, and whether stderr
// reports an incomplete check.
type hookRow struct {
	name, command           string
	denyDefault, incDefault bool
	denyStrict, incStrict   bool
}

// runHookRows runs each row through the cursor and claude hooks, with the
// default config and with configs/strict.yaml.
func runHookRows(t *testing.T, rows []hookRow) {
	t.Helper()
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
	presets := []struct {
		name string
		args []string
	}{
		{"default", []string{"hook"}},
		{"strict", []string{"hook", "--config", "../../../configs/strict.yaml"}},
	}
	for _, h := range hooks {
		for _, p := range presets {
			for _, tt := range rows {
				t.Run(h.name+"/"+p.name+"/"+tt.name, func(t *testing.T) {
					deny, inc := tt.denyDefault, tt.incDefault
					if p.name == "strict" {
						deny, inc = tt.denyStrict, tt.incStrict
					}
					cmd := h.cmd()
					cmd.SetArgs(p.args)
					cmd.SetIn(bytes.NewReader([]byte(h.input(tt.command))))
					out, errOut := &strings.Builder{}, &strings.Builder{}
					cmd.SetOut(out)
					cmd.SetErr(errOut)
					if err := cmd.Execute(); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if got := strings.Contains(out.String(), `"deny"`); got != deny {
						t.Fatalf("output %s: deny=%v, want %v", out.String(), got, deny)
					}
					if got := strings.Contains(errOut.String(), "incomplete_pair_check"); got != inc {
						t.Fatalf("stderr %q: incomplete=%v, want %v", errOut.String(), got, inc)
					}
				})
			}
		}
	}
}

// TestHooks_HandOffsTheSplitterCannotRead checks hand-offs through text the
// splitter does not read, copied files, here-strings and a command's own
// words in both hooks.
func TestHooks_HandOffsTheSplitterCannotRead(t *testing.T) {
	runHookRows(t, []hookRow{
		{"escaped command", `echo -R 777 /srv | xargs \chmod`, false, true, true, true},
		{"subshell", "(echo -R 777 /srv) | xargs chmod", false, true, true, true},
		{"quoted variable", `echo -R 777 "$HOME" | xargs chmod`, false, true, true, true},
		{"copied file", "echo -R 777 /srv > /tmp/a; cp /tmp/a /tmp/b; xargs chmod < /tmp/b", false, true, true, true},
		{"own flag, handed mode", "echo 777 /srv | xargs chmod -R", false, true, true, true},
		{"here-string", "xargs chmod <<<'-R 777 /srv'", true, false, true, false},
		// Visible benign words do not clear input the checker cannot establish.
		{"escaped command, mode not world writable", `echo 755 /srv | xargs \chmod`, false, true, true, true},
		{"copy not read back", "echo -R 777 /srv > /tmp/a; cp /tmp/a /tmp/b; xargs chmod < /tmp/c", false, true, true, true},
		{"own words, mode not world writable", "echo 755 /srv | xargs chmod -R", false, false, false, false},
		{"here-string, no flag", "xargs chmod <<<'644 /srv'", false, true, true, true},
	})
}
