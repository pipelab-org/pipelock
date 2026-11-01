// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestGitShellScriptOperand checks Git commands an argument list hands to a
// shell's -c. The shell runs its command string, so a builtin there keeps its
// own reading; anything the proof cannot read as submitted keeps the strictest
// verdict.
func TestGitShellScriptOperand(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, tc := range []struct {
		name  string
		args  []string
		allow bool
	}{
		{"bash builtin format", []string{"bash", "-c", "git ls-files --for=x"}, true},
		{"sh unused alias", []string{"sh", "-c", "git -c alias.l=push ls-files --for=x"}, true},
		{"wrapped shell two commands", []string{"env", "bash", "-c", "git status; git ls-files --for=x"}, true},
		{"zsh fetch force", []string{"zsh", "-c", "git fetch --force"}, true},
		{"expanded command prefix", []string{"bash", "-c", "$0 git fetch --force", "git"}, false},
		{"expanded later command", []string{"bash", "-c", "git ls-files --for=x; $0 --for", "git-push"}, false},
		{"glob command prefix", []string{"bash", "-c", "* git fetch --force"}, false},
		{"substituted command prefix", []string{"bash", "-c", "`basename gitx x` git ls-files --for"}, false},
		// Environment given to the shell may define git as a function.
		{"imported git function", []string{"env", "BASH_FUNC_git%%=() { shift; command $G $P \"$@\"; }", "bash", "-c", "git ls-files --for origin main"}, false},
		{"startup file", []string{"env", "BASH_ENV=/tmp/f", "bash", "-c", "git ls-files --for"}, false},
		{"wrapper without assignment", []string{"env", "-u", "push", "bash", "-c", "git ls-files --for=x"}, true},
		{"builtin destructive", []string{"bash", "-c", "git push --for origin"}, false},
		{"unknown subcommand", []string{"bash", "-c", "git pus --for"}, false},
		{"quoted subcommand", []string{"bash", "-c", "git 'ls-files' --for=x"}, false},
		{"invisible subcommand", []string{"bash", "-c", "git ls-f\u200biles --for=x"}, false},
		{"later alias", []string{"bash", "-c", "git ls-files --for=x; git l --for=x"}, false},
		// Words after the command string are positional parameters; they never run.
		{"positional words", []string{"bash", "-c", "git status", "git", "l", "--for=x"}, true},
		{"not a shell", []string{"python3", "-c", "git ls-files --for=x"}, false},
		{"option before -c", []string{"bash", "-e", "-c", "git ls-files --for=x"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for surface, got := range gitProofVerdicts(t, pc, "bash", tc.args, "argv") {
				if (got.Matched && got.Action == config.ActionBlock) == tc.allow {
					t.Errorf("%s: matched=%v rules=%v, want allow=%v", surface, got.Matched, got.Rules, tc.allow)
				}
			}
		})
	}
}

// An argument list element is a literal argument, so "$X" there is not
// expanded; with no recorded shape it may be shell text that expands to Git.
func TestGitShellScriptAfterExpansionWithoutShape(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	if got := pc.CheckToolCall("bash", []string{"$X", "bash", "-c", "git fetch --force"}); !got.Matched {
		t.Fatalf("expansion before a shell command string was allowed: %+v", got)
	}
}

// TestGitSubcommandNameAsWrapperValue checks that a bare Git subcommand name
// outside Git, such as env -u's value, does not lend Git's options to the
// command that follows.
func TestGitSubcommandNameAsWrapperValue(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, tc := range []struct {
		command string
		allow   bool
	}{
		{"env -u push git ls-files --for=x", true},
		// An expansion before git may be the executable itself.
		{"$CMD git fetch --force", false},
		{`"$CMD" git fetch --force`, false},
		{"$CMD\\\n git fetch --force", false},
		{"$CMD`true` git fetch --force", false},
		{"$CMD$(true) git fetch --force", false},
		{"$CMD\\; git fetch --force", false},
		// A command substitution's output may be the executable.
		{"`basename gitx x` git ls-files --for", false},
		{"git status; `basename gitx x` git ls-files --for", false},
		{`cd "/srv/repo" && git fetch --force`, true},
		{"env -u reset git -c alias.a=rm ls-files --for=x", true},
		{"env -u push git push --for", false},
		{"env -u push git l --for=x", false},
		{"sudo -u push -- git reset --ha", false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			for surface, got := range gitProofVerdicts(t, pc, "bash", []string{tc.command}, "command") {
				if (got.Matched && got.Action == config.ActionBlock) == tc.allow {
					t.Errorf("%s: matched=%v rules=%v, want allow=%v", surface, got.Matched, got.Rules, tc.allow)
				}
			}
		})
	}
}
