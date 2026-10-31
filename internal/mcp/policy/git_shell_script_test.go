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
				if got.Matched == tc.allow {
					t.Errorf("%s: matched=%v rules=%v, want allow=%v", surface, got.Matched, got.Rules, tc.allow)
				}
			}
		})
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
		{"env -u reset git -c alias.a=rm ls-files --for=x", true},
		{"env -u push git push --for", false},
		{"env -u push git l --for=x", false},
		{"sudo -u push -- git reset --ha", false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			for surface, got := range gitProofVerdicts(t, pc, "bash", []string{tc.command}, "command") {
				if got.Matched == tc.allow {
					t.Errorf("%s: matched=%v rules=%v, want allow=%v", surface, got.Matched, got.Rules, tc.allow)
				}
			}
		})
	}
}
