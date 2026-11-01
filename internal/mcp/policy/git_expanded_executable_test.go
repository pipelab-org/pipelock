// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestGitShellScriptOperandStaysStrict checks Git commands an argument list
// hands to a shell's -c. The proof does not read the command string, because
// the shell's environment, startup files and aliases can redefine git there,
// so a long option word keeps the strictest reading even for a builtin.
func TestGitShellScriptOperandStaysStrict(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, args := range [][]string{
		{"bash", "-c", "git ls-files --for=x"},
		{"sh", "-c", "git -c alias.l=push ls-files --for=x"},
		{"bash", "-c", "$0 git fetch --force", "git"},
		{"bash", "-c", "git ls-files --for=x; $0 --for", "git-push"},
		{"bash", "-c", "exec -agit-push git ls-files --for"},
		{"env", "BASH_ENV=/tmp/f", "bash", "-c", "git ls-files --for"},
		{"zsh", "-c", "git ls-files --for"},
		{"env", "--argv0=git-push", "git", "ls-files", "--for"},
	} {
		for surface, got := range gitProofVerdicts(t, pc, "bash", args, "argv") {
			if !got.Matched || got.Action != config.ActionBlock {
				t.Errorf("%q %s: matched=%v rules=%v, want block", args, surface, got.Matched, got.Rules)
			}
		}
	}
}

// TestGitExpandedExecutable checks a Git command whose executable may come from
// a shell expansion, a substitution or an argv[0] rename. Git can then run an
// alias or another builtin instead of the subcommand the text shows, so its
// options keep the strictest reading.
func TestGitExpandedExecutable(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, tc := range []struct {
		command string
		allow   bool
	}{
		// An expansion before git may be the executable itself.
		{"$CMD git fetch --force", false},
		{`"$CMD" git fetch --force`, false},
		{"$CMD\\\n git fetch --force", false},
		{"$CMD`true` git fetch --force", false},
		{"$CMD$(true) git fetch --force", false},
		{"$CMD\\; git fetch --force", false},
		// Git runs the builtin its argv[0] names as git-<name>.
		{"exec -agit-push git ls-files --for", false},
		{"env --argv0=git-push git ls-files --for", false},
		{"ARGV0=git-push git ls-files --for", false},
		{"sudo -u git-user git ls-files --for=x", true},
		// A command substitution's output may be the executable.
		{"`basename gitx x` git ls-files --for", false},
		{"git status; `basename gitx x` git ls-files --for", false},
		{`cd "/srv/repo" && git fetch --force`, true},
		// A bare subcommand word may name a function, so env -u's value keeps
		// the conservative reading.
		{"env -u push git ls-files --for=x", false},
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

// TestGitSubcommandWordAsExecutable checks that a bare subcommand word may
// itself be the executable. It must not lend a later Git operand a proof.
func TestGitSubcommandWordAsExecutable(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, words := range [][]string{
		{"push", "--for"},
		{"reset", "--ha"},
		{"clean", "-d", "--fo"},
		{"push", "git", "ls-files", "--for"},
		{"reset", "git", "ls-files", "--ha"},
		{"clean", "-d", "git", "ls-files", "--fo"},
		{"env", "-u", "push", "-Sgit", "git", "ls-files", "--for"},
		{"env", "--unset", "reset", "--split-string=git", "git", "ls-files", "--ha"},
		{"env", "push", "git", "ls-files", "--for"},
		{"env", "-u", "NAME", "push", "git", "ls-files", "--for"},
		{"env", "--", "push", "git", "ls-files", "--for"},
		{"sudo", "push", "git", "ls-files", "--for"},
		{"env", "-u", "push", "push", "git", "ls-files", "--for"},
	} {
		for _, key := range []string{"command", "argv"} {
			args := words
			if key == "command" {
				args = []string{strings.Join(words, " ")}
			}
			for surface, got := range gitProofVerdicts(t, pc, "bash", args, key) {
				if !got.Matched || got.Action != config.ActionBlock {
					t.Errorf("%q %s %s: got %+v, want block", words, key, surface, got)
				}
			}
		}
	}
	for _, command := range []string{
		`env -u push git ls-files --for=x; $X --for`,
		`env -u push git ls-files --for=x && $X --for`,
		`env -u push git ls-files --for=x | $X --for`,
		`G=git; P=git; clean(){ command "$G" "$P" "$@"; }; clean -d --fo`,
		`G=git; env(){ shift; shift; command "$G" "$@"; }; env -u push git ls-files --for`,
		`G=git; function env { shift; shift; command "$G" "$@"; }; env --unset push git ls-files --for`,
		`G=git; push(){ command "$G" "$@"; }; push git ls-files --for`,
		`G=git; reset(){ command "$G" "$@"; }; reset git ls-files --ha`,
		`G=git; clean(){ command "$G" "$@"; }; clean -d git ls-files --fo`,
	} {
		for surface, got := range gitProofVerdicts(t, pc, "bash", []string{command}, "command") {
			if !got.Matched || got.Action != config.ActionBlock {
				t.Errorf("%q %s: got %+v, want block", command, surface, got)
			}
		}
	}
}

// TestVariableCommandName checks a command whose name the shell expands, such
// as $X: it may run Git with any subcommand, so its long options keep the
// strictest reading. Assignments before the name, earlier commands and
// literal argument-list elements do not count as an expanded name.
func TestVariableCommandName(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{`X="git push"; $X --force origin main`, true},
		{"$X --force origin main", true},
		{"git ls-files --for=x; $X --force", true},
		{"FOO=1 $X --force", true},
		{`"$CMD" --for`, true},
		// A variable program with a force- or hard-like option is blocked
		// even when it is not Git.
		{"$HOME/bin/deploy --force", true},
		{"$EDITOR notes.txt", false},
		{"$CC --help", false},
		{"FOO=bar git fetch --force", false},
		{`cd "/srv/repo" && git fetch --force`, false},
		{"# note\ngit fetch --force", false},
	} {
		for surface, got := range gitProofVerdicts(t, pc, "bash", []string{tc.command}, "command") {
			if (got.Matched && got.Action == config.ActionBlock) != tc.block {
				t.Errorf("%q %s: matched=%v rules=%v, want block=%v", tc.command, surface, got.Matched, got.Rules, tc.block)
			}
		}
	}
	// Without a recorded shape the values may be shell text, so only the
	// shaped surfaces know these elements are literal.
	for surface, got := range gitProofVerdicts(t, pc, "bash", []string{"$X", "--force"}, "argv") {
		if surface != "CheckToolCall" && got.Matched {
			t.Errorf("literal argv $X %s: matched=%v rules=%v, want allow", surface, got.Matched, got.Rules)
		}
	}
}
