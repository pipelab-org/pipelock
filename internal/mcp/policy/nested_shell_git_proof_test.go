// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestNestedShellGitProofSeparator checks a destructive Git option abbreviation
// after a command separator inside a nested shell script. The builtin proof
// must not cover that option: the nested shell runs the text after the
// separator as its own command.
func TestNestedShellGitProofSeparator(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{`bash -c "echo hi; git fetch --har"`, true},
		{`sh -c "echo hi; git fetch --har"`, true},
		{`dash -c "echo hi; git fetch --har"`, true},
		{`zsh -c "echo hi; git fetch --har"`, true},
		{`bash -lc "echo hi; git fetch --har"`, true},
		{`bash -ce "echo hi; git fetch --har"`, true},
		{`bash -o errexit -c "echo hi; git fetch --har"`, true},
		{`sudo bash -c "echo hi; git fetch --har"`, true},
		{`bash -c "echo hi && git fetch --har"`, true},
		{`bash -c "echo hi || git fetch --har"`, true},
		{`bash -c "echo hi | git fetch --har"`, true},
		{"bash -c \"echo hi\ngit fetch --har\"", true},
		{`bash -c 'echo hi; git fetch --har'`, true},
		{`bash -c "echo hi; git fetch --force"`, true},
		{`bash -c "echo hi;git fetch --har"`, true},
		// Benign nested scripts and top-level commands.
		{`bash -c "echo hi; git status"`, false},
		{`bash -c "git fetch origin"`, false},
		{`bash -c "git log --oneline; echo done"`, false},
		{`git fetch --har`, false},
		{`echo hi; git fetch --har`, false},
		{`bash -c "git fetch origin"; git status`, false},
		{`git fetch --force`, false},
		{`git fetch --force; echo done`, false},
		// A quoted operand is not a nested script. These keep the readings
		// they have without one: a separator glued to the option stays a
		// proved builtin, a space-separated separator does not, and quoted
		// --hard text stays denied.
		{`git ls-files "--for=%(path); git fetch --har"`, false},
		{`git log --oneline '--format=%H; git fetch --har'`, false},
		{`git ls-files '--for=%(path) ; git fetch'`, true},
		{`echo "git fetch --hard is bad"`, true},
		{`echo 'git fetch --hard is bad'`, true},
	} {
		t.Run(tc.command, func(t *testing.T) {
			for surface, got := range gitProofVerdicts(t, pc, "bash", []string{tc.command}, "command") {
				if blocked := got.Matched && got.Action == config.ActionBlock; blocked != tc.block {
					t.Errorf("%s: matched=%v rules=%v, want block=%v", surface, got.Matched, got.Rules, tc.block)
				}
			}
		})
	}
	// An argument list already leaves the script as one literal element.
	for _, args := range [][]string{
		{"bash", "-c", "echo hi; git fetch --har"},
		{"sh", "-c", "echo hi; git fetch --har"},
		{"bash", "-c", "echo hi && git fetch --har"},
		{"bash", "-c", "echo hi | git fetch --har"},
		{"bash", "-c", "echo hi\ngit fetch --har"},
	} {
		t.Run("argv/"+strings.Join(args, " "), func(t *testing.T) {
			for surface, got := range gitProofVerdicts(t, pc, "bash", args, "argv") {
				if !got.Matched || got.Action != config.ActionBlock {
					t.Errorf("%s: matched=%v rules=%v, want block", surface, got.Matched, got.Rules)
				}
			}
		})
	}
}
