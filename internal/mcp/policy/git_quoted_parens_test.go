// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestGitQuotedParentheses(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{`git ls-files '--for=%(path)'`, false},
		{`git log --oneline '--for=%(x)'`, false},
		{`git -c alias.a=push ls-files '--for=%(path)'`, false},
		{`git -c alias.a=rm ls-files '--for=%(path)'`, false},
		{`git -c alias.a=push -c alias.b=rm ls-files '--for=%(path)'`, false},
		{`sudo -u reset git -c alias.a=push ls-files '--for=%(path)'`, false},
		{`sudo git -c alias.a=push ls-files '--for=%(path)'`, false},
		{`git ls-files --for=path`, false},
		{`git ls-files '--format=%(path)'`, false},
		{`git for-each-ref --format='%(refname)'`, false},
		{`git branch '--format=%(refname:short)'`, false},
		{`echo '(hi)' && git status --short`, false},
		{`git ls-files "--for=%(path)"`, false},
		{`git ls-files '--for=%(path with spaces)'`, false},
		{`git ls-files '--for=%("path")'`, false},
		{`git ls-files "--for=%('path')"`, false},
		{`git ls-files --for='%(path)'`, false},
		{`git ls-files '--for=%(''path'')'`, false},
		{`git -c alias.a=push -c alias.l=ls-files l '--for=%(path)'`, true},
		{`git ls-files '--for=x' ')' push --force`, true},
		{`git ls-files '--for=%(' ; git push --force`, true},
		{`git ls-files '--for=%(path)`, true},
		{`git ls-files "--for=%(path)`, true},
		{`( git push --force )`, true},
		{`(git ls-files '--for=%(path)')`, true},
		{`git ls-files '--for=%(')git push --force`, true},
		{`(git ls-files '--for=%(path)'; git push --force)`, true},
		{`(git ls-files '--for=%(path)') && git push --force`, true},
		{`git ls-files '--for=%(path)'$(git push --force)`, true},
		{`git ls-files '--for=%(path)' ; (git push --force)`, true},
		{`git ls-files '--for=%(path)'); git push --force; (echo ok)`, true},
		{`git ls-files '--for=%(path)' "$(git push --force)"`, true},
		{"git ls-files '--for=%(path)' `git push --force`", true},
		{`git $X --force`, true},
		{`$CMD git ls-files '--for=%(path)'`, true},
		{`"$CMD" git ls-files '--for=%(path)'`, true},
		{`$(printf git) ls-files '--for=%(path)'`, true},
		{"`printf git` ls-files '--for=%(path)'", true},
		{`git ls-files "--for=%(\"path\")"; git push --force`, true},
		{`git ls-files '--for=%(path)'\); git push --force`, true},
		{`git ls-files $'--for=%(path)'; git push --force`, true},
		{`git ls-files $'--for=%(path)'`, true},
		{`git ls-files "--for=%(\"path\")"`, true},
		{`git ls-files "--for=%($(printf path))"`, true},
		{`git ls-files '--for=%(path)' >/tmp/output`, true},
		{`git ls-files $'--for=%(\x27)'; git push --force`, true},
		{`git ls-files $'--for=%(\'path\')'; git push --force`, true},
		{`git ls-files '--for=%(path)' "$(printf '%s' "$(git push --force)")"`, true},
	} {
		t.Run(tc.command, func(t *testing.T) {
			verdicts := gitProofVerdicts(t, pc, "bash", []string{tc.command}, "command")
			raw, err := json.Marshal(map[string]string{"command": tc.command})
			if err != nil {
				t.Fatal(err)
			}
			verdicts["CheckShellCommand"] = pc.CheckShellCommand(tc.command, raw)
			for surface, got := range verdicts {
				t.Logf("%s: matched=%v action=%s rules=%v", surface, got.Matched, got.Action, got.Rules)
				if tc.block {
					if !got.Matched || got.Action != config.ActionBlock {
						t.Errorf("%s: got %+v, want block", surface, got)
					}
				} else if got.Matched {
					t.Errorf("%s: got %+v, want no match", surface, got)
				}
			}
		})
	}
}

func TestGitQuotedParenthesesArgv(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	for _, tc := range []struct {
		args  []string
		block bool
	}{
		{[]string{"git", "-c", "alias.a=push", "ls-files", "--for=%(path)"}, false},
		{[]string{"git", "ls-files", "--for=%(path)"}, false},
		{[]string{"bash", "-c", "git ls-files '--for=%(path)'"}, true},
	} {
		for surface, got := range gitProofVerdicts(t, pc, "bash", tc.args, "argv") {
			t.Logf("%q %s: matched=%v action=%s rules=%v", tc.args, surface, got.Matched, got.Action, got.Rules)
			if got.Matched != tc.block || tc.block && got.Action != config.ActionBlock {
				t.Errorf("%q %s: got %+v, want block=%v", tc.args, surface, got, tc.block)
			}
		}
	}
}
