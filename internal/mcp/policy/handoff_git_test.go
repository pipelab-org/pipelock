// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestLeadingWords_OptionalLeadingParts checks words after an optional or
// repeated part at the start of a pattern.
func TestLeadingWords_OptionalLeadingParts(t *testing.T) {
	tests := []struct {
		pat  string
		want []string
	}{
		{`(\bgit\s+)?(push|clean)\s`, []string{"clean", "git", "push"}},
		{`(?:sudo\s+)?rm\s`, []string{"rm", "sudo"}},
		{`(?:sudo\s+)*rm\s`, []string{"rm", "sudo"}},
		{`(?:sudo\s+)+rm\s`, []string{"sudo"}},
		{`(?:ab|cd)?(?:ef|gh)?x`, []string{"ab", "cd", "efx", "ghx", "x"}},
		// Inside a word an optional part still ends it.
		{`rm(?:dir)?\s`, []string{"rm"}},
		// Nothing literal leads.
		{`(?:rm)?\s+-rf`, nil},
		{`\s*rm`, nil},
		{`.*rm`, nil},
		{`(?:a?b?)x`, []string{"a", "bx", "x"}},
		// More ways to start than are kept, even when they are the same word.
		{`(?:a?b?c?d?e?f?){8}x`, nil},
		{`(?:\b?){20}x`, nil},
		// Too much work for one pattern, and a control.
		{strings.Repeat(`\b`, maxLeadWordSteps) + `x`, nil},
		{strings.Repeat(`\b`, 100) + `x`, []string{"x"}},
	}
	for _, tt := range tests {
		name := tt.pat
		if len(name) > 40 {
			name = name[:40]
		}
		t.Run(name, func(t *testing.T) {
			got := leadingWords(regexp.MustCompile(tt.pat))
			want := make([]string, len(tt.want))
			for i, w := range tt.want {
				want[i] = foldString(w)
			}
			if len(want) == 0 {
				want = nil
			}
			if !slices.Equal(got, want) {
				t.Fatalf("leadingWords(%q) = %q, want %q", tt.pat, got, want)
			}
		})
	}
}

// TestLeadingWords_BuiltinGitRule checks the built-in git rule gets its
// command words.
func TestLeadingWords_BuiltinGitRule(t *testing.T) {
	for _, r := range DefaultToolPolicyRules() {
		if r.Name != ruleGit {
			continue
		}
		got := leadingWords(regexp.MustCompile(r.ArgPattern))
		for _, w := range []string{"git", "push", "reset", "clean"} {
			if !slices.Contains(got, foldString(w)) {
				t.Fatalf("leadingWords(%s) = %q, missing %q", r.Name, got, w)
			}
		}
		return
	}
	t.Fatalf("no %s rule", ruleGit)
}

// TestDefaultRules_GitHandOffs checks git commands given their flags by
// another command.
func TestDefaultRules_GitHandOffs(t *testing.T) {
	inc := incompletePairCheckRule
	runVerdictRows(t, []verdictRow{
		{"flags piped to xargs", "echo -f -d | xargs git clean", inc, ruleGit},
		{"flags piped, reversed", "echo -d -f | xargs git clean", inc, ruleGit},
		{"flags piped, text not split", "echo -f -d $x | xargs git clean", inc, ruleGit},
		{"flags through a file", "echo -f -d > /tmp/a; xargs git clean < /tmp/a", inc, ruleGit},
		{"own flag, handed flag", "echo -d | xargs git clean -f", inc, ruleGit},
		{"own flag, handed flag, reversed", "echo -f | xargs git clean -d", inc, ruleGit},
		{"handed force push", "echo -f origin | xargs git push", ruleGit, ""},
		{"here-string", "git clean <<<'-f -d'", ruleGit, ""},
		{"clean without git", "echo -f -d | xargs clean", inc, ruleGit},
		// Benign twins.
		{"dry run", "echo -n -d | xargs git clean", "", ""},
		{"another subcommand", "echo -f -d | xargs git status", "", ""},
		{"own dry run", "echo -d | xargs git clean -n", "", ""},
		{"plain push", "echo origin main | xargs git push", "", ""},
	})
}

// TestCommandAfterParts_GitWords checks the git rule's words are found in
// a hand-off.
func TestCommandAfterParts_GitWords(t *testing.T) {
	var pat *regexp.Regexp
	for _, r := range DefaultToolPolicyRules() {
		if r.Name == ruleGit {
			pat = regexp.MustCompile(r.ArgPattern)
		}
	}
	if pat == nil {
		t.Fatalf("no %s rule", ruleGit)
	}
	tests := []struct {
		cmd  string
		want bool
	}{
		{"echo -f -d | xargs git clean", true},
		{"echo -n -d | xargs git clean", false},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			if got := commandAfterParts(pat, [][]string{strings.Fields(tt.cmd)}); got != tt.want {
				t.Fatalf("commandAfterParts = %v, want %v", got, tt.want)
			}
		})
	}
}
