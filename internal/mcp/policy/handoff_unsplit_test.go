// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"regexp"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// verdictRow is one command and the verdict the default rules should give
// it: want is "" for none, a rule name for a full match, or
// incompletePairCheckRule, with inc the rule whose check was incomplete.
type verdictRow struct {
	name, cmd, want, inc string
}

// runVerdictRows checks each row with on_incomplete_check set to warn and to
// block.
func runVerdictRows(t *testing.T, rows []verdictRow) {
	t.Helper()
	for _, mode := range []string{config.ActionWarn, config.ActionBlock} {
		pc := defaultConfigWithIncomplete(t, mode)
		for _, tt := range rows {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				v := pc.CheckToolCall("bash", []string{tt.cmd})
				switch tt.want {
				case "":
					if v.Matched || len(v.IncompleteRules) > 0 {
						t.Fatalf("verdict %q %v %v, want none", v.Action, v.Rules, v.IncompleteRules)
					}
				case incompletePairCheckRule:
					if !slices.Equal(v.Rules, []string{incompletePairCheckRule}) || v.Action != mode ||
						!slices.Contains(v.IncompleteRules, tt.inc) {
						t.Fatalf("verdict %q %v %v, want %s for %s with action %s",
							v.Action, v.Rules, v.IncompleteRules, incompletePairCheckRule, tt.inc, mode)
					}
				default:
					if !v.Matched || !slices.Contains(v.Rules, tt.want) || slices.Contains(v.Rules, incompletePairCheckRule) {
						t.Fatalf("verdict %v %q %v, want %q", v.Matched, v.Action, v.Rules, tt.want)
					}
				}
			})
		}
	}
}

// TestDefaultRules_HandOffsTheSplitterCannotRead checks hand-offs of a
// command's words through text commandSegments does not split, through a
// copied, moved or linked file, through a here-string, and after the
// command's own words.
func TestDefaultRules_HandOffsTheSplitterCannotRead(t *testing.T) {
	inc := incompletePairCheckRule
	runVerdictRows(t, []verdictRow{
		// Text the splitter does not read.
		{"escaped command", `echo -R 777 /srv | xargs \chmod`, inc, rulePermissions},
		{"dollar in a comment", "echo -R 777 /srv | xargs chmod # $x", inc, rulePermissions},
		{"quoted variable", `echo -R 777 "$HOME" | xargs chmod`, inc, rulePermissions},
		{"subshell", "(echo -R 777 /srv) | xargs chmod", inc, rulePermissions},
		{"braces", "{ echo -R 777 /srv; } | xargs chmod", inc, rulePermissions},
		{"printf escape", `printf '%s\n' -R 777 /srv | xargs chmod`, inc, rulePermissions},
		{"backticks", "echo -R 777 `pwd` | xargs chmod", inc, rulePermissions},
		{"command substitution", "echo -R 777 $(pwd) | xargs chmod", inc, rulePermissions},
		{"own words, unsplit", "echo 777 $HOME | xargs chmod -R", inc, rulePermissions},
		// Files copied, moved or linked on.
		{"copied file", "echo -R 777 /srv > /tmp/a; cp /tmp/a /tmp/b; xargs chmod < /tmp/b", inc, rulePermissions},
		{"moved file", "echo -R 777 /srv > /tmp/a; mv /tmp/a /tmp/b; xargs -a /tmp/b chmod", inc, rulePermissions},
		{"linked file", "echo -R 777 /srv > /tmp/a; ln -s /tmp/a /tmp/b; xargs chmod < /tmp/b", inc, rulePermissions},
		{"installed file", "echo -R 777 /srv > /tmp/a; install /tmp/a /tmp/b; xargs chmod < /tmp/b", inc, rulePermissions},
		{"dd copy", "echo -R 777 /srv > /tmp/a; dd if=/tmp/a of=/tmp/b; xargs chmod < /tmp/b", inc, rulePermissions},
		{"./a then a", "echo -R 777 /srv > a; xargs chmod < ./a", inc, rulePermissions},
		// The command's own words come first.
		{"own flag, handed mode", "echo 777 /srv | xargs chmod -R", inc, rulePermissions},
		{"own mode, handed flag", "echo -R /srv | xargs chmod 777", inc, rulePermissions},
		// Here-strings are the command's input.
		{"here-string", "xargs chmod <<<'-R 777 /srv'", rulePermissions, ""},
		{"here-string, double quotes", `xargs chmod <<<"-R 777 /srv"`, rulePermissions, ""},
		{"here-string, spaced", "xargs chmod <<< '-R 777 /srv'", rulePermissions, ""},
		// Controls in order, unsplit.
		{"in order, unsplit", `chmod -R 777 "$HOME"`, rulePermissions, ""},
		// Benign twins: a part is missing, so no verdict and no flag.
		{"mode not world writable, unsplit", `echo 755 $HOME | xargs \chmod`, inc, rulePermissions},
		{"no mode, subshell", "(echo -R ./build) | xargs chmod", inc, rulePermissions},
		{"no command word, unsplit", "echo -R 777 $HOME | xargs ls", "", ""},
		{"copy not read back", "echo -R 777 /srv > /tmp/a; cp /tmp/a /tmp/b; xargs chmod < /tmp/c", inc, rulePermissions},
		{"other file copied", "echo -R 777 /srv > /tmp/a; cp /tmp/c /tmp/b; xargs chmod < /tmp/b", inc, rulePermissions},
		{"own words, mode not world writable", "echo 755 /srv | xargs chmod -R", "", ""},
		{"own words, no flag", "echo /srv | xargs chmod 777", "", ""},
		{"here-string, no flag", "xargs chmod <<<'644 /srv'", inc, rulePermissions},
		{"several values", "echo a b c $HOME | xargs ls -la", "", ""},
	})
}

func TestCommandAfterParts_OwnWords(t *testing.T) {
	three := regexp.MustCompile(`\bchmod(?:\s+[^\s;|&]+)*?\s+-R(?:\s+[^\s;|&]+)*?\s+777`)
	tests := []struct {
		name string
		segs [][]string
		want bool
	}{
		{"own flag then handed mode", [][]string{{"echo", "777", "|", "xargs", "chmod", "-R"}}, true},
		{"earlier command word", [][]string{{"echo", "777", "|", "xargs", "chmod", "-R", "|", "xargs", "chmod", "644"}}, true},
		{"own words alone are the command's", [][]string{{"echo", "x", "|", "xargs", "chmod", "-R", "777"}}, false},
		{"own flag, no mode handed", [][]string{{"echo", "755", "|", "xargs", "chmod", "-R"}}, false},
		{"no words before", [][]string{{"chmod", "-R", "|", "echo", "777"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := commandAfterParts(three, tt.segs); got != tt.want {
				t.Fatalf("commandAfterParts = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommandSegments_CopiedFiles(t *testing.T) {
	tests := []struct {
		cmd  string
		want int
	}{
		{"echo x > /tmp/a; cp /tmp/a /tmp/b; cat /tmp/b", 1},
		{"echo x > /tmp/a; mv /tmp/a /tmp/b; cat /tmp/b", 1},
		{"echo x > /tmp/a; ln -s /tmp/a /tmp/b; cat /tmp/b", 1},
		{"echo x > /tmp/a; dd if=/tmp/a of=/tmp/b; cat /tmp/b", 1},
		{"echo x > /tmp/a; cp /tmp/a /tmp/b; cp /tmp/b /tmp/c; cat /tmp/c", 1},
		{"echo x > a; cat ./a", 1},
		{"echo x > ./a; cat a", 1},
		{"echo x > /tmp//a; cat /tmp/a", 1},
		// Controls.
		{"echo x > /tmp/a; cp /tmp/c /tmp/b; cat /tmp/b", 3},
		{"echo x > /tmp/a; cp /tmp/a /tmp/b; cat /tmp/d", 2},
		{"echo x; cp -r a b; ls", 3},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			if got := commandSegments([]string{tt.cmd}); len(got) != tt.want {
				t.Fatalf("commandSegments = %q, want %d parts", got, tt.want)
			}
		})
	}
}

func TestHereStringData(t *testing.T) {
	tests := []struct {
		tokens []string
		want   []string
		ok     bool
	}{
		{[]string{"xargs", "chmod", "<<<-R", "777"}, []string{"xargs", "chmod", "-R", "777"}, true},
		{[]string{"cat", "<<<", "x", "2>&1"}, []string{"cat", "x"}, false},
		{[]string{"cat", "<", "f"}, []string{"cat", "f"}, false},
	}
	for _, tt := range tests {
		got, ok := hereStringData(tt.tokens)
		if ok != tt.ok || (ok && !slices.Equal(got, tt.want)) {
			t.Errorf("hereStringData(%q) = %q, %v; want %q, %v", tt.tokens, got, ok, tt.want, tt.ok)
		}
	}
}
