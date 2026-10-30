// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDefaultRules_CommandAfterItsArguments(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string // "" no verdict, incompletePairCheckRule, or a rule name
	}{
		// The words a command reads come before it.
		{"through cat to xargs", "echo -R 777 /srv | cat | xargs chmod", incompletePairCheckRule},
		{"piped to xargs", "echo -R 777 /srv | xargs chmod", incompletePairCheckRule},
		{"file then xargs <", "echo -R 777 /srv > /tmp/a; xargs chmod < /tmp/a", incompletePairCheckRule},
		{"file then xargs -a", "echo -R 777 /srv > /tmp/a && xargs -a /tmp/a chmod", incompletePairCheckRule},
		{"mode before flag", "echo 777 -R /srv | xargs chmod", incompletePairCheckRule},
		{"symbolic mode", "echo -R o+w /srv | xargs chmod", incompletePairCheckRule},
		{"redirect before the words", "echo 2>&1 -R 777 /srv | xargs chmod", incompletePairCheckRule},
		{"output discarded before the words", "echo &>/dev/null -R 777 /srv | xargs chmod", incompletePairCheckRule},
		{"command by path", "echo -R 777 /srv | xargs /bin/chmod", incompletePairCheckRule},
		// Controls: in order on the command itself.
		{"in order", "chmod -R 777 /srv", rulePermissions},
		{"in order after a pipe", "echo /srv | xargs chmod -R 777", rulePermissions},
		// Benign twins: a part is missing, so no verdict and no flag.
		{"mode not world writable", "echo 755 ./build | xargs chmod", ""},
		{"no mode", "echo -R ./build | xargs chmod", ""},
		{"no recursive flag", "echo 777 ./build | xargs chmod", ""},
		{"parts after the command", "xargs chmod < list; echo -R 777", incompletePairCheckRule},
		{"file not read back", "echo -R 777 /srv > /tmp/a; xargs chmod < /tmp/b", incompletePairCheckRule},
		{"no command word", "echo -R 777 /srv | xargs ls", ""},
		{"plain xargs", "find . -name '*.sh' | xargs chmod +x", incompletePairCheckRule},
	}
	for _, mode := range []string{config.ActionWarn, config.ActionBlock} {
		pc := defaultConfigWithIncomplete(t, mode)
		for _, tt := range tests {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				v := pc.CheckToolCall("bash", []string{tt.cmd})
				switch tt.want {
				case "":
					if v.Matched || len(v.IncompleteRules) > 0 {
						t.Fatalf("verdict %q %v %v, want none", v.Action, v.Rules, v.IncompleteRules)
					}
				case incompletePairCheckRule:
					if !slices.Equal(v.Rules, []string{incompletePairCheckRule}) || v.Action != mode ||
						!slices.Equal(v.IncompleteRules, []string{rulePermissions}) {
						t.Fatalf("verdict %q %v %v, want %s for %s with action %s",
							v.Action, v.Rules, v.IncompleteRules, incompletePairCheckRule, rulePermissions, mode)
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

func TestLeadingWords(t *testing.T) {
	// Words are case-folded (see foldString).
	tests := []struct {
		pat  string
		want []string
	}{
		{`\brm\s+-rf`, []string{"rm"}},
		{`(?i)\b(chmod\s+-R|chown\s+-R)`, []string{"chmod", "chown"}},
		{`^git\s+push`, []string{"git"}},
		{`(?:a|bc)\s+x`, []string{"a", "bc"}},
		{`\s+rm`, nil},
		{`(?:rm)?\s+-rf`, nil},
		{`.*rm`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.pat, func(t *testing.T) {
			got := leadingWords(regexp.MustCompile(tt.pat))
			slices.Sort(got)
			for i, w := range tt.want {
				tt.want[i] = foldString(w)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("leadingWords(%q) = %q, want %q", tt.pat, got, tt.want)
			}
		})
	}
}

func TestCommandAfterParts(t *testing.T) {
	three := regexp.MustCompile(`\bchmod(?:\s+[^\s;|&]+)*?\s+-R(?:\s+[^\s;|&]+)*?\s+777`)
	two := regexp.MustCompile(`\brm(?:\s+[^\s;|&]+)*?\s+-rf`)
	tests := []struct {
		name string
		pat  *regexp.Regexp
		segs [][]string
		want bool
	}{
		{"parts before command", three, [][]string{{"echo", "-R", "777", "/srv", "|", "xargs", "chmod"}}, true},
		{"operators cut from words", three, [][]string{{"echo", "-R", "777", "/srv;", "xargs", "chmod", "<", "/tmp/a"}}, true},
		{"second command", three, [][]string{{"ls"}, {"echo", "-R", "777", "|", "xargs", "chmod"}}, true},
		{"part missing", three, [][]string{{"echo", "-R", "755", "|", "xargs", "chmod"}}, false},
		{"parts in other command", three, [][]string{{"echo", "-R", "777"}, {"xargs", "chmod"}}, false},
		{"command first", three, [][]string{{"chmod", "x", "|", "echo", "-R", "777"}}, false},
		{"one word is enough", two, [][]string{{"echo", "-rf", "|", "xargs", "rm"}}, false},
		{"one word is enough, three part pattern", three, [][]string{{"echo", "-R 777", "|", "xargs", "chmod"}}, false},
		{"no segments", three, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := commandAfterParts(tt.pat, tt.segs); got != tt.want {
				t.Fatalf("commandAfterParts = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCommandAfterPartsSharedMatchesUnshared checks that results shared between
// the views of one check are reused only where the text checked is the same:
// each view gets exactly its own commandAfterParts result, in either order.
func TestCommandAfterPartsSharedMatchesUnshared(t *testing.T) {
	pat := regexp.MustCompile(`chmod\b.*-R\b.*\b777\b`)
	views := map[string][]string{
		// chmod is at the same position in each; the words before it differ
		// (-R or -v), or only the words after it do.
		"handed-words-match": strings.Fields("echo -R 777 x | xargs chmod"),
		"earlier-word-only":  strings.Fields("echo -v 777 x | xargs chmod"),
		"later-words-only":   strings.Fields("echo -R 777 x | xargs chmod --quiet"),
	}
	for _, pair := range [][2]string{
		{"handed-words-match", "earlier-word-only"},
		{"earlier-word-only", "handed-words-match"},
		{"handed-words-match", "later-words-only"},
		{"later-words-only", "earlier-word-only"},
	} {
		memo := &afterPartsMemo{segs: map[int]*afterPartsSeg{}}
		for _, name := range pair {
			segs := [][]string{views[name]}
			if got, want := commandAfterPartsShared(pat, segs, memo), commandAfterParts(pat, segs); got != want {
				t.Errorf("%s after %s: shared result %v, own result %v", name, pair[0], got, want)
			}
		}
	}
	if !commandAfterParts(pat, [][]string{views["handed-words-match"]}) || commandAfterParts(pat, [][]string{views["earlier-word-only"]}) {
		t.Fatal("fixture: the two views must differ in their own results")
	}
}
