// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// objFiles returns n short object file names (f0.o, f1.o, ...).
func objFiles(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "f" + strconv.Itoa(i) + ".o"
	}
	return out
}

// cmd joins words into one command string.
func cmd(words ...[]string) string {
	var all []string
	for _, w := range words {
		all = append(all, w...)
	}
	return strings.Join(all, " ")
}

func w(words ...string) []string { return words }

func TestDefaultRules_LongCommandShapes(t *testing.T) {
	longFlag := "-rf" + strings.Repeat("f", 28)
	tests := []struct {
		name string
		args []string
		rule string // "" means no verdict
	}{
		// Redirections, quoting and paths to the command.
		{"redirect between command and files", w(cmd(w("rm", "2>&1"), objFiles(62), w("-rf", "/srv/data"))), ruleFileDelete},
		{"redirect, 200 files", w(cmd(w("rm", "2>&1"), objFiles(200), w("-rf", "/srv/data"))), ruleFileDelete},
		{"command by path", w(cmd(w("/bin/rm", "2>&1"), objFiles(62), w("-rf", "/srv/data"))), ruleFileDelete},
		{"output discarded", w(cmd(w("rm", "&>/dev/null"), objFiles(62), w("-rf", "/srv/data"))), ruleFileDelete},
		{"quoted separator", w(cmd(w("rm", "'a;b'"), objFiles(62), w("-rf", "/srv/data"))), ruleFileDelete},
		{"push with redirect", w(cmd(w("git", "push", "2>&1", "origin"), shortWords(200), w("--force"))), ruleGit},
		{"chmod with redirect", w(cmd(w("chmod", "2>&1"), pathOperands(200), w("-R", "777"))), rulePermissions},
		// Argument arrays.
		{"array, files before flag", append(append(objFiles(70), "-rf", "/srv/data"), "rm"), ruleFileDelete},
		{"array, flag then words", append(w("rm", "-rf"), shortWords(63)...), ruleFileDelete},
		{"array, flag first, command last", append(append(w("-rf"), shortWords(63)...), "rm"), ruleFileDelete},
		// Piped into a command that runs its input.
		{"piped to xargs", w(cmd(w("echo", "-rf"), shortWords(60), w("/srv/data", "|", "xargs", "rm"))), ruleFileDelete},
		{"piped to xargs, 200 words", w(cmd(w("echo", "-rf"), shortWords(200), w("/srv/data", "|", "xargs", "rm"))), ruleFileDelete},
		{"printf to xargs", w(cmd(w("printf", `'%s\n'`, "-rf"), shortWords(70), w("/srv/data", "|", "xargs", "rm"))), ruleFileDelete},
		{"piped to xargs, short", w("echo -rf /srv/data | xargs rm"), ruleFileDelete},
		// A long option after a full set of paths.
		{"long flag after paths", w(cmd(w("rm", "2>&1"), pathOperands(2100), w(longFlag, "/srv"))), ruleFileDelete},
		// Separate commands are paired within each command first. A match
		// only across commands is reported as incomplete, not as clean,
		// unless the check before commands were split matched it: up to 64
		// tokens, any pair of tokens still matches.
		{"delete then extract", w(cmd(w("rm"), pathOperands(70), w("&&", "tar", "-xf", "new.tar"))), incompletePairCheckRule},
		{"delete then group write", w(cmd(w("rm"), pathOperands(70), w("&&", "chmod", "-R", "g+w", "./out"))), incompletePairCheckRule},
		{"push then follow logs", w(cmd(w("git", "push", "origin", "main", "&&", "tail", "-f"), pathOperands(70))), incompletePairCheckRule},
		{"short delete then extract", w("rm old.tar && tar -xf new.tar"), ruleFileDelete},
		{"delete; extract", w("rm old.tar; tar -xf new.tar"), ruleFileDelete},
		// A newline is whitespace to the pattern, so the whole string
		// matches as written, as it did before commands were split.
		{"delete, newline, extract", w("rm old.tar\ntar -xf new.tar"), ruleFileDelete},
		{"delete || extract", w("rm old.tar || tar -xf new.tar"), ruleFileDelete},
		{"push then follow a log", w("git push origin main && tail -f build.log"), ruleGit},
		{"file not read back", w("echo -rf /srv/data > /tmp/a; xargs rm < /tmp/b"), ruleFileDelete},
		{"delete then list", w("rm old.tar && ls -la"), ""},
		{"delete then extract, no dash", w("rm old.tar && tar xf new.tar"), ""},
		{"build then test", w("make -j4 && go test ./..."), ""},
		// A pipeline is one command.
		{"list piped to grep", w("ls -f | grep rm"), ruleFileDelete},
		{"piped through cat to xargs", w("echo -rf /srv/data | cat | xargs rm"), ruleFileDelete},
		{"piped through grep to xargs", w("echo -rf /srv/data | grep -e . | xargs rm"), ruleFileDelete},
		{"piped through tee to xargs", w("echo -rf /srv/data | tee /tmp/a | xargs rm"), ruleFileDelete},
		{"piped through cat, 100 words", w(cmd(w("echo", "-rf"), shortWords(100), w("/srv/data", "|", "cat", "|", "xargs", "rm"))), ruleFileDelete},
		{"push flag through cat", w("echo --force | cat | xargs git push origin main"), ruleGit},
		// A file written by one command and named by a later one joins them.
		{"file then xargs <", w("echo -rf /srv/data > /tmp/a; xargs rm < /tmp/a"), ruleFileDelete},
		{"file then xargs -a", w("echo -rf /srv/data > /tmp/a && xargs -a /tmp/a rm"), ruleFileDelete},
		{"file, newline, xargs <", w("echo -rf /srv/data > /tmp/a\nxargs rm < /tmp/a"), ruleFileDelete},
		{"file then xargs <, 100 words", w(cmd(w("echo", "-rf"), shortWords(100), w("/srv/data", ">", "/tmp/a;", "xargs", "rm", "<", "/tmp/a"))), ruleFileDelete},
		{"appended file then cat", w("echo -rf /srv/data >> /tmp/a; cat /tmp/a | xargs rm"), ruleFileDelete},
		{"tee file then xargs <", w("echo -rf /srv/data | tee /tmp/a; xargs rm < /tmp/a"), ruleFileDelete},
		{"push flag through a file", w("echo --force > /tmp/f; xargs git push origin main < /tmp/f"), ruleGit},
		{"push flag through a file, attached", w("echo --force >/tmp/f; xargs git push origin main </tmp/f"), ruleGit},
		{"push --force", w("git push origin main --force"), ruleGit},
		{"push --force first", w("git push --force origin main"), ruleGit},
		{"push -f after words", w(cmd(w("git", "push", "origin"), shortWords(200), w("-f"))), ruleGit},
		{"push --force in a later command", w("git fetch && git push --force origin main"), ruleGit},
		// Controls: the same commands with the flag on the command.
		{"delete with flag then extract", w(cmd(w("rm", "-rf"), pathOperands(70), w("&&", "tar", "-xf", "new.tar"))), ruleFileDelete},
		{"short delete with flag", w("rm -rf old && tar -xf new.tar"), ruleFileDelete},
		{"extract then delete with flag", w("tar -xf new.tar && rm -rf old"), ruleFileDelete},
		{"quoted && stays one command", w(`rm 'x && y' -rf /srv/data`), ruleFileDelete},
		{"no flag anywhere", w(cmd(w("rm", "2>&1"), objFiles(62), w("/srv/data"))), ""},
		{"echo without the pipe", w(cmd(w("echo", "-rf"), shortWords(60), w("/srv/data", "rm"))), ruleFileDelete},
	}
	for _, mode := range []string{config.ActionWarn, config.ActionBlock} {
		pc := defaultConfigWithIncomplete(t, mode)
		for _, tt := range tests {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				v := pc.CheckToolCall("bash", tt.args)
				switch tt.rule {
				case "":
					if v.Matched {
						t.Fatalf("unexpected verdict %s %v", v.Action, v.Rules)
					}
					return
				case incompletePairCheckRule:
					if !slices.Equal(v.Rules, []string{incompletePairCheckRule}) || v.Action != mode || len(v.IncompleteRules) == 0 {
						t.Fatalf("verdict %q %v %v, want only %s with action %s", v.Action, v.Rules, v.IncompleteRules, incompletePairCheckRule, mode)
					}
					return
				}
				if !v.Matched || !slices.Contains(v.Rules, tt.rule) {
					t.Fatalf("verdict %v %q %v, want %q", v.Matched, v.Action, v.Rules, tt.rule)
				}
				if slices.Contains(v.Rules, incompletePairCheckRule) {
					t.Fatalf("rules %v report an incomplete check", v.Rules)
				}
			})
		}
	}
}

func TestCommandSegments(t *testing.T) {
	tests := []struct {
		in   []string
		want []string
	}{
		{w("rm a && tar -xf b"), w("rm a ", " tar -xf b")},
		{w("a; b\nc || d | e |& f"), w("a", " b", "c ", " d | e |& f")},
		{w(`rm 'a && b' "c; d" e`), w(`rm 'a && b' "c; d" e`)},
		{w("ls -la"), w("ls -la")},
		{w("a && && b"), w("a ", " b")},
		{w("ls | grep x"), w("ls | grep x")},
		{w("echo x | cat | xargs rm"), w("echo x | cat | xargs rm")},
		{w("echo x > /tmp/a; xargs rm < /tmp/a"), w("echo x > /tmp/a ;  xargs rm < /tmp/a")},
		{w("echo x >/tmp/a && xargs -a /tmp/a rm"), w("echo x >/tmp/a  ;  xargs -a /tmp/a rm")},
		{w("echo x 2>>'/tmp/a'; ls; rm --from=/tmp/a"), w("echo x 2>>'/tmp/a' ;  rm --from=/tmp/a", " ls")},
		{w("echo x 2>> /tmp/a; ls; rm --from=/tmp/a"), w("echo x 2>> /tmp/a ;  rm --from=/tmp/a", " ls")},
		{w("echo x | tee -a /tmp/a; sh /tmp/a"), w("echo x | tee -a /tmp/a ;  sh /tmp/a")},
		{w("echo x > /tmp/a; xargs rm < /tmp/b"), w("echo x > /tmp/a", " xargs rm < /tmp/b")},
		{w("rm 'open"), nil},
		{w("rm $(x) && y"), nil},
		{w("rm `x` && y"), nil},
		{w(`rm a\;b && y`), nil},
		{w("rm {a,b} && y"), nil},
		{w("rm a", "&& y"), nil},
		{nil, nil},
	}
	for _, tt := range tests {
		if got := commandSegments(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("commandSegments(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCleanCommandTokens(t *testing.T) {
	tests := []struct {
		in      []string
		blank   bool
		want    []string
		changed bool
	}{
		{w("rm", "2>&1", "-rf", ">out", ">>log", "<in", "&>/dev/null", ">|f", "2>", "x"), false, w("rm", "-rf", "x"), true},
		{w("rm", "'a;b'", "c|d", "e&f"), true, w("rm", "'a_b'", "c_d", "e_f"), true},
		{w("rm", "'a;b'"), false, w("rm", "'a;b'"), false},
		{w("rm", "-rf", "a=>b", "-->"), true, w("rm", "-rf", "a=>b", "-->"), false},
	}
	for _, tt := range tests {
		got, changed := cleanCommandTokens(tt.in, tt.blank)
		if !slices.Equal(got, tt.want) || changed != tt.changed {
			t.Errorf("cleanCommandTokens(%q, %v) = %q %v, want %q %v", tt.in, tt.blank, got, changed, tt.want, tt.changed)
		}
	}
}
