// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// numbered returns n tokens prefix0, prefix1, ... each followed by suffix.
func numbered(prefix, suffix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = prefix + strconv.Itoa(i) + suffix
	}
	return out
}

// builtInPattern returns the compiled argument pattern of a built-in rule.
func builtInPattern(t *testing.T, name string) *regexp.Regexp {
	t.Helper()
	for _, r := range DefaultToolPolicyRules() {
		if r.Name == name {
			return regexp.MustCompile(r.ArgPattern)
		}
	}
	t.Fatalf("no built-in rule %q", name)
	return nil
}

func TestLiteralIn(t *testing.T) {
	lits, ok := pairLiterals(builtInPattern(t, ruleFileDelete))
	if !ok || len(lits) != 1 || lits[0].text != foldString("rm") || !lits[0].wordStart || !lits[0].wordEnd {
		t.Fatalf("Destructive File Delete literals = %+v %v, want rm at word edges", lits, ok)
	}
	tests := []struct {
		tok        string
		has, exact bool
	}{
		{"rm", true, true},
		{"RM", true, true},
		{"/bin/rm", true, true},
		{"./rm", true, true},
		{"x-rm", true, false},
		{"rm.sh", true, false},
		{"farm0", false, false},
		{"rm0", false, false},
		{"format_1.go", false, false},
		{"src/platform/x.go", false, false},
		{"terms", false, false},
		{"confirm", false, false},
		{"ls", false, false},
	}
	for _, tt := range tests {
		has, exact := literalIn(tt.tok, lits)
		if has != tt.has || exact != tt.exact {
			t.Errorf("literalIn(%q) = %v %v, want %v %v", tt.tok, has, exact, tt.has, tt.exact)
		}
	}
	// A literal with no word edge in its pattern is found anywhere.
	plain, ok := pairLiterals(regexp.MustCompile(`(git\s+)?push`))
	if !ok || plain[0].wordStart || plain[0].wordEnd {
		t.Fatalf("push literals = %+v %v, want no word edges", plain, ok)
	}
	if has, _ := literalIn("unpushed", plain); !has {
		t.Fatal("unpushed does not hold push")
	}
}

func TestPairLiteralEdges(t *testing.T) {
	tests := []struct {
		pat              string
		wordStart, wordE bool
	}{
		{`(?i)\brm\s+-r`, true, true},
		{`\brm\b`, true, true},
		{`(?m)^rm$`, true, true},
		{`[ /]rm[ ;]`, true, true},
		{`xrm\s`, false, true},
		{`\brmx?`, true, false},
		{`rm(?:\s+\S+)*?\s+-f`, false, true},
		{`\brm[a-z]?\s`, true, false},
		{`(?i)\bks\b`, false, false}, // k and s also match non-word runes under (?i)
	}
	for _, tt := range tests {
		lits, ok := pairLiterals(regexp.MustCompile(tt.pat))
		if !ok || len(lits) != 1 {
			t.Fatalf("pairLiterals(%q) = %+v %v", tt.pat, lits, ok)
		}
		if lits[0].wordStart != tt.wordStart || lits[0].wordEnd != tt.wordE {
			t.Errorf("pairLiterals(%q) = %+v, want wordStart %v wordEnd %v", tt.pat, lits[0], tt.wordStart, tt.wordE)
		}
	}
	// Each case: the edge is sound, so a token the literal check rejects can
	// never be part of a match.
	for _, tt := range []struct{ pat, a, b string }{
		{`(?i)\bks\b`, "\u212as", "x"},
		{`\brm\s+-r`, "x-rm", "-r"},
	} {
		re := regexp.MustCompile(tt.pat)
		lits, _ := pairLiterals(re)
		has, _ := literalIn(tt.a, lits)
		if re.MatchString(tt.a+" "+tt.b) && !has {
			t.Errorf("%q matches %q but literalIn rejects %q", tt.pat, tt.a+" "+tt.b, tt.a)
		}
	}
}

func TestMatchBoundedPairs_CommandTokenPairsFirst(t *testing.T) {
	pat := builtInPattern(t, ruleFileDelete)
	for _, filler := range [][]string{numbered("farm", "", 100), numbered("x-rm", "", 100), numbered("rm-", ".log", 100)} {
		tokens := slices.Concat(filler, w("-rf", "/srv/data", "rm"))
		matched, checks, complete := matchBoundedPairs(pat, [][]string{tokens})
		if !matched || !complete {
			t.Fatalf("filler %q: matched %v complete %v", filler[0], matched, complete)
		}
		if checks > 2*len(tokens) {
			t.Errorf("filler %q: %d checks before the command word was paired", filler[0], checks)
		}
	}
}

func TestDefaultRules_FillersDoNotHideCommandWord(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"array, farm fillers", slices.Concat(w("rm", "-rf"), numbered("farm", "", 100), w("/srv/data"))},
		{"array, rm fillers", slices.Concat(w("rm", "-rf"), numbered("rm", "", 100), w("/srv/data"))},
		{"array, word-edge fillers", slices.Concat(w("rm", "-rf"), numbered("x-rm", "", 100), w("/srv/data"))},
		{"array, command last", slices.Concat(w("-rf"), numbered("x-rm", "", 3000), w("/srv/data", "/bin/rm"))},
		{"shell, rm fillers to xargs", w(cmd(w("echo", "-rf"), numbered("rm", "", 100), w("/srv/data", "|", "xargs", "rm")))},
		{"shell, farm fillers to xargs", w(cmd(w("echo", "-rf"), numbered("farm", "", 100), w("/srv/data", "|", "xargs", "rm")))},
	}
	for _, mode := range []string{config.ActionWarn, config.ActionBlock} {
		pc := defaultConfigWithIncomplete(t, mode)
		for _, tt := range tests {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				v := pc.CheckToolCall("bash", tt.args)
				if !slices.Contains(v.Rules, ruleFileDelete) || slices.Contains(v.Rules, incompletePairCheckRule) || v.Action != config.ActionBlock {
					t.Fatalf("verdict %q %v, want %q blocked", v.Action, v.Rules, ruleFileDelete)
				}
			})
		}
	}
}

func TestDefaultRules_LongEverydayCommandsInBlockMode(t *testing.T) {
	gitPaths := slices.Concat(numbered("src/app/file_", ".go", 290), numbered("src/platform/format_", ".go", 10))
	docs := slices.Concat(numbered("docs/page_", ".md", 120),
		numbered("docs/terms_", ".md", 3), numbered("docs/firmware_", ".md", 3), numbered("docs/confirm_", ".md", 3),
		numbered("docs/format_", ".md", 3), numbered("docs/platform_", ".md", 3), numbered("docs/alarm_", ".md", 3))
	tests := []struct {
		name string
		args []string
		rule string
	}{
		{"git add 300 paths", w(cmd(w("git", "add"), gitPaths)), ""},
		{"git add 300 paths as array", slices.Concat(w("git", "add", "--"), gitPaths), ""},
		{"prettier over 138 docs", w(cmd(w("npx", "prettier", "--write"), docs)), ""},
		{"prettier then git add", w(cmd(w("npx", "prettier", "--write"), docs, w("&&", "git", "add"), gitPaths)), ""},
		// Controls: the same lists with a real delete or force push.
		{"prettier then delete", w(cmd(w("npx", "prettier", "--write"), docs, w("&&", "rm", "-rf", "docs/old"))), ruleFileDelete},
		{"git add then force push", w(cmd(w("git", "add"), gitPaths, w("&&", "git", "push", "--force"))), ruleGit},
		{"delete over the same list", w(cmd(w("rm", "-rf"), gitPaths)), ruleFileDelete},
	}
	pc := defaultConfigWithIncomplete(t, config.ActionBlock)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := pc.CheckToolCall("bash", tt.args)
			if tt.rule == "" {
				if v.Matched {
					t.Fatalf("unexpected verdict %q %v %v", v.Action, v.Rules, v.IncompleteRules)
				}
				return
			}
			if !slices.Contains(v.Rules, tt.rule) || slices.Contains(v.Rules, incompletePairCheckRule) {
				t.Fatalf("verdict %q %v, want %q", v.Action, v.Rules, tt.rule)
			}
		})
	}
}

func TestMatchPatternParity(t *testing.T) {
	patterns := []string{``, `a*b?`, `^alpha beta$`, `(?i)k.*s`, `(?:alpha|beta)+`, `a{0,3}`, `(?:alpha)?beta`, `[^a]+`, `(?s).*`, `(?i)\bks\b`}
	for _, rule := range DefaultToolPolicyRules() {
		patterns = append(patterns, rule.ArgPattern)
	}
	texts := []string{"", "alpha beta", "beta alpha", "ALPHA", "Kſ", "ks", "a\nb", "\xff", "echo hello", "git status", "find . -print0 | xargs -0 chmod 644"}
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		for _, text := range texts {
			for _, input := range []string{text, strings.Repeat("a", 4096) + text, text + strings.Repeat("z", 4096)} {
				if got, want := matchPatternWithFold(re, input, nil), re.MatchString(input); got != want {
					t.Fatalf("pattern %q text %q: got %v want %v", pattern, text, got, want)
				}
			}
		}
	}
}

func TestSameArgViewProvenance(t *testing.T) {
	base := argView{tokens: []string{"echo", "hello"}, joined: "echo hello", segments: [][]string{{"echo", "hello"}}}
	if !sameArgView(base, base) {
		t.Fatal("identical view differs")
	}
	changes := []func(*argView){
		func(v *argView) { v.unsplit = true },
		func(v *argView) { v.plain = true },
		func(v *argView) { v.checkXargs = true },
		func(v *argView) { v.inputKnown = "echo" },
		func(v *argView) { v.joined = "different" },
		func(v *argView) { v.tokens = []string{"different"} },
		func(v *argView) { v.segments = nil },
		func(v *argView) { v.segments = [][]string{{"echo"}, {"hello"}} },
	}
	for i, change := range changes {
		other := base
		change(&other)
		if sameArgView(base, other) {
			t.Errorf("difference %d was ignored", i)
		}
	}
	if sameArgView(argView{}, argView{segments: [][]string{}}) {
		t.Fatal("nil segments differ from empty segments")
	}
}

func BenchmarkPolicyArgumentMatching(b *testing.B) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, OnIncompleteCheck: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, tc := range []struct{ name, text string }{
		{"large_word", "echo " + strings.Repeat("a", 1<<20)},
		{"script", strings.Repeat("echo hello world; ls -la /tmp | head -3\n", 50)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			args := []string{tc.text}
			if verdict := pc.CheckToolCall("bash", args); verdict.Matched {
				b.Fatalf("benchmark control matched: %+v", verdict)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(tc.text)))
			for b.Loop() {
				_ = pc.CheckToolCall("bash", args)
			}
		})
	}
}

func TestCommandWordFoldParity(t *testing.T) {
	words := []string{foldString("alpha"), foldString("ks"), foldString("Σ")}
	for _, text := range []string{"alpha", "/bin/ALPHA", "Kſ", "Σ", "ς", "σ", "", strings.Repeat("a", 4096)} {
		want := slices.Contains(words, foldString(text))
		if strings.HasPrefix(text, "/bin/") {
			want = slices.Contains(words, foldString(strings.TrimPrefix(text, "/bin/")))
		}
		if got := isCommandWord(text, words); got != want {
			t.Errorf("%q: got %v want %v", text, got, want)
		}
	}
	for r := rune(0); r <= unicode.MaxASCII; r++ {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < least {
				least = f
			}
		}
		if got := foldString(string(r)); got != string(least) {
			t.Fatalf("fold %U: %q", r, got)
		}
	}
}
