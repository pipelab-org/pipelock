// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// shortWords returns n distinct short tokens (w0, w1, ...). Each one is a
// pairing anchor for a pattern without required literal text.
func shortWords(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "w" + strconv.Itoa(i)
	}
	return out
}

// pathOperands returns n distinct path tokens. Paths never anchor pairs.
func pathOperands(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "./build/cache/obj_" + strconv.Itoa(i) + ".o"
	}
	return out
}

// longFlags returns n distinct long options (--opt-0, --opt-1, ...).
func longFlags(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "--opt-" + strconv.Itoa(i)
	}
	return out
}

// buildTokens surrounds padding with prefix and suffix so the result has
// exactly total tokens.
func buildTokens(t *testing.T, total int, prefix, suffix []string, pad func(int) []string) []string {
	t.Helper()
	n := total - len(prefix) - len(suffix)
	if n < 0 {
		t.Fatalf("total %d too small for prefix %v and suffix %v", total, prefix, suffix)
	}
	out := append(append(slices.Clone(prefix), pad(n)...), suffix...)
	if len(out) != total {
		t.Fatalf("built %d tokens, want %d", len(out), total)
	}
	return out
}

func TestCheckToolCall_PairwiseOnlyPatternAtTokenCounts(t *testing.T) {
	rule := &CompiledRule{
		Name:        "pairwise-only",
		ToolPattern: regexp.MustCompile(`^bash$`),
		ArgPattern:  regexp.MustCompile(`^rm -rf$`),
		Action:      config.ActionBlock,
	}
	pc := &Config{Action: config.ActionWarn, Rules: []*CompiledRule{rule}}
	repeated := func(n int) []string { return slices.Repeat([]string{"x"}, n) }

	for _, total := range []int{63, 64, 65, 200} {
		for _, pad := range []struct {
			name string
			fn   func(int) []string
		}{
			{"repeated operand", repeated},
			{"path operands", pathOperands},
		} {
			t.Run(strconv.Itoa(total)+" "+pad.name, func(t *testing.T) {
				args := buildTokens(t, total, []string{"rm"}, []string{"-rf"}, pad.fn)
				if v := pc.CheckToolCall("bash", args); !v.Matched {
					t.Fatalf("separate rm and -rf not paired at %d tokens", total)
				}
				control := buildTokens(t, total, []string{"rm"}, []string{"-v"}, pad.fn)
				if v := pc.CheckToolCall("bash", control); v.Matched {
					t.Fatalf("control without -rf matched at %d tokens: %v", total, v.Rules)
				}
			})
		}
	}
}

func TestDefaultRules_LongCommandsAtTokenCounts(t *testing.T) {
	pc := defaultConfig(t)
	tests := []struct {
		name           string
		prefix, suffix []string
		pad            func(int) []string
		rule           string
	}{
		{"rm path operands", []string{"rm"}, []string{"-rf"}, pathOperands, ruleFileDelete},
		{"rm word operands", []string{"rm"}, []string{"-rf", "/srv"}, shortWords, ruleFileDelete},
		{"git push force", []string{"git", "push", "origin"}, []string{"--force"}, shortWords, ruleGit},
		{"git push short force", []string{"git", "push"}, []string{"-f"}, shortWords, ruleGit},
		{"git reset hard", []string{"git", "reset"}, []string{"--hard"}, shortWords, ruleGit},
		{"git clean", []string{"git", "clean"}, []string{"-fdx"}, shortWords, ruleGit},
		{"chmod verbose recursive", []string{"chmod", "-v"}, []string{"-R", "777", "/srv"}, shortWords, rulePermissions},
		{"pip flags before install", []string{"pip"}, []string{"install", "requests"}, longFlags, rulePkgInstall},
		{"dd operands before target", []string{"dd", "status=none"}, []string{"if=/dev/zero", "of=/dev/sda"}, shortWords, ruleDiskWipe},
	}
	for _, total := range []int{64, 65, 200} {
		for _, tt := range tests {
			t.Run(strconv.Itoa(total)+" "+tt.name, func(t *testing.T) {
				tokens := buildTokens(t, total, tt.prefix, tt.suffix, tt.pad)
				cmd := strings.Join(tokens, " ")
				v := pc.CheckToolCall("bash", []string{cmd})
				if !v.Matched || !slices.Contains(v.Rules, tt.rule) {
					t.Fatalf("%d-token command not matched by %q: %+v", total, tt.rule, v.Rules)
				}
			})
		}
	}
}

func TestDefaultRules_LongCommandsStayAllowed(t *testing.T) {
	pc := defaultConfigWithIncomplete(t, config.ActionBlock)
	dotted := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "file_" + strconv.Itoa(i) + ".txt"
		}
		return out
	}
	tests := []struct {
		name           string
		prefix, suffix []string
		pad            func(int) []string
	}{
		{"ls dotted names", []string{"ls", "-la"}, nil, dotted},
		{"ls short names", []string{"ls"}, nil, shortWords},
		{"ls paths", []string{"ls"}, nil, pathOperands},
		{"rm without flags", []string{"rm"}, nil, pathOperands},
		{"long commit message", []string{"git", "commit", "-m"}, nil, shortWords},
		{"push with lease", []string{"git", "push", "--force-with-lease", "origin"}, nil, shortWords},
		{"chmod non-world mode", []string{"chmod", "-R", "755"}, nil, pathOperands},
		{"pip list", []string{"pip", "list"}, nil, longFlags},
	}
	for _, total := range []int{200} {
		for _, tt := range tests {
			t.Run(strconv.Itoa(total)+" "+tt.name, func(t *testing.T) {
				// Checked in full, so nothing is raised even when an
				// incomplete check would block.
				tokens := buildTokens(t, total, tt.prefix, tt.suffix, tt.pad)
				if v := pc.CheckToolCall("bash", []string{strings.Join(tokens, " ")}); v.Matched {
					t.Fatalf("command string matched: %s %v", v.Action, v.Rules)
				}
				if v := pc.CheckToolCall("bash", tokens); v.Matched {
					t.Fatalf("argument array matched: %s %v", v.Action, v.Rules)
				}
			})
		}
	}
}

func TestMatchBoundedPairs_StaysWithinCheckLimit(t *testing.T) {
	never := regexp.MustCompile(`^never-matches$`)
	noLiteral := regexp.MustCompile(`^[a-z]{2} [+][rf]+$`)
	tests := []struct {
		name     string
		pat      *regexp.Regexp
		tokens   []string
		complete bool
	}{
		{"literal pattern, short tokens", never, shortWords(10000), true},
		{"literal pattern, paths", never, pathOperands(10000), true},
		{"no literal, short tokens", noLiteral, shortWords(10000), false},
		{"no literal, paths", noLiteral, pathOperands(10000), false},
		{"no literal, mixed", noLiteral, append(shortWords(5000), pathOperands(5000)...), false},
		{"no literal, one anchor many paths", noLiteral, append([]string{"rm"}, pathOperands(2016)...), true},
		{"no literal, repeated tokens", noLiteral, append([]string{"rm"}, slices.Repeat([]string{"x"}, 200)...), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, checks, complete := matchBoundedPairs(tt.pat, [][]string{tt.tokens})
			if matched {
				t.Fatal("unexpected match")
			}
			if checks > maxPairChecks {
				t.Fatalf("ran %d pair checks, limit %d", checks, maxPairChecks)
			}
			if complete != tt.complete {
				t.Fatalf("complete = %v, want %v (%d checks)", complete, tt.complete, checks)
			}
		})
	}

	// Positive controls: a pair present among the checked tokens is found
	// well inside the limit, with and without required literal text.
	for _, pat := range []*regexp.Regexp{regexp.MustCompile(`^rm\s-rf$`), regexp.MustCompile(`^[a-z]{2} -[rf]+$`)} {
		tokens := append(append([]string{"rm"}, pathOperands(10000)...), "-rf")
		matched, checks, _ := matchBoundedPairs(pat, [][]string{tokens})
		if !matched {
			t.Fatalf("%s: pair of short tokens not found among path operands", pat)
		}
		if checks > maxPairChecks {
			t.Fatalf("%s: ran %d pair checks, limit %d", pat, checks, maxPairChecks)
		}
	}
}

func TestSplitPairTokens(t *testing.T) {
	anchors, others, dropped := splitPairTokens([]string{"rm", "-rf", "rm", "./a/b", `C:\x`, strings.Repeat("y", maxPairAnchorLen+1), "-rf", "./a/b"})
	if want := []string{"-rf", "rm"}; !slices.Equal(anchors, want) {
		t.Fatalf("anchors = %q, want %q", anchors, want)
	}
	if want := []string{"./a/b", `C:\x`, strings.Repeat("y", maxPairAnchorLen+1)}; !slices.Equal(others, want) {
		t.Fatalf("others = %q, want %q", others, want)
	}
	if dropped {
		t.Fatal("short list reported dropped tokens")
	}

	// Options anchor whatever their length.
	long := "-" + strings.Repeat("r", 2*maxPairAnchorLen)
	if anchors, _, _ := splitPairTokens(append(pathOperands(3000), long)); !slices.Contains(anchors, long) {
		t.Fatalf("long option %q not kept as an anchor: %q", long, anchors)
	}

	// Anchors past their limit move to the rest while there is room.
	anchors, others, dropped = splitPairTokens(shortWords(maxPairwiseTokens + 1))
	if len(anchors) != maxPairwiseTokens || !slices.Equal(others, []string{"w64"}) || dropped {
		t.Fatalf("kept %d anchors, others %q, dropped %v", len(anchors), others, dropped)
	}

	anchors, others, dropped = splitPairTokens(append(shortWords(100000), pathOperands(100000)...))
	if len(anchors) > maxPairwiseTokens || len(others) > maxPairChecks/2 {
		t.Fatalf("kept %d anchors and %d others, want at most %d and %d", len(anchors), len(others), maxPairwiseTokens, maxPairChecks/2)
	}
	if !dropped {
		t.Fatal("tokens past both limits not reported as dropped")
	}
}

func TestPairLiterals(t *testing.T) {
	tests := []struct {
		pat  string
		lits []string
		ok   bool
	}{
		{`^rm -rf$`, []string{"rm -rf"}, false}, // spans the pair space
		{`(?i)\brm\s+-r`, []string{foldString("rm")}, true},
		{`(?i)(curl|wget)\b.*-d`, []string{foldString("curl"), foldString("wget")}, true},
		{`(git\s+)?push`, []string{foldString("push")}, true},
		{`a*b?`, nil, false},
		{`[a-z]{2} -x|y+`, []string{" -x", "y"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.pat, func(t *testing.T) {
			lits, ok := pairLiterals(regexp.MustCompile(tt.pat))
			var texts []string
			for _, l := range lits {
				texts = append(texts, l.text)
			}
			if ok != tt.ok || (ok && !slices.Equal(texts, tt.lits)) {
				t.Fatalf("pairLiterals = %q %v, want %q %v", texts, ok, tt.lits, tt.ok)
			}
		})
	}
	// Every built-in command rule narrows its pairs by literal text, so long
	// commands are checked in full.
	for _, rule := range DefaultToolPolicyRules() {
		if rule.ArgPattern == "" {
			continue
		}
		if _, ok := pairLiterals(regexp.MustCompile(rule.ArgPattern)); !ok {
			t.Errorf("built-in rule %q has no required literal text", rule.Name)
		}
	}
}

func TestFoldString(t *testing.T) {
	for _, s := range []string{"RM", "rm", "Rm", "rM"} {
		if foldString(s) != foldString("rm") {
			t.Fatalf("foldString(%q) = %q", s, foldString(s))
		}
	}
	// U+212A KELVIN SIGN matches k under (?i).
	if !regexp.MustCompile(`(?i)k`).MatchString("\u212a") || foldString("\u212a") != foldString("k") {
		t.Fatal("Kelvin sign does not fold with k")
	}
}
