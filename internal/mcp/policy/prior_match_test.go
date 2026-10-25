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
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// priorRuleTests are single command strings that the argument check matched
// before commands in one string were told apart. Splitting them, or a revised
// pattern, must not turn them into an incomplete check or a clean call.
var priorRuleTests = []struct {
	name    string
	command string
	rule    string // "" means no verdict
}{
	{"copied file to xargs <", "echo -rf /srv/data > /tmp/a; cp /tmp/a /tmp/b; xargs rm < /tmp/b", ruleFileDelete},
	{"copied file to xargs -a", "echo -rf /srv/data > /tmp/a; cp /tmp/a /tmp/b; xargs -a /tmp/b rm", ruleFileDelete},
	{"moved file to xargs <", "echo -rf /srv/data > /tmp/a; mv /tmp/a /tmp/b; xargs rm < /tmp/b", ruleFileDelete},
	{"moved file to xargs -a", "echo -rf /srv/data > /tmp/a; mv /tmp/a /tmp/b; xargs -a /tmp/b rm", ruleFileDelete},
	{"./a then a", "echo -rf /srv/data > ./a; xargs rm < a", ruleFileDelete},
	{"double slash", "echo -rf /srv/data > /tmp/a; xargs rm < /tmp//a", ruleFileDelete},
	{"dot dot", "echo -rf /srv/data > /tmp/a; xargs rm < /tmp/../tmp/a", ruleFileDelete},
	{"two files", "echo -rf > /tmp/a; echo /srv/data > /tmp/b; cat /tmp/a /tmp/b | xargs rm", ruleFileDelete},
	{"push flag through a copy", "echo --force > /tmp/f; cp /tmp/f /tmp/g; xargs git push origin main < /tmp/g", ruleGit},
	{"push -f through a copy", "echo -f > /tmp/f; cp /tmp/f /tmp/g; xargs git push origin main < /tmp/g", ruleGit},
	{"reset flag through a copy", "echo --hard > /tmp/a; cp /tmp/a /tmp/b; xargs git reset < /tmp/b", ruleGit},
	{"reset flag through a move", "echo --hard > /tmp/a; mv /tmp/a /tmp/b && xargs -a /tmp/b git reset", ruleGit},
	{"delete then extract", "rm old.tar && tar -xf new.tar", ruleFileDelete},
	{"push then follow a log", "git push origin main && tail -f build.log", ruleGit},
	// Zero-width spaces in place of spaces: only the view that turns them
	// into spaces splits these into tokens.
	{"zero-width, copied file to xargs <", zeroWidth("echo -rf /srv/data > /tmp/a; cp /tmp/a /tmp/b; xargs rm < /tmp/b"), ruleFileDelete},
	{"zero-width, reset flag through a copy", zeroWidth("echo --hard > /tmp/a; cp /tmp/a /tmp/b; xargs git reset < /tmp/b"), ruleGit},
	{"zero-width, decode written then piped to sh", zeroWidth("echo base64 -d x.b64 > /tmp/a; cat /tmp/a | sh"), ruleEncoded},
	// Controls: the same shapes with nothing the rules name.
	{"copied file, no flag", "echo old > /tmp/a; cp /tmp/a /tmp/b; xargs rm < /tmp/b", ""},
	{"copied file to ls", "echo -rf /srv/data > /tmp/a; cp /tmp/a /tmp/b; xargs ls < /tmp/b", ""},
	{"moved file, no flag", "echo main > /tmp/a; mv /tmp/a /tmp/b; xargs git push origin < /tmp/b", ""},
	{"reset without the flag", "echo HEAD > /tmp/a; cp /tmp/a /tmp/b; xargs git reset < /tmp/b", ""},
	{"delete then list", "rm old.tar && ls -la", ""},
	{"zero-width, copied file, no flag", zeroWidth("echo old > /tmp/a; cp /tmp/a /tmp/b; xargs rm < /tmp/b"), ""},
}

// zeroWidth puts U+200B in place of every space.
func zeroWidth(s string) string { return strings.ReplaceAll(s, " ", "\u200b") }

func TestDefaultRules_PriorMatchesStillMatch(t *testing.T) {
	for _, mode := range []string{config.ActionWarn, config.ActionBlock} {
		pc := defaultConfigWithIncomplete(t, mode)
		for _, tt := range priorRuleTests {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				checkPriorVerdict(t, pc.CheckToolCall("bash", []string{tt.command}), tt.rule)
				line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_command","arguments":{"command":` +
					strconv.Quote(tt.command) + `}}}`
				checkPriorVerdict(t, pc.CheckRequest([]byte(line)), tt.rule)
			})
		}
	}
}

func checkPriorVerdict(t *testing.T, v Verdict, rule string) {
	t.Helper()
	if rule == "" {
		if v.Matched {
			t.Fatalf("unexpected verdict %s %v", v.Action, v.Rules)
		}
		return
	}
	if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, rule) ||
		slices.Contains(v.Rules, incompletePairCheckRule) {
		t.Fatalf("verdict %v %q %v %v, want block by %q", v.Matched, v.Action, v.Rules, v.IncompleteRules, rule)
	}
}

// A configured rule keeps matching a pair across commands as before.
func TestConfiguredRule_PriorMatchesStillMatch(t *testing.T) {
	pc := &Config{
		Action:           config.ActionWarn,
		IncompleteAction: config.ActionWarn,
		Rules: []*CompiledRule{{
			Name:        "named pair",
			ToolPattern: regexp.MustCompile(`^bash$`),
			ArgPattern:  regexp.MustCompile(`\bfoo\s+--bar\b`),
			Action:      config.ActionBlock,
		}},
	}
	tests := []struct {
		command string
		match   bool
	}{
		{"foo x && echo --bar", true},
		{"echo --bar > /tmp/a; cp /tmp/a /tmp/b; xargs foo < /tmp/b", true},
		{"foo x && echo bar", false},
	}
	for _, tt := range tests {
		v := pc.CheckToolCall("bash", []string{tt.command})
		if tt.match {
			checkPriorVerdict(t, v, "named pair")
		} else if v.Matched {
			t.Fatalf("%q: unexpected verdict %s %v", tt.command, v.Action, v.Rules)
		}
	}
}

func TestPriorArgPatterns_AreShipped(t *testing.T) {
	shipped := map[string]bool{}
	for _, r := range DefaultToolPolicyRules() {
		shipped[r.ArgPattern] = true
	}
	if len(priorArgPatterns) == 0 {
		t.Fatal("no prior patterns")
	}
	for p, prev := range priorArgPatterns {
		if !shipped[p] {
			t.Errorf("pattern %q is not a built-in pattern", p)
		}
		if len(prev) == 0 || slices.Contains(prev, p) {
			t.Errorf("pattern %q: prior %q", p, prev)
		}
		if got := priorPatterns(regexp.MustCompile(p)); len(got) != len(prev) {
			t.Errorf("pattern %q: %d compiled, want %d", p, len(got), len(prev))
		}
	}
	if got := priorPatterns(regexp.MustCompile(`unrelated`)); got != nil {
		t.Errorf("unrelated pattern has priors %v", got)
	}
}

// earlierBuiltinPatterns are the built-in patterns before they were revised,
// as written then, independent of priorArgPatterns.
var earlierBuiltinPatterns = map[string]string{
	"Destructive File Delete":     `(?i)\brm\s+(--\s+)?(-[a-z]*[rf]\b|--(?:recursive|force)\b)`,
	"Recursive Permission Change": `(?i)\b(chmod\s+(-R|--recursive)\s+(777|666)|chmod\s+(777|666)\s+(-R|--recursive)|chown\s+(-R|--recursive))\b`,
	"Reverse Shell":               `(?i)(bash\s+-i\s+>&|/dev/tcp/|mkfifo\s+|nc\s+-e|ncat\s+-e)`,
	"Disk Wipe Command":           `(?i)\b(dd\s+if=.*of=/dev/|mkfs\.|fdisk)\b`,
	"Package Install":             `(?i)\b(pip|npm|gem|cargo|go)\s+install\b`,
	"Destructive Git Operation":   `(?i)(\bgit\s+)?(push\s+(--force(\s|$)|-f\b)|reset\s+--hard\b|clean\s+-fd\b)`,
	"Encoded Command Execution":   `(?i)(\beval\b.*\bbase64\b|\bbase64\s+(-d|--decode)\b.*\|\s*(ba)?sh\b)`,
	"Detached Process Spawning":   `(?i)(\bnohup\s+|\bdisown\b|\bsetsid\s+|\bscreen\s+(-\S+\s+)*-[dDm]|\btmux\s+(new-session|new)\s+-d)`,
}

// earlierCheck is the argument check as it read a call before commands were
// told apart: the joined list, each token, and up to 64 tokens every ordered
// pair, in each normalization view.
func earlierCheck(pat *regexp.Regexp, args []string) bool {
	type view struct {
		tokens []string
		joined string
	}
	var views []view
	for _, n := range []struct {
		fn  func(string) string
		pre *strings.Replacer
	}{{normalize.ForMatching, policyPreNormalize}, {normalize.ForPolicy, policyPreNormalize}, {normalize.ForMatching, nil}} {
		tokens, joined := normalizeArgTokens(args, n.fn, n.pre)
		views = append(views, view{tokens, joined})
	}
	tokens, joined := literalArgTokens(args)
	views = append(views, view{tokens, joined})
	for _, v := range views {
		if pat.MatchString(v.joined) {
			return true
		}
		for _, tok := range v.tokens {
			if pat.MatchString(tok) {
				return true
			}
		}
		if len(v.tokens) > 64 {
			continue
		}
		for i := range v.tokens {
			for j := range v.tokens {
				if i != j && pat.MatchString(v.tokens[i]+" "+v.tokens[j]) {
					return true
				}
			}
		}
	}
	return false
}

// priorCorpus builds command strings that join commands every way the
// matcher tells them apart, with and without the words the rules name.
func priorCorpus() []string {
	var out []string
	for _, tt := range priorRuleTests {
		out = append(out, tt.command)
	}
	writers := []string{"echo -rf /srv/data", "echo --force", "echo -f", "echo --hard", "echo -fd", "echo old", "echo -e /bin/sh"}
	readers := []string{"xargs rm", "xargs git push origin main", "xargs git reset", "xargs git clean", "rm old", "git push origin", "tar -xf new.tar", "ls -la", "nc host 9"}
	joins := []string{" > /tmp/a; %s < /tmp/a", " > /tmp/a; cp /tmp/a /tmp/b; %s < /tmp/b", " > /tmp/a && mv /tmp/a /tmp/b && xargs -a /tmp/b %s", " | %s", " && %s", "; %s", "\n%s", " > ./a; %s < a"}
	for _, w := range writers {
		for _, r := range readers {
			for _, j := range joins {
				out = append(out, w+strings.Replace(j, "%s", r, 1))
			}
		}
	}
	return out
}

// TestDefaultRules_NeverWeakerThanEarlierCheck checks that every built-in
// rule matched by the earlier check, with the earlier pattern or the current
// one, still matches in full, whatever on_incomplete_check is.
func TestDefaultRules_NeverWeakerThanEarlierCheck(t *testing.T) {
	corpus := priorCorpus()
	rules := defaultConfig(t).Rules
	want := make([][]string, len(corpus))
	checked := 0
	for i, cmd := range corpus {
		for _, rule := range rules {
			if rule.ArgPattern == nil || rule.ToolPattern == nil || !rule.ToolPattern.MatchString("bash") ||
				shippedCredentialToolPatterns[rule.ToolPattern.String()] {
				continue
			}
			pats := []*regexp.Regexp{rule.ArgPattern}
			if prev, ok := earlierBuiltinPatterns[rule.Name]; ok {
				pats = append(pats, regexp.MustCompile(prev))
			}
			for _, p := range pats {
				if earlierCheck(p, []string{cmd}) {
					want[i] = append(want[i], rule.Name)
					checked++
					break
				}
			}
		}
	}
	// Positive control: the corpus exercises the earlier check.
	if checked < 100 {
		t.Fatalf("earlier check matched %d times, want at least 100", checked)
	}
	for _, mode := range []string{config.ActionWarn, config.ActionBlock} {
		pc := defaultConfigWithIncomplete(t, mode)
		for i, cmd := range corpus {
			v := pc.CheckToolCall("bash", []string{cmd})
			for _, name := range want[i] {
				if !slices.Contains(v.Rules, name) {
					t.Errorf("%s: %q: earlier check matched %q, verdict %q %v", mode, cmd, name, v.Action, v.Rules)
				}
			}
		}
	}
}
