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

// pastAnchorKeep puts the flag first and the command word after 63 distinct
// short words, so the command word is the 65th distinct short token.
func pastAnchorKeep() []string {
	return append(append([]string{"-rf"}, shortWords(maxPairwiseTokens-1)...), "rm")
}

// literalCrowd returns n distinct tokens that each hold the command word rm
// at a word edge without forming a command, so every pair among them needs a
// check.
func literalCrowd(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "rm-" + strconv.Itoa(i)
	}
	return out
}

func defaultConfigWithIncomplete(t *testing.T, action string) *Config {
	t.Helper()
	pc := defaultConfig(t)
	pc.IncompleteAction = action
	return pc
}

// noLiteralConfig has one rule whose pattern has no required literal text,
// so long lists fall back to anchored pairs.
func noLiteralConfig(action string) *Config {
	return &Config{
		Action:           config.ActionWarn,
		IncompleteAction: action,
		Rules: []*CompiledRule{{
			Name:        "two letter plus flag",
			ToolPattern: regexp.MustCompile(`^bash$`),
			ArgPattern:  regexp.MustCompile(`^[a-z]{2} [+][rf]+$`),
			Action:      config.ActionBlock,
		}},
	}
}

func TestSplitPairTokens_ReportsDroppedTokens(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []string
		dropped bool
	}{
		{"anchor past its keep moves to the rest", pastAnchorKeep(), false},
		{"rest past its keep", append([]string{"rm"}, pathOperands(maxPairChecks/2+1)...), true},
		{"anchors and rest past their keeps", append(shortWords(maxPairwiseTokens), pathOperands(maxPairChecks/2+1)...), true},
		{"repeats are not dropped", append(shortWords(maxPairwiseTokens), shortWords(maxPairwiseTokens)...), false},
		{"rest at its keep", append([]string{"rm"}, pathOperands(maxPairChecks/2)...), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, dropped := splitPairTokens(tt.tokens); dropped != tt.dropped {
				t.Fatalf("dropped = %v, want %v", dropped, tt.dropped)
			}
		})
	}
}

func TestMatchBoundedPairs_ReportsIncompleteScan(t *testing.T) {
	literal := regexp.MustCompile(`(?i)\brm\s+-x$`)
	noLiteral := regexp.MustCompile(`^[a-z]{2} [+][rf]+$`)
	tests := []struct {
		name     string
		pat      *regexp.Regexp
		segs     [][]string
		complete bool
	}{
		{"literal tokens past the limit", literal, [][]string{literalCrowd(70)}, false},
		{"literal tokens within the limit", literal, [][]string{literalCrowd(64)}, true},
		{"literal tokens split over commands", literal, [][]string{literalCrowd(40), literalCrowd(40)}, true},
		{"anchors past the limit", noLiteral, [][]string{pastAnchorKeep()}, false},
		{"dropped tokens", noLiteral, [][]string{append([]string{"rm"}, pathOperands(maxPairChecks/2+1)...)}, false},
		{"one anchor, rest at its keep", noLiteral, [][]string{append([]string{"rm"}, pathOperands(maxPairChecks/2)...)}, true},
		{"64 anchors fit the limit exactly", noLiteral, [][]string{shortWords(maxPairwiseTokens)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, checks, complete := matchBoundedPairs(tt.pat, tt.segs)
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
}

// wantIncomplete checks that v carries the incomplete signal with action.
func wantIncomplete(t *testing.T, v Verdict, action string) {
	t.Helper()
	if !v.Matched || v.Action != action {
		t.Fatalf("verdict matched=%v action=%q, want %q (rules %v)", v.Matched, v.Action, action, v.Rules)
	}
	if !slices.Contains(v.Rules, incompletePairCheckRule) {
		t.Fatalf("rules %v lack %q", v.Rules, incompletePairCheckRule)
	}
	if !slices.ContainsFunc(v.Notes, func(n string) bool { return strings.Contains(n, "could not rule out a match") }) {
		t.Fatalf("notes %v do not explain the incomplete check", v.Notes)
	}
}

func TestDefaultRules_IncompletePairCheck(t *testing.T) {
	crowd := literalCrowd(70)
	tests := []struct {
		name   string
		args   []string
		action string // on_incomplete_check
		want   string // verdict action; "" means no verdict
	}{
		{"check limit reached, default", crowd, "", config.ActionWarn},
		{"check limit reached, warn", crowd, config.ActionWarn, config.ActionWarn},
		{"check limit reached, block", crowd, config.ActionBlock, config.ActionBlock},
		{"check limit reached in a string, block", []string{strings.Join(crowd, " ")}, config.ActionBlock, config.ActionBlock},
		// Controls: the same shape inside the limit, or split into
		// commands that each fit, is checked in full and raises nothing.
		{"within the limit, block", literalCrowd(64), config.ActionBlock, ""},
		{"split commands within the limit, block", []string{strings.Join(literalCrowd(60)[:30], " ") + " && " + strings.Join(literalCrowd(60)[30:], " ")}, config.ActionBlock, ""},
		// Each command fits, but the whole string read as one command does
		// not, so a match across the commands is not ruled out.
		{"split commands past the limit, block", []string{strings.Join(literalCrowd(80)[:40], " ") + " && " + strings.Join(literalCrowd(80)[40:], " ")}, config.ActionBlock, config.ActionBlock},
		{"short list, block", []string{"-rf", "w0", "w1", "ls"}, config.ActionBlock, ""},
		{"200 paths, block", append([]string{"ls"}, pathOperands(200)...), config.ActionBlock, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := defaultConfigWithIncomplete(t, tt.action).CheckToolCall("bash", tt.args)
			if tt.want == "" {
				if v.Matched {
					t.Fatalf("unexpected verdict %s %v", v.Action, v.Rules)
				}
				return
			}
			wantIncomplete(t, v, tt.want)
		})
	}
}

func TestNoLiteralRule_IncompletePairCheck(t *testing.T) {
	dropped := append(append(shortWords(maxPairwiseTokens), pathOperands(maxPairChecks/2)...), "zz", "+rf")
	tests := []struct {
		name   string
		args   []string
		action string
		want   string
	}{
		{"dropped tokens, default", dropped, "", config.ActionWarn},
		{"dropped tokens, block", dropped, config.ActionBlock, config.ActionBlock},
		{"check limit reached, default", pastAnchorKeep(), "", config.ActionWarn},
		{"check limit reached, block", pastAnchorKeep(), config.ActionBlock, config.ActionBlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantIncomplete(t, noLiteralConfig(tt.action).CheckToolCall("bash", tt.args), tt.want)
		})
	}
	// Positive control: the pair is found when it fits.
	v := noLiteralConfig(config.ActionBlock).CheckToolCall("bash", append(append([]string{"zz"}, pathOperands(500)...), "+rf"))
	if !v.Matched || v.Action != config.ActionBlock || !slices.Equal(v.Rules, []string{"two letter plus flag"}) {
		t.Fatalf("verdict %v %q %v, want the rule alone", v.Matched, v.Action, v.Rules)
	}
}

func TestDefaultRules_FlagBeforeCommandWord(t *testing.T) {
	// The flag first and the command word after 63 short words: every
	// pair with the command word is checked, so the rule matches.
	for _, form := range [][]string{pastAnchorKeep(), {strings.Join(pastAnchorKeep(), " ")}} {
		v := defaultConfigWithIncomplete(t, "").CheckToolCall("bash", form)
		if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, ruleFileDelete) {
			t.Fatalf("%d strings: verdict %v %q %v, want %q", len(form), v.Matched, v.Action, v.Rules, ruleFileDelete)
		}
		if slices.Contains(v.Rules, incompletePairCheckRule) {
			t.Fatalf("%d strings: rules %v report an incomplete check", len(form), v.Rules)
		}
	}
	// Control: without the flag nothing matches.
	if v := defaultConfig(t).CheckToolCall("bash", pastAnchorKeep()[1:]); v.Matched {
		t.Fatalf("unexpected verdict %s %v", v.Action, v.Rules)
	}
}

func TestIncompleteCheckKeepsMatchedRules(t *testing.T) {
	// A rule that matches still reports itself next to the incomplete
	// signal, and the stricter action wins.
	pc := noLiteralConfig(config.ActionWarn)
	pc.Rules = append(pc.Rules, &CompiledRule{
		Name:        "named word",
		ToolPattern: regexp.MustCompile(`^bash$`),
		ArgPattern:  regexp.MustCompile(`^danger$`),
		Action:      config.ActionBlock,
	})
	v := pc.CheckToolCall("bash", append(pastAnchorKeep(), "danger"))
	if !slices.Contains(v.Rules, "named word") || !slices.Contains(v.Rules, incompletePairCheckRule) {
		t.Fatalf("rules %v, want %q and %q", v.Rules, "named word", incompletePairCheckRule)
	}
	if v.Action != config.ActionBlock {
		t.Fatalf("action %q, want block from the matched rule", v.Action)
	}
}

func TestDefaultRules_LongListingAllowedByDefault(t *testing.T) {
	pc := defaultConfig(t)
	for _, args := range [][]string{
		append([]string{"ls"}, shortWords(199)...),
		append([]string{"ls", "-la"}, pathOperands(198)...),
		slices.Repeat([]string{"ls"}, 200),
	} {
		for _, form := range [][]string{args, {strings.Join(args, " ")}} {
			if v := pc.CheckToolCall("bash", form); v.Matched {
				t.Fatalf("%d-token listing matched: %s %v", len(args), v.Action, v.Rules)
			}
		}
	}
}

func TestNew_CarriesIncompleteAction(t *testing.T) {
	for _, action := range []string{"", config.ActionWarn, config.ActionBlock} {
		pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules(), OnIncompleteCheck: action})
		if pc.IncompleteAction != action {
			t.Fatalf("IncompleteAction = %q, want %q", pc.IncompleteAction, action)
		}
		want := config.ActionWarn
		if action == config.ActionBlock {
			want = config.ActionBlock
		}
		if got := pc.incompleteAction(); got != want {
			t.Fatalf("incompleteAction() = %q for %q, want %q", got, action, want)
		}
	}
}
