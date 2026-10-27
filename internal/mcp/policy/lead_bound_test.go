// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// manyWords are 17 command words, one more than maxLeadingWords, with no
// shared first letter, so the parsed pattern keeps them apart.
var manyWords = []string{
	"alpha", "bravo", "charlie", "delta", "emu", "foxtrot", "golf", "hotel",
	"india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
	"chmod",
}

// permTail is what follows the command word in the test patterns: other
// words, then -R, then other words, then 777.
const permTail = `(?:\s+[^\s;|&]+)*?\s+-R(?:\s+[^\s;|&]+)*?\s+777\b`

func overWordsPattern() *regexp.Regexp {
	return regexp.MustCompile(`\b(?:` + strings.Join(manyWords, "|") + `)` + permTail)
}

func overStepsPattern() *regexp.Regexp {
	return regexp.MustCompile(strings.Repeat(`(?:\b)?`, maxLeadWordSteps) + `\bchmod` + permTail)
}

func boundedPattern() *regexp.Regexp {
	return regexp.MustCompile(`\bchmod` + permTail)
}

func TestLeadingWordsBounded_Over(t *testing.T) {
	tests := []struct {
		name string
		pat  *regexp.Regexp
		over bool
	}{
		{"too many words", overWordsPattern(), true},
		{"too many steps", overStepsPattern(), true},
		{"bounded", boundedPattern(), false},
		{"no literal start", regexp.MustCompile(`[a-z]+ -R`), false},
		{"many words or no literal start", regexp.MustCompile(`\b(?:` + strings.Join(manyWords, "|") + `|\S+=)` + permTail), false},
		{"many ways to one word", regexp.MustCompile(`(?:\b?){24}chmod` + permTail), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			words, over := leadingWordsBounded(tt.pat)
			if over != tt.over || (over && words != nil) {
				t.Fatalf("leadingWordsBounded = %q, %v, want over %v", words, over, tt.over)
			}
		})
	}
}

// TestCommandAfterParts_OverBound checks that a pattern whose command
// words are not all worked out flags the same hand-offs as one whose words
// are, and that a long command is flagged as is.
func TestCommandAfterParts_OverBound(t *testing.T) {
	long := "echo " + strings.Repeat("x ", maxPairwiseTokens) + "| xargs chmod"
	tests := []struct {
		name, cmd string
		want      bool
	}{
		{"handed to xargs", "echo -R 777 /srv | xargs chmod", true},
		{"handed after own words", "echo 777 /srv | xargs chmod -R", true},
		{"nothing handed", "echo hi | xargs chmod 644", false},
		{"one command", "ls -la /srv", false},
	}
	for _, p := range []struct {
		name string
		pat  *regexp.Regexp
	}{{"bounded", boundedPattern()}, {"too many words", overWordsPattern()}, {"too many steps", overStepsPattern()}} {
		for _, tt := range tests {
			t.Run(p.name+"/"+tt.name, func(t *testing.T) {
				if got := commandAfterParts(p.pat, [][]string{strings.Fields(tt.cmd)}); got != tt.want {
					t.Fatalf("commandAfterParts(%q) = %v, want %v", tt.cmd, got, tt.want)
				}
			})
		}
		_, over := leadingWordsBounded(p.pat)
		t.Run(p.name+"/long", func(t *testing.T) {
			if got := commandAfterParts(p.pat, [][]string{strings.Fields(long)}); got != over {
				t.Fatalf("commandAfterParts(long) = %v, want %v", got, over)
			}
		})
	}
}

// TestPresets_OverBoundIsIncomplete adds a rule whose command words are not
// all worked out to each preset, and checks that a hand-off to it is an
// incomplete check with the preset's action for one, which strict and
// hostile-model block.
func TestPresets_OverBoundIsIncomplete(t *testing.T) {
	presets, err := filepath.Glob(filepath.Join("..", "..", "..", "configs", "*.yaml"))
	if err != nil || len(presets) == 0 {
		t.Fatalf("no presets found: %v", err)
	}
	const name = "many command words"
	for _, preset := range presets {
		base := filepath.Base(preset)
		t.Run(base, func(t *testing.T) {
			cfg, err := config.Load(preset)
			if err != nil {
				t.Fatal(err)
			}
			pc := New(cfg.MCPToolPolicy)
			if pc == nil {
				t.Skip("tool policy disabled")
			}
			if (base == "strict.yaml" || base == "hostile-model.yaml") && pc.IncompleteAction != config.ActionBlock {
				t.Fatalf("incomplete action %q, want block", pc.IncompleteAction)
			}
			pc.Rules = append(pc.Rules, &CompiledRule{
				Name:        name,
				ToolPattern: regexp.MustCompile(`^bash$`),
				ArgPattern:  overWordsPattern(),
				Action:      config.ActionBlock,
			})
			v := pc.CheckToolCall("bash", []string{"echo -R 777 /tmp/x | xargs kilo"})
			if !slices.Contains(v.Rules, incompletePairCheckRule) || !slices.Contains(v.IncompleteRules, name) ||
				v.Action != pc.IncompleteAction {
				t.Fatalf("verdict %q %v %v, want %s for %q with action %q",
					v.Action, v.Rules, v.IncompleteRules, incompletePairCheckRule, name, pc.IncompleteAction)
			}
			if v := pc.CheckToolCall("bash", []string{"echo hi | xargs kilo 644"}); !slices.Contains(v.IncompleteRules, name) {
				t.Fatalf("unresolved command words must retain uncertainty, got %v", v.IncompleteRules)
			}
		})
	}
}

// TestShippedPatterns_WithinLeadBound checks that every shipped tool rule
// pattern has its command words worked out within the bounds, and the words
// of the built-in rules with the most ways to start.
func TestShippedPatterns_WithinLeadBound(t *testing.T) {
	check := func(where string, rules []config.ToolPolicyRule) {
		for _, r := range rules {
			if r.ArgPattern == "" {
				continue
			}
			if _, over := leadingWordsBounded(regexp.MustCompile(r.ArgPattern)); over {
				t.Errorf("%s: %q is over the bound", where, r.Name)
			}
		}
	}
	check("built-in", DefaultToolPolicyRules())
	want := map[string][]string{
		"Protected Path Delete":           nil,
		"Protected Path Metadata Change":  nil,
		"Protected Path Link Creation":    nil,
		"Protected Path Copy":             nil,
		"Shell Profile Write via Command": {">", "alias", "cp", "install", "link", "ln", "mv", "sed", "tee"},
	}
	for _, r := range DefaultToolPolicyRules() {
		w, ok := want[r.Name]
		if !ok {
			continue
		}
		delete(want, r.Name)
		var folded []string
		for _, x := range w {
			folded = append(folded, foldString(x))
		}
		if got := leadingWords(regexp.MustCompile(r.ArgPattern)); !slices.Equal(got, folded) {
			t.Errorf("leadingWords(%q) = %q, want %q", r.Name, got, folded)
		}
	}
	if len(want) != 0 {
		t.Errorf("built-in rules not found: %v", want)
	}
	files, _ := filepath.Glob(filepath.Join("..", "..", "..", "configs", "*.yaml"))
	more, _ := filepath.Glob(filepath.Join("..", "..", "..", "examples", "*", "pipelock.yaml"))
	files = append(files, more...)
	if len(files) < 8 {
		t.Fatalf("found %d config files", len(files))
	}
	for _, f := range files {
		cfg, err := config.Load(f)
		if err != nil {
			t.Fatalf("load %s: %v", f, err)
		}
		check(f, cfg.MCPToolPolicy.Rules)
	}
}
