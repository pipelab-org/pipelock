// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func keywordConfigYAML(fields string) string {
	return "dlp:\n  include_defaults: false\n  patterns:\n    - name: Account\n      regex: '[0-9]{16}'\n      severity: high\n" + fields
}

func TestDLPKeywordsLoad(t *testing.T) {
	const accountSample = "ACCOUNT 3333333333333333"
	const abcSample = "abc3333333333333333" // the whole keyword must fit the three-rune window
	// Beyond the default 50-rune window, so only an honored 300 qualifies it.
	farSample := "ACCOUNT" + strings.Repeat(" ", 51) + "3333333333333333"
	for _, tc := range []struct {
		fields      string
		wantMatcher bool
		sample      string
		start, end  int
	}{
		{fields: ""},
		{fields: "      keywords: null\n"},
		{fields: "      keywords:\n"},
		{fields: "      keywords: []\n"},
		{fields: "      keywords: [account]\n", wantMatcher: true, sample: accountSample, start: 8, end: 24},
		{fields: "      keywords: [account]\n      keyword_window: null\n", wantMatcher: true, sample: accountSample, start: 8, end: 24},
		{fields: "      keywords: [account]\n      keyword_window:\n", wantMatcher: true, sample: accountSample, start: 8, end: 24},
		{fields: "      keywords: [abc]\n      keyword_window: 3\n", wantMatcher: true, sample: abcSample, start: 3, end: 19},
		{fields: "      keywords: [account]\n      keyword_window: 300\n", wantMatcher: true, sample: farSample, start: 58, end: 74},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(keywordConfigYAML(tc.fields)))
			if err != nil {
				t.Fatal(err)
			}
			p := cfg.DLP.Patterns[0]
			matcher, err := p.CompileKeywords()
			if err != nil {
				t.Fatal(err)
			}
			if (matcher != nil) != tc.wantMatcher {
				t.Fatalf("matcher loaded=%v, want %v", matcher != nil, tc.wantMatcher)
			}
			if tc.wantMatcher && !matcher.Matches(tc.sample, tc.start, tc.end) {
				t.Fatalf("keyword near candidate in %q did not qualify", tc.sample)
			}
		})
	}
}

func TestDLPKeywordsRejectsInvalid(t *testing.T) {
	fields := []string{
		"keywords: account", "keywords: {account: true}", "keywords: [123]", "keywords: [true]", "keywords: [null]", "keywords: ['']", "keywords: ['   ']", "keywords: ['ab']", "keywords: [' account']", "keywords: ['account ']", `keywords: ["ab\nc"]`, "keywords: [account, ACCOUNT]", "keywords: [key, Key]", "keywords: ['áb']", "keywords: [account]\n      keyword_window: 0", "keywords: [account]\n      keyword_window: -1", "keywords: [account]\n      keyword_window: 301", "keywords: [account]\n      keyword_window: 1.5", "keywords: [account]\n      keyword_window: '50'", "keywords: [account]\n      keyword_window: ''", "keywords: [account]\n      keyword_window: true", "keywords: [account]\n      keyword_window: false", "keywords: [account]\n      keyword_window: 1", "keywords: [account]\n      keyword_window: 2", "keywords: [account]\n      keyword_window: 6", "keyword_window: 50", "keywords: []\n      keyword_window: 50", "keywordz: [account]", "keywords: ['" + strings.Repeat("x", 91) + "']",
	}
	var terms []string
	for i := range 51 {
		terms = append(terms, fmt.Sprintf("term%d", i))
	}
	fields = append(fields, "keywords: ["+strings.Join(terms, ",")+"]")
	for _, fields := range fields {
		t.Run(fields, func(t *testing.T) {
			if _, err := LoadBytes([]byte(keywordConfigYAML("      " + fields + "\n"))); err == nil {
				t.Fatal("accepted invalid keyword control")
			}
		})
	}
}

func TestDLPKeywordsProgrammatic(t *testing.T) {
	for _, p := range []DLPPattern{
		{Name: "custom", Regex: "[0-9]{16}", Keywords: []string{string([]byte{'a', 'b', 0xff})}},
		{Name: "custom", Regex: "[0-9]{16}", Keywords: []string{"abc"}, KeywordWindow: new(0)},
		{Name: "custom", Regex: "[0-9]{16}", Keywords: []string{"abc"}, Compiled: true},
		{Name: CoreDLPPatterns()[0].Name, Regex: "[0-9]{16}", Keywords: []string{"abc"}},
	} {
		if err := p.ValidateKeywords(); err == nil {
			t.Fatalf("accepted invalid pattern %+v", p)
		}
	}
	for _, p := range DefaultDLPPatterns() {
		p.Compiled = false
		p.Keywords = []string{"account"}
		if err := p.ValidateKeywords(); err == nil {
			t.Fatalf("accepted canonical detector %s", p.Name)
		}
	}
	p := DLPPattern{Name: DefaultDLPPatterns()[0].Name, Regex: "custom[0-9]{16}", Keywords: []string{"account"}}
	if err := p.ValidateKeywords(); err != nil && !IsCoreDLPPatternName(p.Name) {
		t.Fatal(err)
	}
}

func TestDLPKeywordsCloneHashAndReload(t *testing.T) {
	base, err := LoadBytes([]byte(keywordConfigYAML("")))
	if err != nil {
		t.Fatal(err)
	}
	gate := base.Clone()
	gate.DLP.Patterns[0].Keywords = []string{"account", "customer"}
	defaults := gate.Clone()
	defaults.DLP.Patterns[0].Keywords = []string{"CUSTOMER", "ACCOUNT"}
	defaults.DLP.Patterns[0].KeywordWindow = new(50)
	if gate.CanonicalPolicyHash() != defaults.CanonicalPolicyHash() {
		t.Fatal("equivalent keyword controls changed policy identity")
	}
	if gate.CanonicalPolicyHash() == base.CanonicalPolicyHash() {
		t.Fatal("keyword gate missing from policy identity")
	}
	clone := defaults.Clone()
	clone.DLP.Patterns[0].Keywords[0] = "payment"
	*clone.DLP.Patterns[0].KeywordWindow = 30
	if defaults.DLP.Patterns[0].Keywords[0] != "CUSTOMER" || *defaults.DLP.Patterns[0].KeywordWindow != 50 {
		t.Fatal("mutable clone shared keyword state")
	}
	for _, tc := range []struct {
		name    string
		next    DLPPattern
		reduced bool
	}{
		{"enable", gate.DLP.Patterns[0], true},
		{"equivalent", defaults.DLP.Patterns[0], false},
		{"remove term", DLPPattern{Keywords: []string{"account"}}, true},
		{"add term", DLPPattern{Keywords: []string{"account", "customer", "payment"}}, false},
		{"shrink", DLPPattern{Keywords: []string{"account", "customer"}, KeywordWindow: new(49)}, true},
		{"enlarge", DLPPattern{Keywords: []string{"account", "customer"}, KeywordWindow: new(51)}, false},
		{"disable", DLPPattern{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := gate.DLP.Patterns[0]
			if tc.name == "enable" {
				old = base.DLP.Patterns[0]
			}
			if got := KeywordCoverageReduced(old, tc.next); got != tc.reduced {
				t.Fatalf("reduced=%v, want %v", got, tc.reduced)
			}
			next := old
			next.Keywords = tc.next.Keywords
			next.KeywordWindow = tc.next.KeywordWindow
			changes := removedOrWeakenedDLPPatterns([]DLPPattern{old}, []DLPPattern{next})
			if (len(changes) > 0) != tc.reduced {
				t.Fatalf("reload changes=%v", changes)
			}
		})
	}
}

func TestDLPKeywordsPredicate(t *testing.T) {
	p := DLPPattern{Name: "custom", Regex: "[0-9]+", Keywords: []string{"key"}, KeywordWindow: new(5)}
	gate, err := p.CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		left, right string
		want        bool
	}{
		{"key  ", "", true},
		{"key   ", "", false},
		{"", "  key", true},
		{"", "   key", false},
		{"monkey", "", true},
		{"", "KEY", true},
		{"key界界", "", true},
		{"key界界界", "", false},
		{"", "", false},
	} {
		text := tc.left + "1234" + tc.right
		if got := gate.Matches(text, len(tc.left), len(tc.left)+4); got != tc.want {
			t.Errorf("%q: got %v want %v", text, got, tc.want)
		}
	}
	if gate.Matches("key1234", 0, 7) {
		t.Fatal("keyword inside candidate corroborated itself")
	}
}

func TestDLPKeywordsDocsAndPresets(t *testing.T) {
	for _, profile := range []string{DLPPresetProfileFull, DLPPresetProfileQuickstart, DLPPresetProfileHostile} {
		patterns, err := PresetDLPPatterns(profile)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range patterns {
			if len(p.Keywords) > 0 || p.KeywordWindow != nil {
				t.Fatalf("preset %s unexpectedly narrowed %s", profile, p.Name)
			}
		}
	}
	data, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	section := strings.SplitN(string(data), "### Nearby keywords for custom patterns", 2)[1]
	example := strings.SplitN(strings.SplitN(section, "```yaml\n", 2)[1], "```", 2)[0]
	if _, err := LoadBytes([]byte(example)); err != nil {
		t.Fatalf("documented YAML: %v", err)
	}
	for _, include := range []string{"", "  include_defaults: true\n", "  include_defaults: false\n"} {
		body := strings.Replace(example, "dlp:\n", "dlp:\n"+include, 1)
		cfg, err := LoadBytes([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, p := range cfg.DLP.Patterns {
			if p.Name == "Customer account number" {
				found = len(p.Keywords) > 0
			}
		}
		if !found {
			t.Fatal("default merging dropped custom control")
		}
	}
}

func TestDLPKeywordsLegacyPolicyHashGolden(t *testing.T) {
	// Legacy values were captured from the pre-keyword policy at
	// 06907c6982b07f25905d4d40782cb9d76badd6cb. The balanced default-corpus
	// case was rebaselined for the Anthropic credential audience change and
	// the JWT sign-in bearer carrier, then for the Doppler, 1Password and age
	// patterns and the widened PyPI and Sentry patterns.
	// Balanced mode without default patterns retains its pre-keyword hash
	// independently of changes to the built-in corpus.
	for _, tc := range []struct{ body, want string }{
		{keywordConfigYAML(""), "85c76016e5a0725a682561e23f18dd8ebade2ada53e72c7324cbb511f7749ed6"},
		{"mode: balanced\n", "3eeacdd6767200e0d57638cf4fb51a33e42b899a78cb7feacce8bb594ed31b93"},
		{"mode: balanced\ndlp:\n  include_defaults: false\n", "66df31a95a2ce552d4d50fc55356f0dd204d8bf3999a3bfa90bf9c3332710d86"},
	} {
		cfg, err := LoadBytes([]byte(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.CanonicalPolicyHash(); got != tc.want {
			t.Fatalf("omitted fields changed legacy policy identity: got %s want %s", got, tc.want)
		}
	}
}

func TestDLPKeywordsAgentCloneIsolation(t *testing.T) {
	cfg := Defaults()
	cfg.Agents = map[string]AgentProfile{"operator": {DLP: &AgentDLP{Patterns: []DLPPattern{{Name: "account", Regex: `[0-9]{16}`, Keywords: []string{"account"}, KeywordWindow: new(50)}}}}}
	clone := cfg.Clone()
	clone.Agents["operator"].DLP.Patterns[0].Keywords[0] = "payment"
	*clone.Agents["operator"].DLP.Patterns[0].KeywordWindow = 30
	p := cfg.Agents["operator"].DLP.Patterns[0]
	if p.Keywords[0] != "account" || *p.KeywordWindow != 50 {
		t.Fatal("agent keyword controls shared mutable clone state")
	}
}

func TestDLPKeywordsYAMLMerge(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		wantError    bool
	}{
		{name: "legacy"},
		{name: "keywords", fields: "      keywords: [account]\n      keyword_window: 50\n"},
		{name: "unknown merged field", fields: "      keywordz: [account]\n", wantError: true},
		{name: "invalid merged type", fields: "      keywords: [123]\n", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := "dlp:\n  include_defaults: false\n  patterns:\n    - &defaults\n      name: original\n      regex: '[0-9]{16}'\n      severity: high\n" + tc.fields + "    - <<: *defaults\n      name: merged\n"
			if tc.wantError {
				data = "dlp:\n  include_defaults: false\n  patterns:\n    - &defaults\n      name: original\n      regex: '[0-9]{16}'\n      severity: high\n    - name: merged\n      <<:\n        regex: '[0-9]{16}'\n        severity: high\n" + strings.ReplaceAll(tc.fields, "      ", "        ")
			}
			// The pre-keyword decoder used yaml.v3's native struct merge behavior.
			type legacyPattern struct{ Name, Regex, Severity string }
			var legacy struct {
				DLP struct{ Patterns []legacyPattern }
			}
			if err := yaml.Unmarshal([]byte(data), &legacy); err != nil || len(legacy.DLP.Patterns) != 2 || legacy.DLP.Patterns[1].Regex != `[0-9]{16}` {
				t.Fatalf("legacy merge control: %+v, %v", legacy, err)
			}
			cfg, err := LoadBytes([]byte(data))
			if (err != nil) != tc.wantError {
				t.Fatalf("load error=%v wantError=%v", err, tc.wantError)
			}
			if err != nil {
				return
			}
			merged := cfg.DLP.Patterns[1]
			if merged.Regex != cfg.DLP.Patterns[0].Regex || merged.Name != "merged" {
				t.Fatalf("merged pattern=%+v", merged)
			}
			if tc.fields != "" && (len(merged.Keywords) != 1 || merged.Keywords[0] != "account" || merged.KeywordWindow == nil || *merged.KeywordWindow != 50) {
				t.Fatalf("merged pattern lost inherited keyword controls: %+v", merged)
			}
		})
	}
}

func TestDLPKeywordsMatchesAnywhere(t *testing.T) {
	pattern := DLPPattern{Name: "custom", Keywords: []string{"account", "api.key"}}
	matcher, err := pattern.CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"", false},
		{"ordinary text", false},
		{"ACCOUNT" + strings.Repeat("x", 70), true},
		{"prefix api.key suffix", true},
		{"prefix apiXkey suffix", false},
	} {
		if got := matcher.MatchesAnywhere(tc.text); got != tc.want {
			t.Fatalf("MatchesAnywhere(%q)=%v, want %v", tc.text, got, tc.want)
		}
	}
	var disabled *DLPKeywordMatcher
	if !disabled.MatchesAnywhere("") {
		t.Fatal("disabled keywords must accept")
	}
}
