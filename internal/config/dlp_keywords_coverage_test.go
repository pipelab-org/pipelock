// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDLPKeywordsValidationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		terms     []string
		window    *int
		wantError string
	}{
		{name: "omitted"},
		{name: "empty", terms: []string{}},
		{name: "minimum length", terms: []string{"abc"}, window: new(3)},
		{name: "maximum length", terms: []string{strings.Repeat("界", 90)}, window: new(90)},
		{name: "maximum window", terms: []string{"account"}, window: new(300)},
		{name: "malformed UTF8", terms: []string{"ab\xff"}, wantError: "Unicode scalar"},
		{name: "short after normalization", terms: []string{"a\u200bb"}, wantError: "Unicode scalar"},
		{name: "long after normalization", terms: []string{strings.Repeat("ﬃ", 31)}, window: new(300), wantError: "Unicode scalar"},
		{name: "control", terms: []string{"acc\x00ount"}, wantError: "controls"},
		{name: "normalized whitespace", terms: []string{"\u200b account"}, wantError: "whitespace"},
		{name: "normalized duplicate", terms: []string{"account", "ａｃｃｏｕｎｔ"}, wantError: "duplicates"},
		{name: "window below minimum", terms: []string{"account"}, window: new(0), wantError: "1 to 300"},
		{name: "window above maximum", terms: []string{"account"}, window: new(301), wantError: "1 to 300"},
		{name: "orphan window", window: new(50), wantError: "requires nonempty"},
		{name: "keyword exceeds window", terms: []string{"account"}, window: new(6), wantError: "longer than"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := DLPPattern{Name: "custom", Regex: `[0-9]{16}`, Keywords: tc.terms, KeywordWindow: tc.window}
			err := p.ValidateKeywords()
			matcher, compileErr := p.CompileKeywords()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) || compileErr == nil || matcher != nil {
					t.Fatalf("validation=%v compile=%v matcher=%v", err, compileErr, matcher)
				}
				return
			}
			if err != nil || compileErr != nil {
				t.Fatalf("validation=%v compile=%v", err, compileErr)
			}
			if len(tc.terms) > 0 && p.KeywordPolicyIdentity() == "" {
				t.Fatal("configured keywords lost policy identity")
			}
			if len(tc.terms) == 0 && (p.CanonicalKeywords() != nil || matcher != nil || p.KeywordPolicyIdentity() != "") {
				t.Fatal("empty keywords changed effective policy")
			}
		})
	}
}

func TestDLPKeywordsYAMLDecodeErrors(t *testing.T) {
	for _, tc := range []struct{ name, document, want string }{
		{"scalar pattern", `account`, "must be a mapping"},
		{"sequence pattern", `[account]`, "must be a mapping"},
		{"duplicate field", "name: custom\nkeywords: [account]\nkeywords: [payment]\n", "already defined"},
		{"invalid plain field", "name: custom\nregex: [not, a, string]\n", "cannot unmarshal"},
		{"unknown unnamed field", "keywordz: [account]\n", "<unnamed>"},
		{"mapping entry", "keywords: [{account: true}]\n", "entries must be strings"},
		{"sequence window", "keyword_window: [50]\n", "must be an integer"},
		{"overflow window", "keyword_window: 999999999999999999999999999999999999\n", "must be an integer"},
		{"float keyword", "keywords: [1.5]\n", "entries must be strings"},
		{"alias keyword", "name: &label account\nkeywords: [*label]\n", "entries must be strings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p DLPPattern
			err := yaml.Unmarshal([]byte(tc.document), &p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestDLPKeywordsMatcherInvalidCoordinates(t *testing.T) {
	gate, err := (DLPPattern{Name: "custom", Keywords: []string{"account"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		gate       *DLPKeywordMatcher
		text       string
		start, end int
		want       bool
	}{
		{"nil matcher", nil, "", -1, 20, true},
		{"negative start", gate, "account 123", -1, 11, false},
		{"reversed", gate, "account 123", 11, 8, false},
		{"past end", gate, "account 123", 8, 12, false},
		{"empty context", gate, "", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.gate.Matches(tc.text, tc.start, tc.end); got != tc.want {
				t.Fatalf("match=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestDLPKeywordsContextAndAgentWarnings(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"", ""}, {"ａｃｃｏｕｎｔ", "account"}, {"ａｃｃｏｕｎｔ\u2003\x00１２３\n", "account\u2003\x00123\n"},
	} {
		if got := DLPKeywordContext(tc.input); got != tc.want {
			t.Errorf("context %q=%q, want %q", tc.input, got, tc.want)
		}
	}
	cfg := Defaults()
	cfg.Agents = map[string]AgentProfile{
		"empty": {},
		"zeta":  {DLP: &AgentDLP{Patterns: []DLPPattern{{Name: "legacy"}, {Name: "custom", Keywords: []string{"account"}}}}},
		"alpha": {DLP: &AgentDLP{Patterns: []DLPPattern{{Name: "custom", Keywords: []string{"payment"}}}}},
	}
	warnings := cfg.agentDLPKeywordWarnings()
	if len(warnings) != 2 || warnings[0].Field != "agents.alpha.dlp.patterns[0].keywords" || warnings[1].Field != "agents.zeta.dlp.patterns[1].keywords" {
		t.Fatalf("warnings=%+v", warnings)
	}
	for _, w := range warnings {
		if w.Message != dlpKeywordAdvisory {
			t.Errorf("message=%q", w.Message)
		}
	}
	original := []DLPPattern{{Name: "custom", Keywords: []string{"account"}, KeywordWindow: new(50)}}
	clone := CloneDLPPatterns(original)
	clone[0].Keywords[0] = "payment"
	*clone[0].KeywordWindow = 30
	if original[0].Keywords[0] != "account" || *original[0].KeywordWindow != 50 {
		t.Fatal("clone changed original")
	}
	builtIn := DefaultDLPPatterns()[0]
	for _, tc := range []DLPPattern{
		func() DLPPattern { p := builtIn; p.Keywords = []string{"account"}; return p }(),
		func() DLPPattern { p := builtIn; p.KeywordWindow = new(50); return p }(),
	} {
		if got := changedFromBuiltIn(tc, builtIn); !reflect.DeepEqual(got, []string{"keywords"}) {
			t.Fatalf("changed fields=%v", got)
		}
	}
}

func TestDLPKeywordsAgentReloadFallbacks(t *testing.T) {
	previous := MergeAgentProfileFunc
	t.Cleanup(func() { MergeAgentProfileFunc = previous })
	old := Defaults()
	next := old.Clone()
	MergeAgentProfileFunc = nil
	if got := agentDLPReloadWarnings(old, next); len(got) != 0 {
		t.Fatalf("unavailable merger warnings=%+v", got)
	}
	MergeAgentProfileFunc = func(base *Config, profile *AgentProfile) (*Config, error) {
		merged := base.Clone()
		if profile.DLP != nil {
			merged.DLP.Patterns = CloneDLPPatterns(profile.DLP.Patterns)
		}
		return merged, nil
	}
	pattern := DLPPattern{Name: "custom", Regex: `[0-9]{16}`, Keywords: []string{"account"}}
	for _, tc := range []struct {
		name          string
		before, after map[string]AgentProfile
		want          int
	}{
		{name: "no profiles"},
		{name: "removed to base", before: map[string]AgentProfile{"operator": {DLP: &AgentDLP{Patterns: []DLPPattern{pattern}}}}},
		{name: "removed to gated fallback", before: map[string]AgentProfile{"operator": {}}, after: map[string]AgentProfile{"_default": {DLP: &AgentDLP{Patterns: []DLPPattern{pattern}}}}, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, after := old.Clone(), next.Clone()
			before.DLP.Patterns = []DLPPattern{{Name: "custom", Regex: pattern.Regex}}
			after.DLP.Patterns = CloneDLPPatterns(before.DLP.Patterns)
			before.Agents, after.Agents = tc.before, tc.after
			got := agentDLPReloadWarnings(before, after)
			if len(got) != tc.want {
				t.Fatalf("warnings=%+v, want %d", got, tc.want)
			}
			for _, warning := range got {
				if !strings.Contains(warning.Message, "keywords narrowed") {
					t.Errorf("warning=%+v", warning)
				}
			}
			// Exercise the public reload entry point as well as its profile comparison.
			public := ValidateReload(before, after)
			for _, warning := range got {
				found := false
				for _, candidate := range public {
					found = found || candidate.Field == warning.Field && candidate.Message == warning.Message
				}
				if !found {
					t.Errorf("profile warning missing from public reload: %+v", warning)
				}
			}
		})
	}
}
