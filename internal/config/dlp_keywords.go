// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"gopkg.in/yaml.v3"
)

// DefaultDLPKeywordWindow follows the AWS Macie custom identifier distance.
const DefaultDLPKeywordWindow = 50

const dlpKeywordAdvisory = "keyword-gated custom patterns miss values without nearby labels; keywords reduce accidental-leak noise and do not prevent deliberate exfiltration"

// EffectiveKeywordWindow resolves the optional per-side character distance.
func (p DLPPattern) EffectiveKeywordWindow() int {
	if p.KeywordWindow != nil {
		return *p.KeywordWindow
	}
	return DefaultDLPKeywordWindow
}

// CanonicalKeywords returns the normalized, simple-folded keyword OR-set.
// It does not mutate the operator's configuration.
func (p DLPPattern) CanonicalKeywords() []string {
	if len(p.Keywords) == 0 {
		return nil
	}
	out := make([]string, len(p.Keywords))
	for i, term := range p.Keywords {
		out[i] = strings.Map(func(r rune) rune {
			smallest := r
			for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
				smallest = min(smallest, f)
			}
			return smallest
		}, normalize.ForDLP(term))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// KeywordCoverageReduced compares effective OR-sets without guessing semantic
// implications between different substrings.
func KeywordCoverageReduced(old, next DLPPattern) bool {
	if len(next.Keywords) == 0 {
		return false
	}
	if len(old.Keywords) == 0 || next.EffectiveKeywordWindow() < old.EffectiveKeywordWindow() {
		return true
	}
	terms := next.CanonicalKeywords()
	for _, term := range old.CanonicalKeywords() {
		if !slices.Contains(terms, term) {
			return true
		}
	}
	return false
}

// ValidateKeywords applies equally to YAML and programmatically built rules.
func (p DLPPattern) ValidateKeywords() error {
	fail := func(reason string) error {
		return fmt.Errorf("DLP pattern %q keywords/keyword_window: %s", p.Name, reason)
	}
	if p.KeywordWindow != nil && (*p.KeywordWindow < 1 || *p.KeywordWindow > 300) {
		return fail("keyword_window must be an integer from 1 to 300")
	}
	if len(p.Keywords) == 0 {
		if p.KeywordWindow != nil {
			return fail("keyword_window requires nonempty keywords")
		}
		return nil
	}
	if len(p.Keywords) > 50 {
		return fail("keywords must contain at most 50 entries")
	}
	if p.Compiled || IsCoreDLPPatternName(p.Name) || p.canonicalBuiltInDetector() {
		return fail("built-in and core patterns cannot require keywords")
	}
	for _, term := range p.Keywords {
		n := utf8.RuneCountInString(term)
		normalized := normalize.ForDLP(term)
		size := utf8.RuneCountInString(normalized)
		if !utf8.ValidString(term) || n < 3 || n > 90 || size < 3 || size > 90 {
			return fail("each keyword must contain 3 to 90 Unicode scalar values before and after DLP normalization")
		}
		if strings.TrimSpace(term) != term || strings.TrimSpace(normalized) != normalized || strings.ContainsFunc(term, unicode.IsControl) {
			return fail("keywords must not contain controls or leading/trailing whitespace")
		}
		if size > p.EffectiveKeywordWindow() {
			return fail("keyword is longer than keyword_window; enlarge keyword_window")
		}
	}
	if len(p.CanonicalKeywords()) != len(p.Keywords) {
		return fail("keywords must not contain normalized case-insensitive duplicates")
	}
	return nil
}

func (p DLPPattern) canonicalBuiltInDetector() bool {
	for _, builtIn := range defaultDLPPatternSet {
		if p.Regex == builtIn.Regex && p.Validator == builtIn.Validator {
			return true
		}
	}
	return false
}

// DLPKeywordMatcher is a pure, immutable proximity predicate shared by traffic
// and offline scanners. Byte offsets identify the candidate; windows count runes.
type DLPKeywordMatcher struct {
	re     *regexp.Regexp
	window int
}

// CompileKeywords validates and compiles literal, case-insensitive terms.
func (p DLPPattern) CompileKeywords() (*DLPKeywordMatcher, error) {
	if err := p.ValidateKeywords(); err != nil {
		return nil, err
	}
	if len(p.Keywords) == 0 {
		return nil, nil
	}
	terms := p.CanonicalKeywords()
	for i := range terms {
		terms[i] = regexp.QuoteMeta(terms[i])
	}
	re, err := regexp.Compile("(?i:" + strings.Join(terms, "|") + ")")
	if err != nil {
		return nil, fmt.Errorf("DLP pattern %q keywords: %w", p.Name, err)
	}
	return &DLPKeywordMatcher{re: re, window: p.EffectiveKeywordWindow()}, nil
}

// Matches tests complete keywords wholly outside the candidate in either side.
// source must already have text-preserving DLP normalization applied.
func (m *DLPKeywordMatcher) Matches(source string, start, end int) bool {
	if m == nil {
		return true
	}
	if start < 0 || end < start || end > len(source) {
		return false
	}
	left, right := start, end
	for n := 0; left > 0 && n < m.window; n++ {
		_, size := utf8.DecodeLastRuneInString(source[:left])
		left -= size
	}
	for n := 0; right < len(source) && n < m.window; n++ {
		_, size := utf8.DecodeRuneInString(source[right:])
		right += size
	}
	return m.re.MatchString(source[left:start]) || m.re.MatchString(source[end:right])
}

// MatchesAnywhere tests the same literal keywords without a proximity window.
// URL DLP uses it only when an exact candidate source span is unavailable.
// source must already have DLP normalization applied.
func (m *DLPKeywordMatcher) MatchesAnywhere(source string) bool {
	return m == nil || m.re.MatchString(source)
}

// UnmarshalYAML keeps strict nested fields and rejects YAML scalar coercions.
func (p *DLPPattern) UnmarshalYAML(node *yaml.Node) error {
	type plain DLPPattern
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("DLP pattern must be a mapping")
	}
	// Let yaml.v3 resolve merge precedence and reject duplicate keys before
	// checking effective fields. Node values retain the scalar tags needed
	// to reject coercions in keyword settings.
	var fields map[string]yaml.Node
	if err := node.Decode(&fields); err != nil {
		return err
	}
	patternName := "<unnamed>"
	if name, ok := fields["name"]; ok {
		patternName = name.Value
	}
	fail := func(reason string) error { return fmt.Errorf("DLP pattern %q %s", patternName, reason) }
	var raw plain
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		value := fields[key]
		switch key {
		case "name", "regex", "severity", "validator", "exempt_domains", "action":
		case "keywords":
			if value.Tag == "!!null" {
				continue
			}
			if value.Kind != yaml.SequenceNode {
				return fail("keywords must be a list of strings")
			}
			for _, term := range value.Content {
				if term.Kind != yaml.ScalarNode || term.Tag != "!!str" {
					return fail("keywords entries must be strings")
				}
			}
		case "keyword_window":
			if value.Tag != "!!null" && (value.Kind != yaml.ScalarNode || value.Tag != "!!int") {
				return fail("keyword_window must be an integer")
			}
		default:
			return fail(fmt.Sprintf("has unknown field %q", key))
		}
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*p = DLPPattern(raw)
	return nil
}

// KeywordPolicyIdentity binds the effective context policy for reload adapters.
func (p DLPPattern) KeywordPolicyIdentity() string {
	if len(p.Keywords) == 0 {
		return ""
	}
	data, _ := json.Marshal(struct {
		Keywords []string
		Window   int
	}{p.CanonicalKeywords(), p.EffectiveKeywordWindow()})
	return string(data)
}

// DLPKeywordContext applies DLP normalization without deleting Unicode
// whitespace. Distance-bearing whitespace and synthetic projection separators
// retain their character count.
func DLPKeywordContext(text string) string {
	if !strings.ContainsFunc(text, func(r rune) bool { return unicode.IsSpace(r) || r == 0 }) {
		return normalize.ForDLP(text)
	}
	var b strings.Builder
	from := 0
	for i, c := range text {
		if unicode.IsSpace(c) || c == 0 {
			b.WriteString(normalize.ForDLP(text[from:i]))
			b.WriteRune(c)
			from = i + utf8.RuneLen(c)
		}
	}
	b.WriteString(normalize.ForDLP(text[from:]))
	return b.String()
}

func (c *Config) agentDLPKeywordWarnings() []Warning {
	var warnings []Warning
	for _, name := range slices.Sorted(maps.Keys(c.Agents)) {
		profile := c.Agents[name]
		if profile.DLP == nil {
			continue
		}
		for i, pattern := range profile.DLP.Patterns {
			if len(pattern.Keywords) > 0 {
				warnings = append(warnings, Warning{Field: fmt.Sprintf("agents.%s.dlp.patterns[%d].keywords", name, i), Message: dlpKeywordAdvisory})
			}
		}
	}
	return warnings
}
