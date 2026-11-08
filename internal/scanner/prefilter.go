// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// dlpPreFilter provides fast prefix-based pre-screening for DLP patterns.
// Before running expensive regex evaluations, it checks whether any known
// literal prefix appears in the input text. If no prefix is found, all regex
// checks can be skipped entirely. This is the common case for clean traffic.
//
// The pre-filter maps each literal prefix to the indices of DLP patterns that
// could match. When a prefix hits, only those specific patterns are tested
// instead of the full set.
type dlpPreFilter struct {
	// prefixes associates each lowercased literal prefix with the pattern indices
	// in the parent Scanner.dlpPatterns slice that share that prefix.
	prefixes []dlpPrefix

	// alwaysRun holds pattern indices that have no extractable literal prefix
	// (e.g., SSN with \d digits, generic credential patterns with alternations).
	// These patterns must always be evaluated regardless of pre-filter results.
	alwaysRun []int

	// shapeClass is the union of every pattern's shape-gate class and
	// shapeBypass the union of their bypass runes; see shapeRejects.
	minimumRunes int
	shapeClass   asciiByteSet
	shapeBypass  []rune
}

// dlpShapeSummary is one text's longest run of shapeClass bytes and whether
// it holds a bypass rune, computed once for all of a scan's shape gates.
type dlpShapeSummary struct {
	longest int
	bypass  bool
	ready   bool
}

type dlpPrefix struct {
	text    string
	indices []int
	// pairs lists the byte pairs of text for the pair filter in candidates.
	pairs []uint16
}

// newDLPPreFilter builds a pre-filter from compiled DLP patterns.
// It extracts the longest literal prefix from each pattern's regex source.
func newDLPPreFilter(patterns []*compiledPattern) *dlpPreFilter {
	pf := &dlpPreFilter{}
	for id, pattern := range patterns {
		minimum := patternMinimumRunes(pattern)
		if id == 0 || minimum < pf.minimumRunes {
			pf.minimumRunes = minimum
		}
	}
	prefixes := make(map[string][]int)

	bypass := make(map[rune]struct{})
	for _, p := range patterns {
		if p.shapeGate == nil {
			continue
		}
		pf.shapeClass.union(p.shapeGate.class)
		for _, r := range p.shapeGate.nonASCII {
			if _, ok := bypass[r]; !ok {
				bypass[r] = struct{}{}
				pf.shapeBypass = append(pf.shapeBypass, r)
			}
		}
	}
	for i, p := range patterns {
		anchors := extractRequiredLiteralAnchors(p.re.String())
		if len(anchors) == 0 {
			pf.alwaysRun = append(pf.alwaysRun, i)
			continue
		}
		for _, anchor := range anchors {
			// Store lowercased: the input will also be lowercased before checking.
			lower := strings.ToLower(anchor)
			prefixes[lower] = append(prefixes[lower], i)
		}
	}
	// Prefixes are immutable for this scanner. Compile the map into a compact
	// slice once so every decoded view avoids walking the map's iterator.
	pf.prefixes = make([]dlpPrefix, 0, len(prefixes))
	for prefix, indices := range prefixes {
		pf.prefixes = append(pf.prefixes, dlpPrefix{text: prefix, indices: indices, pairs: literalBytePairs(prefix)})
	}
	sort.Slice(pf.prefixes, func(i, j int) bool { return pf.prefixes[i].text < pf.prefixes[j].text })

	return pf
}

const minPreFilterAnchorLength = 3

// shapeRejects reports that gate cannot admit text, deciding every gate of a
// scan from one summary pass. gate.class is within shapeClass, so any run the
// gate admits lies inside a shapeClass run at least gate.minLen bytes long;
// with no such run and none of the bypass runes that make admits accept
// outright, admits is false. A false result proves nothing and the caller
// runs the gate itself.
func (pf *dlpPreFilter) shapeRejects(gate *regexShapeGate, text string, summary *dlpShapeSummary) bool {
	if gate == nil || !gate.class.subsetOf(pf.shapeClass) {
		return false
	}
	if !summary.ready {
		*summary = pf.summarizeShape(text)
	}
	return !summary.bypass && summary.longest < gate.minLen
}

func (pf *dlpPreFilter) summarizeShape(text string) dlpShapeSummary {
	summary := dlpShapeSummary{ready: true}
	run := 0
	for i := 0; i < len(text); {
		c := text[i]
		if c < utf8.RuneSelf {
			if pf.shapeClass.has(c) {
				run++
				summary.longest = max(summary.longest, run)
			} else {
				run = 0
			}
			i++
			continue
		}
		run = 0
		// strings.ContainsRune, which admits uses, finds U+FFFD at a
		// malformed byte; DecodeRuneInString reports that byte the same way.
		r, size := utf8.DecodeRuneInString(text[i:])
		if !summary.bypass && slices.Contains(pf.shapeBypass, r) {
			summary.bypass = true
		}
		i += size
	}
	return summary
}

// extractRequiredLiteralAnchors returns literal alternatives where every match
// of the regex must contain at least one returned string. The full syntax tree
// is always analyzed: a textual prefix is not necessarily required when a bare
// top-level alternation follows it. If any branch cannot prove an anchor, the
// pattern stays in alwaysRun.
func extractRequiredLiteralAnchors(regex string) []string {
	result := extractConservativeLiteralAnchors(regex, true)
	if isGenericCredentialAnchorSet(result) {
		return nil
	}
	return result
}

// extractConservativeLiteralAnchors returns literal alternatives where every
// regex match must contain at least one returned string. It is shared by the
// DLP and response prefilters so both fail closed on the same regex syntax.
// preferLeading lets the DLP hot path choose a longer proven leading set;
// response keywords stay on literal runs and do not absorb whitespace classes.
func extractConservativeLiteralAnchors(regex string, preferLeading bool) []string {
	re, err := syntax.Parse(regex, syntax.Perl)
	if err != nil {
		return nil
	}
	anchors := requiredLiteralAnchors(re)
	if preferLeading {
		if leading, _ := leadingLiteralAnchors(re); betterAnchorSet(leading, anchors) {
			anchors = leading
		}
	}
	if len(anchors) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(anchors))
	result := make([]string, 0, len(anchors))
	for _, anchor := range anchors {
		anchor = strings.ToLower(anchor)
		if len(anchor) < minPreFilterAnchorLength || !isASCIIString(anchor) {
			return nil
		}
		if _, ok := seen[anchor]; ok {
			continue
		}
		seen[anchor] = struct{}{}
		result = append(result, anchor)
	}
	sort.Strings(result)
	return result
}

// leadingLiteralAnchors enumerates a bounded set of literal starts. The bool
// reports whether the expression is fully literal and callers may continue
// concatenating the next expression. A false bool can still carry valid
// prefixes collected before the first variable-width construct.
func leadingLiteralAnchors(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary,
		syntax.OpNoWordBoundary:
		return []string{""}, true
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return []string{""}, true
		}
		return []string{string(re.Rune)}, true
	case syntax.OpCharClass:
		return smallCharClassAlternatives(re.Rune)
	case syntax.OpCapture:
		if len(re.Sub) != 1 {
			return nil, false
		}
		return leadingLiteralAnchors(re.Sub[0])
	case syntax.OpConcat:
		prefixes := []string{""}
		for _, sub := range re.Sub {
			parts, complete := leadingLiteralAnchors(sub)
			if len(parts) == 0 {
				return allNonEmptyStrings(prefixes), false
			}
			prefixes = combineLiteralAlternatives(prefixes, parts)
			if len(prefixes) == 0 {
				return nil, false
			}
			if !complete {
				return allNonEmptyStrings(prefixes), false
			}
		}
		return allNonEmptyStrings(prefixes), true
	case syntax.OpAlternate:
		var combined []string
		complete := true
		for _, sub := range re.Sub {
			parts, branchComplete := leadingLiteralAnchors(sub)
			if len(parts) == 0 {
				return nil, false
			}
			combined = append(combined, parts...)
			complete = complete && branchComplete
		}
		return combined, complete
	case syntax.OpPlus:
		if len(re.Sub) != 1 {
			return nil, false
		}
		parts, _ := leadingLiteralAnchors(re.Sub[0])
		return parts, false
	case syntax.OpRepeat:
		if re.Min == 0 || len(re.Sub) != 1 {
			return nil, false
		}
		parts, complete := leadingLiteralAnchors(re.Sub[0])
		if len(parts) == 0 {
			return nil, false
		}
		if re.Min != re.Max || !complete {
			return parts, false
		}
		result := []string{""}
		for range re.Min {
			result = combineLiteralAlternatives(result, parts)
			if len(result) == 0 {
				return nil, false
			}
		}
		return result, true
	default:
		return nil, false
	}
}

func smallCharClassAlternatives(ranges []rune) ([]string, bool) {
	const maxAlternatives = 8
	var result []string
	for i := 0; i+1 < len(ranges); i += 2 {
		for r := ranges[i]; r <= ranges[i+1]; r++ {
			if len(result) == maxAlternatives {
				return nil, false
			}
			result = append(result, string(r))
			if r == ranges[i+1] {
				break
			}
		}
	}
	return result, len(result) > 0
}

func combineLiteralAlternatives(left, right []string) []string {
	const maxAlternatives = 64
	if len(left) == 0 || len(right) == 0 || len(left) > maxAlternatives/len(right) {
		return nil
	}
	result := make([]string, 0, len(left)*len(right))
	for _, prefix := range left {
		for _, suffix := range right {
			result = append(result, prefix+suffix)
		}
	}
	return result
}

func allNonEmptyStrings(values []string) []string {
	for _, value := range values {
		if value == "" {
			return nil
		}
	}
	return values
}

func isASCIIString(value string) bool {
	for i := range len(value) {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

// Generic credential-field words are common in benign URLs. They are safe as
// gates but not selective enough to pay for candidate-slice allocation on the
// query reconstruction hot path, so those patterns remain in alwaysRun.
func isGenericCredentialAnchorSet(anchors []string) bool {
	if len(anchors) == 0 {
		return false
	}
	for _, anchor := range anchors {
		switch anchor {
		case "api", "key", "passw", "password", "secret", "token":
		default:
			return false
		}
	}
	return true
}

// requiredLiteralAnchors finds one conservative required-literal set for re.
// For concatenation, any mandatory child can prove the gate; prefer the set
// with the longest shortest anchor. For alternation, every branch must prove an
// anchor, because a missing branch would turn the optimization into a bypass.
func requiredLiteralAnchors(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return nil
		}
		return []string{string(re.Rune)}
	case syntax.OpCapture:
		if len(re.Sub) != 1 {
			return nil
		}
		return requiredLiteralAnchors(re.Sub[0])
	case syntax.OpConcat:
		var best []string
		for _, sub := range re.Sub {
			candidate := requiredLiteralAnchors(sub)
			if betterAnchorSet(candidate, best) {
				best = candidate
			}
		}
		return best
	case syntax.OpAlternate:
		var combined []string
		for _, sub := range re.Sub {
			candidate := requiredLiteralAnchors(sub)
			if len(candidate) == 0 {
				return nil
			}
			combined = append(combined, candidate...)
		}
		return combined
	case syntax.OpPlus:
		if len(re.Sub) != 1 {
			return nil
		}
		return requiredLiteralAnchors(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min == 0 || len(re.Sub) != 1 {
			return nil
		}
		return requiredLiteralAnchors(re.Sub[0])
	default:
		return nil
	}
}

func betterAnchorSet(candidate, current []string) bool {
	if len(candidate) == 0 {
		return false
	}
	if len(current) == 0 {
		return true
	}
	return shortestStringLength(candidate) > shortestStringLength(current)
}

func shortestStringLength(values []string) int {
	shortest := -1
	for _, value := range values {
		if shortest < 0 || len(value) < shortest {
			shortest = len(value)
		}
	}
	if shortest < 0 {
		return 0
	}
	return shortest
}

// candidates returns the pattern indices that might match the given text.
// The text should already be normalized (normalize.ForDLP) before calling.
// Returns nil if no candidates are found (callers should still run alwaysRun).
func (pf *dlpPreFilter) candidates(text string) []int {
	if len(pf.prefixes) == 0 {
		return nil
	}
	var lowered dlpLoweredBytes
	lowered.add(text)
	return pf.candidatesWith(text, &lowered)
}

// dlpLoweredBytes records which bytes and adjacent byte pairs (see
// bytePairFilter) the bytes strings.ToLower(text) produces contain, without
// building that string. One record serves every prefilter scanning the text.
type dlpLoweredBytes struct {
	present [4]uint64
	pairs   bytePairFilter
}

func (l *dlpLoweredBytes) add(text string) {
	var prev byte
	first := true
	for i := 0; i < len(text); {
		c := text[i]
		if c < utf8.RuneSelf {
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			l.present[c/64] |= uint64(1) << (c % 64)
			if !first {
				idx := bytePairIndex(prev, c)
				l.pairs[idx>>6] |= 1 << (idx & 63)
			}
			prev, first = c, false
			i++
			continue
		}
		// strings.ToLower maps each rune with unicode.ToLower and writes a
		// malformed byte as U+FFFD; DecodeRuneInString yields that rune.
		r, size := utf8.DecodeRuneInString(text[i:])
		var buf [utf8.UTFMax]byte
		var lowered []byte
		if r == utf8.RuneError && size == 1 {
			// unicode.ToLower(U+FFFD) is U+FFFD; skip the lookup.
			lowered = append(buf[:0], "\uFFFD"...)
		} else {
			lowered = buf[:utf8.EncodeRune(buf[:], unicode.ToLower(r))]
		}
		for _, b := range lowered {
			l.present[b/64] |= uint64(1) << (b % 64)
			if !first {
				idx := bytePairIndex(prev, b)
				l.pairs[idx>>6] |= 1 << (idx & 63)
			}
			prev, first = b, false
		}
		i += size
	}
}

// candidatesWith is candidates for a text whose lowered bytes are recorded.
// The record is only a necessary condition: every surviving prefix still goes
// through the same complete substring check of strings.ToLower(text), which
// is built only when some prefix survives.
func (pf *dlpPreFilter) candidatesWith(text string, lowered *dlpLoweredBytes) []int {
	var lower string
	var hits []int
	for _, prefix := range pf.prefixes {
		first := prefix.text[0]
		if lowered.present[first/64]&(uint64(1)<<(first%64)) == 0 {
			continue
		}
		if !lowered.pairs.mayContain(prefix.pairs) {
			continue
		}
		if lower == "" {
			lower = strings.ToLower(text)
		}
		if strings.Contains(lower, prefix.text) {
			hits = append(hits, prefix.indices...)
		}
	}
	return hits
}

// patternsToCheck returns the combined set of pattern indices that should be
// evaluated against the given text: prefix-matched candidates plus alwaysRun.
// Returns nil only when both candidates and alwaysRun are empty.
// Indices are returned in ascending order for deterministic match reporting.
func (pf *dlpPreFilter) patternsToCheck(text string) []int {
	if !pf.admitsLength(text) {
		return nil
	}
	return pf.mergeAlwaysRun(pf.candidates(text))
}

// patternsToCheckWith is patternsToCheck for a text whose lowered bytes are
// already recorded.
func (pf *dlpPreFilter) patternsToCheckWith(text string, lowered *dlpLoweredBytes) []int {
	if !pf.admitsLength(text) {
		return nil
	}
	if len(pf.prefixes) == 0 {
		return pf.mergeAlwaysRun(nil)
	}
	return pf.mergeAlwaysRun(pf.candidatesWith(text, lowered))
}

func (pf *dlpPreFilter) mergeAlwaysRun(hits []int) []int {
	if len(hits) == 0 {
		if len(pf.alwaysRun) == 0 {
			return nil
		}
		return pf.alwaysRun
	}
	result := append(hits, pf.alwaysRun...)
	sort.Ints(result)
	unique := result[:1]
	for _, idx := range result[1:] {
		if idx != unique[len(unique)-1] {
			unique = append(unique, idx)
		}
	}
	return unique
}

// A regexp match consumes at least shapeMinLen runes. Boundary variants can
// remove a consumed left delimiter, so they participate in the same minimum.
func patternMinimumRunes(p *compiledPattern) int {
	minimum := 0
	for id, re := range []*regexp.Regexp{p.re, p.withoutLeftBoundary} {
		if re == nil {
			continue
		}
		tree, err := syntax.Parse(re.String(), syntax.Perl)
		if err != nil {
			return 0
		}
		n := shapeMinLen(tree)
		if id == 0 || n < minimum {
			minimum = n
		}
	}
	return minimum
}

func (pf *dlpPreFilter) admitsLength(text string) bool {
	return pf.minimumRunes <= 0 || utf8.RuneCountInString(text) >= pf.minimumRunes
}

// ForDLP leaves ASCII unchanged or deletes controls, and repairs each malformed
// UTF-8 byte to one U+FFFD (normalizeSegmented). Neither path expands rune
// count. Valid non-ASCII must keep the full path: NFKC can expand a ligature
// into several runes. This only declines pure matching, never graph observation.
func (pf *dlpPreFilter) rejectsUnnormalizedLength(text string) bool {
	if len(text) >= pf.minimumRunes {
		return false
	}
	for at := 0; at < len(text); at++ {
		if text[at] < utf8.RuneSelf {
			continue
		}
		if _, size := utf8.DecodeRuneInString(text[at:]); size > 1 {
			return false
		}
	}
	return true
}
