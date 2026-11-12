// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// View labels name the exact scanner view that byte offsets index. Labels use
// a transform-stack scheme: "<stage>" or "<stage>:<provenance>". Consumers must
// slice the named view, not the raw input that produced it.
const (
	ViewForMatching        = "for_matching"
	ViewInvisibleSpaced    = "for_matching:invisible_spaced"
	ViewLeetspeak          = "leetspeak:for_matching"
	ViewVowelFold          = "vowel_fold:for_matching"
	ViewBase64Decoded      = "for_matching:base64_decoded"
	ViewHexDecoded         = "for_matching:hex_decoded"
	ViewUnicodeTagsDecoded = "for_matching:unicode_tags_decoded"
	ViewDLPNormalized      = "dlp_normalized"
)

// MatchSpan is retained scanner evidence metadata for a pattern match.
// It carries coordinates and provenance only; it never carries matched bytes.
type MatchSpan struct {
	ByteStart     int
	ByteEnd       int
	ViewLabel     string
	RuleID        string
	Bundle        string
	BundleVersion string
}

func newMatchSpan(start, end int, viewLabel, ruleID, bundle, bundleVersion string) MatchSpan {
	if start < 0 || end < start || viewLabel == "" || ruleID == "" {
		return MatchSpan{}
	}
	return MatchSpan{
		ByteStart:     start,
		ByteEnd:       end,
		ViewLabel:     viewLabel,
		RuleID:        ruleID,
		Bundle:        bundle,
		BundleVersion: bundleVersion,
	}
}

// Valid reports whether the span has coordinates, a view label, and rule ID.
func (s MatchSpan) Valid() bool {
	return s.ByteStart >= 0 && s.ByteEnd >= s.ByteStart && s.ViewLabel != "" && s.RuleID != ""
}

func dlpEncodedViewLabel(encoding string) string {
	return dlpViewLabel(encoding)
}

func dlpViewLabel(provenance string) string {
	return spanViewLabel(ViewDLPNormalized, provenance)
}

func lowerViewLabel(base string) string {
	return spanViewLabel("lowercase", base)
}

func canonicalLowerViewLabel(base string) string {
	return spanViewLabel("canonicalized", lowerViewLabel(base))
}

func vowelFoldViewLabel(base string) string {
	return spanViewLabel("vowel_fold", base)
}

func spanViewLabel(stage string, provenance ...string) string {
	label := stage
	for _, p := range provenance {
		if p == "" {
			continue
		}
		label += ":" + p
	}
	return label
}

func copySpans(spans []MatchSpan) []MatchSpan {
	if len(spans) == 0 {
		return nil
	}
	out := make([]MatchSpan, len(spans))
	copy(out, spans)
	return out
}

func (p *compiledPattern) matchSpan(text string) (start, end int, ok bool) {
	return p.matchSpanInView(text, text)
}

// admitsView applies the compiled pattern's necessary conditions to an exact
// view. Both ordinary matching and decoded-lane matching use the same gates.
func (p *compiledPattern) admitsView(text string) bool {
	if p.requiresEquals && strings.IndexByte(text, '=') < 0 {
		return false
	}
	if p.minASCIIDigits > 0 && !hasMinimumASCIIDigits(text, p.minASCIIDigits) {
		return false
	}
	return p.shapeGate.admits(text)
}

// matchSpanInView returns the credential span rather than a raw-text delimiter
// consumed by an RE2-compatible left-boundary expression. source is the view
// before separators were removed or fields were concatenated. A mid-word
// candidate is suppressed only when that same candidate genuinely existed
// mid-word in source; otherwise the scanner manufactured the adjacency.
func (p *compiledPattern) matchSpanInView(text, source string) (start, end int, ok bool) {
	if p.keywords != nil && p.keywordContext == nil {
		pattern := *p
		logical := config.DLPKeywordContext(source)
		pattern.keywordContext = &keywordCandidateContext{logical: logical}
		return pattern.matchSpanInView(text, source)
	}
	if !p.admitsView(text) {
		return 0, 0, false
	}
	if p.withoutLeftBoundary == nil {
		return p.firstAcceptedSpan(text, nil)
	}
	if source == text {
		return p.firstBoundaryOrGluedSpan(text)
	}
	// Word-boundary families stay on the bounded grammar in a transformed
	// view. A one-character exception applies only when that same candidate
	// is already a one-character disguise in the source. Whitespace removal
	// can glue a date to a clock (2026-12-30 23:59:59) and manufacture an
	// SSN-shaped run; the source still has the space, so it is not confirmed.
	if p.providerPrefixRE == nil {
		return p.firstJoinedGluedSpan(text, source)
	}

	invalidSourceCandidates := p.invalidLeadingCandidates(source)
	invalidIndex := 0
	for _, loc := range p.providerCandidateSpans(text) {
		start, end = loc[0], loc[1]
		candidate := strings.ToLower(text[start:end])
		if invalidIndex < len(invalidSourceCandidates) && sameProviderCandidate(candidate, invalidSourceCandidates[invalidIndex]) {
			invalidIndex++
			continue
		}
		start, end, ok = p.acceptedSpan(text, start, end)
		if ok {
			return start, end, true
		}
	}
	return 0, 0, false
}

// firstBoundaryOrGluedSpan returns the earliest bounded hit. A candidate the
// left boundary rejects is also returned when it starts strictly earlier,
// exactly one preceding rune is what failed the boundary, and the family
// strength check accepts it. A receiver that drops that rune sees the
// credential. PR #1391 prose such as "desk-ant-" still fails, because
// removing one rune leaves another boundary failure.
func (p *compiledPattern) firstBoundaryOrGluedSpan(text string) (int, int, bool) {
	start, end, ok := p.firstBoundedBodySpan(text)
	if !p.relaxSingleGluedBoundary || (ok && start == 0) {
		return start, end, ok
	}
	limit := len(text) + 1
	if ok {
		limit = start
	}
	if gStart, gEnd, gOK := p.earliestGluedSpan(text, limit); gOK {
		return gStart, gEnd, true
	}
	return start, end, ok
}

func (p *compiledPattern) firstBoundedBodySpan(text string) (int, int, bool) {
	for _, loc := range p.re.FindAllStringIndex(text, -1) {
		bodyLoc := p.withoutLeftBoundary.FindStringIndex(text[loc[0]:loc[1]])
		if bodyLoc == nil {
			continue
		}
		start, end, ok := p.acceptedSpan(text, loc[0]+bodyLoc[0], loc[0]+bodyLoc[1])
		if ok {
			return start, end, true
		}
	}
	return 0, 0, false
}

func (p *compiledPattern) firstJoinedGluedSpan(text, source string) (int, int, bool) {
	start, end, ok := p.firstBoundedBodySpan(text)
	if !p.relaxSingleGluedBoundary || (ok && start == 0) {
		return start, end, ok
	}
	// A digit glued to a card or SSN is rejected: it lengthens the number.
	// A digit-only view therefore has no glue rune this family can accept,
	// and a second body scan only repeats the bounded one. Dot-stripping a
	// long dotted integer list produces that view.
	if p.gluedDigitExtendsNumber && !textHasNonDigit(text) {
		return start, end, ok
	}
	limit := len(text) + 1
	if ok {
		limit = start
	}
	bestStart, bestEnd := limit, 0
	found := false
	for _, loc := range p.providerCandidateSpans(text) {
		if loc[0] >= bestStart {
			continue
		}
		gStart, gEnd, gOK := p.gluedCandidateSpan(text, loc)
		if !gOK || gStart >= bestStart || !p.gluedCandidateConfirmedInSource(source, text[gStart:gEnd]) {
			continue
		}
		bestStart, bestEnd, found = gStart, gEnd, true
	}
	if found {
		return bestStart, bestEnd, true
	}
	return start, end, ok
}

func textHasNonDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return true
		}
	}
	return false
}

func (p *compiledPattern) gluedCandidateConfirmedInSource(source, candidate string) bool {
	if candidate == "" || len(candidate) > len(source) {
		return false
	}
	from := 0
	for from <= len(source)-len(candidate) {
		i := strings.Index(source[from:], candidate)
		if i < 0 {
			return false
		}
		at := from + i
		loc := [2]int{at, at + len(candidate)}
		if p.candidateHasLeftBoundary(source, loc) {
			return true
		}
		glued, ok := p.exactlyOneGluedRune(source, loc)
		if ok && (!p.gluedDigitExtendsNumber || glued < '0' || glued > '9') {
			return true
		}
		from = at + 1
	}
	return false
}

func (p *compiledPattern) earliestGluedSpan(text string, limit int) (int, int, bool) {
	bestStart, bestEnd := limit, 0
	found := false
	for _, loc := range p.providerCandidateSpans(text) {
		if loc[0] >= bestStart {
			continue
		}
		start, end, ok := p.gluedCandidateSpan(text, loc)
		if !ok || start >= bestStart {
			continue
		}
		bestStart, bestEnd, found = start, end, true
	}
	return bestStart, bestEnd, found
}

func (p *compiledPattern) gluedCandidateSpan(text string, loc [2]int) (int, int, bool) {
	glued, ok := p.exactlyOneGluedRune(text, loc)
	if !ok {
		return 0, 0, false
	}
	if p.gluedDigitExtendsNumber && glued >= '0' && glued <= '9' {
		return 0, 0, false
	}
	start, end, ok := p.acceptedSpan(text, loc[0], loc[1])
	if !ok || start != loc[0] {
		return 0, 0, false
	}
	if p.providerKeyPrefix != "" && !providerSuffixHasKeyStrength(p.providerKeyPrefix, text[start:end]) {
		return 0, 0, false
	}
	return start, end, true
}

// exactlyOneGluedRune reports the single preceding rune whose removal makes
// candidateHasLeftBoundary true. Zero runes means the boundary already held.
// Two or more means the candidate is still inside a word after one deletion,
// which is the prose shape PR #1391 kept out of redaction and DLP.
func (p *compiledPattern) exactlyOneGluedRune(source string, loc [2]int) (rune, bool) {
	if loc[0] <= 0 || loc[1] > len(source) || loc[0] >= loc[1] || p.candidateHasLeftBoundary(source, loc) {
		return 0, false
	}
	r, size := utf8.DecodeLastRuneInString(source[:loc[0]])
	if r == utf8.RuneError && size == 1 {
		return 0, false
	}
	before := loc[0] - size
	var window string
	candidateStart := 0
	if before > 0 {
		_, prevSize := utf8.DecodeLastRuneInString(source[:before])
		window = source[before-prevSize:before] + source[loc[0]:loc[1]]
		candidateStart = prevSize
	} else {
		window = source[loc[0]:loc[1]]
	}
	if !p.candidateHasLeftBoundary(window, [2]int{candidateStart, len(window)}) {
		return 0, false
	}
	return r, true
}

// matchSpanInJoinedView is matchSpanInView for the whitespace-joined view,
// where offsets maps each joined byte to its offset in source. A pattern with a
// joined-view validator must also pass it; a rejected candidate never hides a
// later genuine one. Patterns without one behave exactly as in matchSpanInView.
func (p *compiledPattern) matchSpanInJoinedView(text, source string, offsets []int) (start, end int, ok bool) {
	if p.keywords != nil && p.keywordContext == nil {
		pattern := *p
		pattern.keywordContext = &keywordCandidateContext{logical: source, offsets: offsets}
		return pattern.matchSpanInJoinedView(text, source, offsets)
	}
	if p.validateJoined == nil || p.withoutLeftBoundary != nil {
		return p.matchSpanInView(text, source)
	}
	if p.requiresEquals && strings.IndexByte(text, '=') < 0 {
		return 0, 0, false
	}
	if p.minASCIIDigits > 0 && !hasMinimumASCIIDigits(text, p.minASCIIDigits) {
		return 0, 0, false
	}
	if !p.shapeGate.admits(text) {
		return 0, 0, false
	}
	return p.firstAcceptedSpan(text, func(start, end int) bool {
		return p.validateJoined(text, start, end, source, offsets)
	})
}

func sameProviderCandidate(candidate, sourceCandidate string) bool {
	// Concatenating another field can extend the provider pattern's greedy
	// suffix. Treat that as the same prose candidate when one string is the
	// other's prefix; unrelated candidates in the same source remain distinct.
	return strings.HasPrefix(candidate, sourceCandidate) || strings.HasPrefix(sourceCandidate, candidate)
}

func (p *compiledPattern) invalidLeadingCandidates(source string) []string {
	var candidates []string
	for _, loc := range p.providerCandidateSpans(source) {
		if p.candidateHasLeftBoundary(source, loc) {
			continue
		}
		// A one-character disguise that passes the strength check is a real
		// candidate. Leaving it in this list would suppress it again once a
		// normalized view no longer matches the source byte for byte.
		if p.relaxSingleGluedBoundary {
			if _, _, ok := p.gluedCandidateSpan(source, loc); ok {
				continue
			}
		}
		candidates = append(candidates, strings.ToLower(source[loc[0]:loc[1]]))
	}
	return candidates
}

// providerCandidateSpans includes nested provider prefixes. The suffix regex is
// greedy, so FindAllStringIndex would let a suppressed prose candidate consume
// a later reconstructed key and mask it from enforcement.
func (p *compiledPattern) providerCandidateSpans(text string) [][2]int {
	if p.providerPrefixRE == nil {
		locs := p.withoutLeftBoundary.FindAllStringIndex(text, -1)
		spans := make([][2]int, len(locs))
		for i, loc := range locs {
			spans[i] = [2]int{loc[0], loc[1]}
		}
		return spans
	}
	return p.canonicalProviderCandidateSpans(text)
}

// canonicalProviderCandidateSpans expands nested prefixes inside each greedy
// provider-key match without rerunning the regex over the remaining text. All
// three canonical bodies share the existing 20-character opaque-suffix minimum.
func (p *compiledPattern) canonicalProviderCandidateSpans(text string) [][2]int {
	outer := p.withoutLeftBoundary.FindAllStringIndex(text, -1)
	spans := make([][2]int, 0, len(outer))
	for _, loc := range outer {
		spans = append(spans, [2]int{loc[0], loc[1]})
		candidate := text[loc[0]:loc[1]]
		// Find prefix coordinates in the source. Unicode case mapping can change
		// byte widths even inside a case-insensitive ASCII letter expression.
		remaining := utf8.RuneCountInString(candidate)
		previousEnd := 0
		for _, prefix := range p.providerPrefixRE.FindAllStringIndex(candidate, -1) {
			remaining -= utf8.RuneCountInString(candidate[previousEnd:prefix[1]])
			previousEnd = prefix[1]
			if prefix[0] == 0 {
				continue
			}
			// The canonical provider bodies require at least 20 suffix characters.
			if remaining >= 20 {
				spans = append(spans, [2]int{loc[0] + prefix[0], loc[1]})
			}
		}
	}
	return spans
}

func (p *compiledPattern) candidateHasLeftBoundary(source string, candidateLoc [2]int) bool {
	windowStart := candidateLoc[0]
	if windowStart > 0 {
		_, size := utf8.DecodeLastRuneInString(source[:windowStart])
		windowStart -= size
	}
	window := source[windowStart:candidateLoc[1]]
	for _, loc := range p.re.FindAllStringIndex(window, -1) {
		bodyLoc := p.withoutLeftBoundary.FindStringIndex(window[loc[0]:loc[1]])
		if bodyLoc != nil && windowStart+loc[0]+bodyLoc[0] == candidateLoc[0] {
			return true
		}
	}
	return false
}

// firstAcceptedSpan preserves whole-match and boundary semantics for ordinary
// validators. The canonical WIF grammar has no boundaries, so a rejected greedy
// hit can hide a valid key that starts inside it; WIF candidates are therefore
// enumerated at every start rather than at the regex's non-overlapping hits.
func (p *compiledPattern) firstAcceptedSpan(text string, joined func(int, int) bool) (int, int, bool) {
	if !p.wifOverlapRetry {
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			start, end, ok := p.acceptedSpan(text, loc[0], loc[1])
			if ok && (joined == nil || joined(start, end)) {
				return start, end, true
			}
		}
		return 0, 0, false
	}
	return firstWIFCandidate(text, func(start, end int) bool {
		return p.accepts(text, start, end) && (joined == nil || joined(start, end))
	})
}

// firstWIFCandidate visits each canonical WIF start once in one pass over
// maximal base58 runs. A canonical candidate's width is fixed by its first
// byte (Bitcoin's mainnet WIF format: '5' then 50 base58 characters, or 'K'/'L'
// then 51), and validateWIF accepts only all-base58 input, so this yields every
// candidate the case-insensitive regex could have had accepted. Re-running the
// regex from each rejected start instead costs up to 52 regex steps per byte.
func firstWIFCandidate(text string, accept func(start, end int) bool) (int, int, bool) {
	// run checks every start in the base58 run text[runStart:runEnd].
	run := func(runStart, runEnd int) (int, int, bool) {
		for start := runStart; runEnd-start >= wifUncompressedLen; start++ {
			width := 0
			switch text[start] {
			case '5':
				width = wifUncompressedLen
			case 'K', 'L':
				width = wifCompressedLen
			}
			if width > 0 && start+width <= runEnd && accept(start, start+width) {
				return start, start + width, true
			}
		}
		return 0, 0, false
	}
	runStart := 0
	for i := range len(text) {
		if isBase58Byte(text[i]) {
			continue
		}
		if start, end, ok := run(runStart, i); ok {
			return start, end, true
		}
		runStart = i + 1
	}
	return run(runStart, len(text))
}
