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
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			bodyLoc := p.withoutLeftBoundary.FindStringIndex(text[loc[0]:loc[1]])
			if bodyLoc == nil {
				continue
			}
			start = loc[0] + bodyLoc[0]
			end = loc[0] + bodyLoc[1]
			if p.accepts(text, start, end) {
				return start, end, true
			}
		}
		return 0, 0, false
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
		if p.accepts(text, start, end) {
			return start, end, true
		}
	}
	return 0, 0, false
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
		candidates = append(candidates, strings.ToLower(source[loc[0]:loc[1]]))
	}
	return candidates
}

// providerCandidateSpans includes nested provider prefixes. The suffix regex is
// greedy, so FindAllStringIndex would let a suppressed prose candidate consume
// a later reconstructed key and mask it from enforcement.
func (p *compiledPattern) providerCandidateSpans(text string) [][2]int {
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
