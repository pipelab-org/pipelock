// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// rawQuerySecurityPairs splits before decoding. Escaped separators remain
// value data, while literal ampersands and semicolons delimit recoverable pairs.
// Unlike ParseQuery, malformed percent escapes cannot remove a pair.
type rawQuerySecurityPair struct {
	key, value string
	hasValue   bool
}

func rawQuerySecurityPairs(query string) []rawQuerySecurityPair {
	var values []rawQuerySecurityPair
	for _, pair := range strings.FieldsFunc(query, func(r rune) bool { return r == '&' || r == ';' }) {
		key, value, hasValue := strings.Cut(pair, "=")
		values = append(values, rawQuerySecurityPair{key: key, value: value, hasValue: hasValue})
	}
	return values
}

// decodedKnownSecretViews shares the bounded candidate graph used for pattern
// DLP. Matching encoded representations alone misses secrets inside a carrier.
func (s *Scanner) decodedKnownSecretViews(text string, decodes *decodingMemo) []spanTextView {
	// A root's decode run lives only for this call: the tag views below read
	// the run add(text) holds. Later checks recompute through the memo, whose
	// retained bytes stay charged, rather than holding graphs across checks.
	var views []spanTextView
	// The value records pattern coverage from a completed continuation. A
	// known-only view from an ordinary walk is seen but not yet inspected.
	seen := make(map[string]bool)
	minimum := min(minKnownSecretSubstringLen, s.minEnvSecretLen)
	// The root's tag views below repeat the root decode add(text) made.
	var rootRun decodedRun
	add := func(value string, root bool) {
		// Decoding cannot grow a candidate; shorter input cannot contain a
		// whole configured secret or an eligible partial-secret window.
		if len(value) < minimum {
			return
		}
		// Complete decodes come from the graph pattern DLP shares, under its
		// own byte budget. Recovered prefixes walk a separate graph and may
		// use the completed base walk's unused candidate slots.
		var baseRun *decodedRun
		if root {
			baseRun = &rootRun
		}
		base := decodes.decodeRun(value, true, 0, 0, baseRun)
		for _, decoded := range base {
			if decoded.encoding == encodingUnicodeTags {
				decoded.text = decodes.normalize(decoded.text)
			}
			if _, exists := seen[decoded.text]; !exists {
				seen[decoded.text] = false
			}
			views = append(views, spanTextView{text: decoded.text, viewLabel: dlpViewLabel(decoded.encoding)})
		}
		var knownRun decodedRun
		for _, decoded := range decodes.decodeKnownSecretRun(value, minimum, base, &knownRun) {
			covered, exists := seen[decoded.text]
			if knownRun.resumed && knownRun.complete && !covered {
				s.noteKnownPrefixPattern(decodes, decoded)
				covered = true
			}
			seen[decoded.text] = covered
			if exists {
				continue
			}
			views = append(views, spanTextView{text: decoded.text, viewLabel: dlpViewLabel(decoded.encoding)})
		}
	}
	add(text, true)
	for _, decoded := range decodes.decodeAgain(text, rootRun) {
		if decoded.encoding == encodingUnicodeTags {
			for _, segment := range textDLPSegments(decodes.normalize(decoded.text)) {
				add(segment, false)
			}
		}
	}
	for _, segment := range textDLPSegments(text) {
		if segment != text {
			add(segment, false)
		}
	}
	return views
}

// noteKnownPrefixPattern runs the ordinary pattern matchers on a completed
// continuation's views. A view seen in an earlier known-prefix walk may not
// have had pattern coverage, and the continuation no longer leaves a refusal.
func (s *Scanner) noteKnownPrefixPattern(decodes *decodingMemo, view decodedResult) {
	if s == nil || decodes == nil || decodes.inbound || decodes.stopRequested() {
		return
	}
	patterns := textDLPAllPatterns
	if decodes.reassemblyPatternSelected {
		patterns = decodes.reassemblyPatterns
	}
	var run normalizationRun
	found := decodes.matchDecodedKeyWithNormalization(decodedMatchKey{scanner: s, text: view.text, encoding: view.encoding, core: true}, &run)
	found = append(found, decodes.matchDecodedForWithNormalization(s, view.text, view.encoding, patterns, &run)...)
	if len(found) == 0 {
		return
	}
	decodes.knownPrefixFindings = append(decodes.knownPrefixFindings, found...)
}

// knownSecretRoots are the texts one known-secret check builds decoded views
// for. Each is a pure function of the checked text.
type knownSecretRoots struct {
	original, decoded, percent string
}

func newKnownSecretRoots(original string) knownSecretRoots {
	text := normalize.ForDLP(original)
	return knownSecretRoots{original: original, decoded: IterativeDecode(text), percent: iterativePercentDecode(text)}
}

// The fixpoint graph already provides encoding layers as separate views. Only
// plaintext and partial-secret matching remain; re-encoding every secret for
// every decoded view repeats work without adding a security view.
func matchDecodedKnownSecret(secret string, windows knownValueWindowIndex, views []spanTextView, hits *knownValueWindowHits) (knownSecretMatch, int, int, string, bool) {
	if start, end, label, ok := indexAnyView(secret, views); ok {
		return knownSecretMatch{encoding: strings.TrimPrefix(label, ViewDLPNormalized+":")}, start, end, label, true
	}
	if start, end, length, label, ok := indexKnownValueSubstringWithHits(secret, windows, views, hits); ok {
		return knownSecretMatch{encoding: strings.TrimPrefix(label, ViewDLPNormalized+":"), partialLen: length}, start, end, label, true
	}
	return knownSecretMatch{}, 0, 0, "", false
}

// queryDLPSecurityViews lets exemptions inspect the same raw components and
// decoding targets as query DLP. Trust validation remains separate and strict.
func queryDLPSecurityViews(rawQuery string) []string {
	var views []string
	for _, pair := range rawQuerySecurityPairs(rawQuery) {
		for _, raw := range []string{pair.key, pair.value} {
			once := normalize.QueryUnescapePartial(raw)
			decoded := IterativeDecode(raw)
			views = append(views, raw, once, decoded, stripURLNoise(decoded))
			for _, candidate := range queryValueDecodedTargets(once) {
				views = append(views, candidate.text)
			}
			for _, candidate := range queryValueDecodedTargets(decoded) {
				views = append(views, candidate.text)
			}
			if raw != decoded {
				for _, candidate := range queryValueDecodedTargets(raw) {
					views = append(views, candidate.text)
				}
			}
		}
	}
	return views
}

// relabelKnownSecretViews names the text a set of decoded views came from, so
// a span's label identifies the string its offsets index.
func relabelKnownSecretViews(views []spanTextView, source string) []spanTextView {
	for i := range views {
		views[i].viewLabel = spanViewLabel(ViewDLPNormalized, source, strings.TrimPrefix(views[i].viewLabel, ViewDLPNormalized+":"))
	}
	return views
}
