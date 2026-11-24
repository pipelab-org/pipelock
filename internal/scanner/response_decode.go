// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "github.com/luckyPipewrench/pipelock/internal/normalize"

// responseDecodeMemo belongs to one decoded matching pass. It preserves the
// depth-first traversal and its source projections, but shares codec results
// and proven empty subtrees reached through multiple codecs or source runs.
// No finding or filtered finding is cached: suppression and observe evidence
// must still be produced in the original order. All keys compare exact bytes.
// It does not own or change the text-DLP inspection budgets.
type responseDecodeMemo struct {
	scanner         *Scanner
	core            bool
	suppress        coreResponseSuppressor
	evidence        int
	carriers        responseCarrierDecoder
	emptyTrees      map[responseDecodeVisit]struct{}
	emptyNormalized map[string]struct{}
	visitDecoded    func(string, string) bool
	stopVisiting    bool
}

type responseDecodeVisit struct {
	content   string
	depth     int
	recoverQP bool
}

func newResponseDecodeMemo(s *Scanner, core bool, suppress coreResponseSuppressor) *responseDecodeMemo {
	m := &responseDecodeMemo{scanner: s, core: core, carriers: responseCarrierDecoder{memo: make(map[responseDecodeKey]string)}, emptyTrees: make(map[responseDecodeVisit]struct{}), emptyNormalized: make(map[string]struct{})}
	m.suppress = func(matches []ResponseMatch) []ResponseMatch {
		if len(matches) > 0 {
			m.evidence++
		}
		if suppress != nil {
			return suppress(matches)
		}
		return matches
	}
	return m
}

func (m *responseDecodeMemo) normalized(content, label string) responseMatchSet {
	if _, ok := m.emptyNormalized[content]; ok {
		return responseMatchSet{}
	}
	if m.visitDecoded != nil {
		m.stopVisiting = !m.visitDecoded(content, label)
		m.emptyNormalized[content] = struct{}{}
		return responseMatchSet{}
	}
	before := m.evidence
	var set responseMatchSet
	if m.core {
		set = m.scanner.matchDecodedCoreNormalized(content, label, m.suppress)
	} else {
		set = m.scanner.matchDecodedNormalized(content, label, m.suppress)
	}
	if len(set.matches) == 0 && before == m.evidence {
		m.emptyNormalized[content] = struct{}{}
	}
	return set
}

func (m *responseDecodeMemo) recursiveMode(content string, depth int, recoverQP bool) (out responseMatchSet) {
	if depth >= responseDecodeMaxDepth || m.stopVisiting {
		return responseMatchSet{}
	}
	key := responseDecodeVisit{content: content, depth: depth, recoverQP: recoverQP}
	if _, ok := m.emptyTrees[key]; ok {
		return responseMatchSet{}
	}
	before := m.evidence
	defer func() {
		if len(out.matches) == 0 && before == m.evidence {
			m.emptyTrees[key] = struct{}{}
		}
	}()
	if decoded, ok := responseDecodeTagView(content); ok {
		if found := m.normalized(decoded, ViewUnicodeTagsDecoded); len(found.matches) > 0 {
			return mapResponseTransformSources(found, content, ViewUnicodeTagsDecoded)
		}
		if m.stopVisiting {
			return responseMatchSet{}
		}
		if found := m.recursiveMode(normalize.ForMatching(decoded), depth+1, true); len(found.matches) > 0 {
			return mapResponseTransformSources(found, content, ViewUnicodeTagsDecoded)
		}
	}
	if m.stopVisiting {
		return responseMatchSet{}
	}
	if normalize.ContainsTags(content) {
		if stripped, ok := responseDecodeQuotedPrintableSource(content); ok {
			if found := m.recursiveMode(stripped, depth+1, recoverQP); len(found.matches) > 0 {
				return mapResponseStrippedSources(found, content)
			}
		}
		if m.stopVisiting {
			return responseMatchSet{}
		}
		source := content
		content = normalize.ForMatching(content)
		defer func() { out = mapResponseTransformSources(out, source, ViewForMatching) }()
	}

	views := textEncodingViewsMode(content, recoverQP)
	for _, view := range views {
		if set := m.normalized(view.text, spanViewLabel(ViewForMatching, view.encoding+"_decoded")); len(set.matches) > 0 {
			set = mapTextEncodingViewSources(set, content, view)
			if len(set.matches) > 0 {
				return set
			}
		}
		if m.stopVisiting {
			return responseMatchSet{}
		}
		if set := m.recursiveMode(view.text, depth+1, true); len(set.matches) > 0 {
			set = mapTextEncodingViewSources(set, content, view)
			if len(set.matches) > 0 {
				return set
			}
		}
		if m.stopVisiting {
			return responseMatchSet{}
		}
	}

	var decodedSet responseMatchSet
	m.carriers.visitBase64HexCarriers(content, printableResponseCarrierText, nil, func(carrier responseDecodedCarrier) bool {
		label := ViewBase64Decoded
		if carrier.hex {
			label = ViewHexDecoded
		}
		found := m.normalized(carrier.text, label)
		if m.stopVisiting {
			return false
		}
		if len(found.matches) == 0 {
			// Recurse on every admitted decode. The depth limit bounds
			// punctuated or split carriers in the next layer.
			found = m.recursiveMode(carrier.text, depth+1, true)
			if len(found.matches) == 0 {
				return !m.stopVisiting
			}
		}
		decodedSet = mapResponseDecodeFinding(found, carrier.text, carrier.source.text, carrier.source.start, carrier.hex)
		return false
	})
	return decodedSet
}

// Source offsets are needed only for findings, not for empty decode attempts.
func mapResponseDecodeFinding(set responseMatchSet, decoded, source string, offset int, hexEncoded bool) responseMatchSet {
	_, offsets := stripDecodeWhitespace(source, offset)
	return mapDecodedSources(set, decoded, offsets, hexEncoded)
}
