// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

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
	decoded         map[responseDecodeKey]string
	emptyTrees      map[responseDecodeVisit]struct{}
	emptyNormalized map[string]struct{}
}

type responseDecodeKey struct {
	content  string
	encoding *base64.Encoding
}
type responseDecodeVisit struct {
	content   string
	depth     int
	recoverQP bool
}

func newResponseDecodeMemo(s *Scanner, core bool, suppress coreResponseSuppressor) *responseDecodeMemo {
	m := &responseDecodeMemo{scanner: s, core: core, decoded: make(map[responseDecodeKey]string), emptyTrees: make(map[responseDecodeVisit]struct{}), emptyNormalized: make(map[string]struct{})}
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

func (m *responseDecodeMemo) decode(content string, encoding *base64.Encoding) string {
	key := responseDecodeKey{content, encoding}
	if text, ok := m.decoded[key]; ok {
		return text
	}
	var decoded []byte
	var err error
	if encoding == nil {
		decoded, err = hex.DecodeString(content)
	} else {
		decoded, err = encoding.DecodeString(content)
	}
	text := ""
	if err == nil {
		text = string(decoded)
	}
	m.decoded[key] = text
	return text
}

func (m *responseDecodeMemo) normalized(content, label string) responseMatchSet {
	if _, ok := m.emptyNormalized[content]; ok {
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
	if depth >= responseDecodeMaxDepth {
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
	if decoded := normalize.DecodeTags(content); decoded != content {
		if found := m.normalized(decoded, ViewUnicodeTagsDecoded); len(found.matches) > 0 {
			return mapResponseTransformSources(found, content, ViewUnicodeTagsDecoded)
		}
		if found := m.recursiveMode(normalize.ForMatching(decoded), depth+1, true); len(found.matches) > 0 {
			return mapResponseTransformSources(found, content, ViewUnicodeTagsDecoded)
		}
	}
	if normalize.ContainsTags(content) {
		if stripped := normalize.StripZeroWidth(content); hasQuotedPrintable(stripped) {
			if found := m.recursiveMode(stripped, depth+1, recoverQP); len(found.matches) > 0 {
				return mapResponseStrippedSources(found, content)
			}
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
		if set := m.recursiveMode(view.text, depth+1, true); len(set.matches) > 0 {
			set = mapTextEncodingViewSources(set, content, view)
			if len(set.matches) > 0 {
				return set
			}
		}
	}

	// Strategy 1: whole-content decode.
	stripped := canonicalMixedBase64(stripResponseDecodeWhitespace(content))

	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if d := m.decode(stripped, enc); d != "" {
			if decodedSet := m.normalized(d, ViewBase64Decoded); len(decodedSet.matches) > 0 {
				return mapResponseDecodeFinding(decodedSet, d, content, 0, false)
			}
			// Always recurse on successful decode. The depth limit is the
			// safety bound; gating on hasEncodedRun lets attackers bypass
			// by splitting or punctuating the inner encoded layer.
			if decodedSet := m.recursiveMode(d, depth+1, true); len(decodedSet.matches) > 0 {
				return mapResponseDecodeFinding(decodedSet, d, content, 0, false)
			}
		}
	}
	if d := m.decode(stripped, nil); d != "" {
		if decodedSet := m.normalized(d, ViewHexDecoded); len(decodedSet.matches) > 0 {
			return mapResponseDecodeFinding(decodedSet, d, content, 0, true)
		}
		if decodedSet := m.recursiveMode(d, depth+1, true); len(decodedSet.matches) > 0 {
			return mapResponseDecodeFinding(decodedSet, d, content, 0, true)
		}
	}

	// Strategy 2: segment-level decode with recursion.
	if decodedSet := m.segments(content, depth); len(decodedSet.matches) > 0 {
		return decodedSet
	}

	return responseMatchSet{}
}

// segments extracts contiguous base64-alphabet runs from
// content, decodes each individually, and checks for injection patterns.
// Recurses on decoded segments to catch multi-layer encoding.
func (m *responseDecodeMemo) segments(content string, depth int) responseMatchSet {
	if depth >= responseDecodeMaxDepth {
		return responseMatchSet{}
	}
	segments := extractEncodedRunSpans(content, minSegmentDecodeLen)
	for _, seg := range segments {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.URLEncoding,
			base64.RawStdEncoding, base64.RawURLEncoding,
		} {
			if d := m.decode(canonicalMixedBase64(seg.text), enc); d != "" && isPrintableText([]byte(d)) {
				if decodedSet := m.normalized(d, ViewBase64Decoded); len(decodedSet.matches) > 0 {
					return mapResponseDecodeFinding(decodedSet, d, seg.text, seg.start, false)
				}
				if decodedSet := m.recursiveMode(d, depth+1, true); len(decodedSet.matches) > 0 {
					return mapResponseDecodeFinding(decodedSet, d, seg.text, seg.start, false)
				}
			}
		}
		if d := m.decode(seg.text, nil); d != "" && isPrintableText([]byte(d)) {
			if decodedSet := m.normalized(d, ViewHexDecoded); len(decodedSet.matches) > 0 {
				return mapResponseDecodeFinding(decodedSet, d, seg.text, seg.start, true)
			}
			if decodedSet := m.recursiveMode(d, depth+1, true); len(decodedSet.matches) > 0 {
				return mapResponseDecodeFinding(decodedSet, d, seg.text, seg.start, true)
			}
		}
	}
	return responseMatchSet{}
}

// Source offsets are needed only for findings, not for empty decode attempts.
func mapResponseDecodeFinding(set responseMatchSet, decoded, source string, offset int, hexEncoded bool) responseMatchSet {
	_, offsets := stripDecodeWhitespace(source, offset)
	return mapDecodedSources(set, decoded, offsets, hexEncoded)
}

func stripResponseDecodeWhitespace(content string) string {
	if !strings.ContainsAny(content, " \n\r\t") {
		return content
	}
	var stripped strings.Builder
	stripped.Grow(len(content))
	for i := 0; i < len(content); i++ {
		switch content[i] {
		case ' ', '\n', '\r', '\t':
			continue
		default:
			stripped.WriteByte(content[i])
		}
	}
	return stripped.String()
}
