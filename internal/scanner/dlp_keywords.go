// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"html"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

type keywordByteSpan struct{ start, end int }

const (
	keywordQueryValues = "query_values"
	// RFC 3986 percent decoding keeps plus signs as data (iterativePercentDecode).
	keywordURLPercent        = "url_percent"
	keywordPercentDrop       = "invalid_percent_drop"
	keywordPercentEscapeDrop = "invalid_percent_escape_drop"
	// A delimiter segment is a literal substring of its parent view.
	keywordSegment = "segment"
)

// keywordDecodeSources records edges of the existing decoder walk, only for
// scans with contextual rules. It neither adds views nor changes admission.
// It is scan-local: source-sensitive decisions never enter shared decode caches.
type keywordDecodeSources struct {
	root        string
	rootCharged bool
	nodes       map[string]*keywordDecodeSource
	budget      *keywordWorkBudget
	incomplete  bool
}

type keywordWorkBudget struct {
	sourceVersion uint64
	used          int
	nodes         int
	incomplete    bool
}

type keywordDecodeSource struct {
	reassembly         *assembledKeywordBits
	logicalVersion     uint64
	logicals           []string
	variants           []*keywordDecodeSource
	logicalReady       bool
	logicalUnavailable bool
	text, encoding     string
	parent             *keywordDecodeSource
	owner              *keywordDecodeSources
	offsets            []keywordByteSpan
	mapped             bool
}

func newKeywordDecodeSources(root string) *keywordDecodeSources {
	sources := &keywordDecodeSources{root: root, nodes: make(map[string]*keywordDecodeSource), budget: &keywordWorkBudget{}}
	sources.nodes[root] = &keywordDecodeSource{text: root, owner: sources}
	return sources
}

const keywordSpanBytes = 2 * (strconv.IntSize / 8)

// Account for the node and its string-key/pointer entry as well as mapping
// backing arrays. The inspection budget is the existing decoder byte bound.
var keywordNodeBytes = int(reflect.TypeFor[keywordDecodeSource]().Size() + reflect.TypeFor[string]().Size() + reflect.TypeFor[*keywordDecodeSource]().Size())

func (s *keywordDecodeSources) chargeNode() bool {
	if s.budget.nodes >= maxDecodeCandidates || !s.charge(keywordNodeBytes) {
		s.incomplete = true
		s.budget.incomplete = true
		return false
	}
	s.budget.nodes++
	return true
}

func (s *keywordDecodeSources) charge(n int) bool {
	if n > maxDecodeTotalBytes-s.budget.used {
		s.incomplete = true
		s.budget.incomplete = true
		return false
	}
	s.budget.used += n
	return true
}

func (s *keywordDecodeSources) add(parent, text, encoding string) *keywordDecodeSource {
	if !s.rootCharged {
		s.rootCharged = true
		if !s.chargeNode() {
			return nil
		}
	}
	p := s.nodes[parent]
	if p == nil {
		s.incomplete = true
		return nil
	}
	if node := s.nodes[text]; node != nil {
		if text == s.root || node == p || node.parent == p && node.encoding == encoding {
			return node
		}
		for _, variant := range node.variants {
			if variant.parent == p && variant.encoding == encoding {
				return node
			}
		}
		// A repeated decoder view can carry another source map. Keep its edge
		// without expanding the decode graph or adding another decoded view.
		if p.hasSourceAncestor(node) {
			return node
		}
		if !s.chargeNode() {
			return node
		}
		s.budget.sourceVersion++
		node.variants = append(node.variants, &keywordDecodeSource{text: text, encoding: encoding, parent: p, owner: s})
		return node
	}
	if !s.chargeNode() {
		return nil
	}
	node := &keywordDecodeSource{text: text, encoding: encoding, parent: p, owner: s}
	s.nodes[text] = node
	return node
}

func (n *keywordDecodeSource) hasSourceAncestor(target *keywordDecodeSource) bool {
	pending := []*keywordDecodeSource{n}
	seen := make(map[*keywordDecodeSource]bool)
	for len(pending) > 0 {
		next := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if next == target {
			return true
		}
		if next == nil || seen[next] {
			continue
		}
		seen[next] = true
		pending = append(pending, next.parent)
		pending = append(pending, next.variants...)
	}
	return false
}

// visitSources enumerates source hulls for every producing path. The existing
// decoded-view deduplication cannot turn a different source context into a
// cached negative keyword decision.
func (n *keywordDecodeSource) visitSources(start, end int, visit func(string, int, int) bool) bool {
	if n == nil || start < 0 || end <= start || end > len(n.text) {
		return false
	}
	if !n.owner.charge(keywordSpanBytes) {
		return false
	}
	if n.visitOneSource(start, end, visit) {
		return true
	}
	for _, variant := range n.variants {
		if variant.visitOneSource(start, end, visit) {
			return true
		}
	}
	return false
}

func (n *keywordDecodeSource) visitOneSource(start, end int, visit func(string, int, int) bool) bool {
	if n.parent == nil {
		return visit(n.text, start, end)
	}
	if n.encoding == "identity" && n.parent.text == n.text {
		// Identity edges keep every byte position. Building and charging a
		// per-byte map for each graph that binds the same parent spends the
		// scan's keyword budget on copies and turns unlabeled values into
		// inspection refusals.
		return n.parent.visitSources(start, end, visit)
	}
	if !n.mapped {
		n.mapped = true
		parentCost := 2 * keywordSpanBytes
		if n.reassembly != nil {
			// RFC replay scans the raw source directly. It retains only the
			// decoded offsets, without the generic decoder's raw span arrays.
			parentCost = 1
		}
		if len(n.text) > maxDecodeTotalBytes/keywordSpanBytes || len(n.parent.text) > maxDecodeTotalBytes/parentCost || !n.owner.charge(len(n.text)*keywordSpanBytes+len(n.parent.text)*parentCost) {
			n.owner.incomplete = true
			n.owner.budget.incomplete = true
			return false
		}
		if n.reassembly != nil {
			n.offsets = n.reassembly.offsets(n.parent.text, n.text)
		} else {
			n.offsets = keywordDecodeOffsets(n.parent.text, n.text, n.encoding)
		}
	}
	if len(n.offsets) != len(n.text) {
		n.owner.incomplete = true
		return false
	}
	return n.parent.visitSources(n.offsets[start].start, n.offsets[end-1].end, visit)
}

// keywordCandidateContext distinguishes logical decoded text from projections
// that delete distance-bearing characters. A complete keyword in either the
// decoded context or the original source outside its exact hull corroborates.
type keywordProjectionKey struct{ source, view string }

type keywordCandidateContext struct {
	presence map[*config.DLPKeywordMatcher]bool
	// exactDecoded uses candidate offsets from an unnormalized decoded view.
	exactDecoded       bool
	exactSources       map[string]*string
	sourceUnavailable  bool
	projections        map[keywordProjectionKey][]keywordByteSpan
	logical            string
	logicalUnavailable bool
	source             string
	decoded            *keywordDecodeSource
	alternatives       []*keywordDecodeSource
	memo               *decodingMemo

	offsets []int
}

func (c *keywordCandidateContext) matches(gate *config.DLPKeywordMatcher, view string, start, end int) (matched bool) {
	if c.exactDecoded && c.exactSources == nil {
		c.exactSources = make(map[string]*string)
	}
	if c.memo != nil {
		incomplete := c.memo.incomplete
		budgetIncomplete := c.memo.keywordBudget != nil && c.memo.keywordBudget.incomplete
		defer func() {
			if matched {
				c.memo.incomplete = incomplete
				if c.memo.keywordBudget != nil {
					c.memo.keywordBudget.incomplete = budgetIncomplete
				}
			}
		}()
	}
	logical := c.logical
	if logical == "" {
		logical = view
	}
	if !c.exactDecoded && !c.keywordPossible(gate, logical, true) {
		return false
	}
	if len(c.alternatives) > 0 {
		if c.projections == nil {
			c.projections = make(map[keywordProjectionKey][]keywordByteSpan)
		}
		for _, node := range c.alternatives {
			contexts := node.logicalContexts()
			unavailable := len(contexts) == 0
			if unavailable {
				contexts = []string{node.text}
			}
			for _, logical := range contexts {
				next := *c
				next.alternatives = nil
				next.decoded = node
				next.logical = config.DLPKeywordContext(logical)
				next.logicalUnavailable = unavailable
				if next.matches(gate, view, start, end) {
					return true
				}
			}
		}
		return false
	}
	ls, le, ok := start, end, true
	if c.exactDecoded {
		ls, le, ok = c.assembledNormalizedSpan(view, logical, start, end)
	} else if view != logical {
		ls, le, ok = c.projectionSpan(logical, view, start, end)
	}
	if c.offsets != nil {
		ok = start >= 0 && end > start && end <= len(c.offsets)
		if ok {
			ls, le = c.offsets[start], c.offsets[end-1]+1
		}
	}
	if !c.logicalUnavailable && ok && gate.Matches(logical, ls, le) {
		return true
	}
	if c.decoded == nil {
		if !ok || c.sourceUnavailable {
			return c.unavailableURLContext(gate)
		}
		return false
	}
	original := config.DLPKeywordContext(c.decoded.text)
	ds, de, mapped := start, end, true
	if !c.exactDecoded {
		if original != view {
			ds, de, mapped = c.projectionSpan(original, view, start, end)
		}
		if mapped {
			ds, de, mapped = keywordNormalizedSpan(c.decoded.text, original, ds, de)
		}
	}
	if !mapped {
		return c.unavailableURLContext(gate)
	}
	found := false
	matched = c.decoded.visitSources(ds, de, func(root string, rs, re int) bool {
		source := c.source
		if source == "" {
			source = root
		} else if !strings.Contains(source, root) && strings.Contains(c.logical, root) {
			// Synthetic separator-preserving units aren't literal URL slices.
			source = c.logical
		} else if !strings.Contains(source, root) && c.memo != nil && root == c.memo.keywordInput {
			// The unit's normalization removes invisible tags. The whole input
			// keeps exact coordinates for a view decoded from those tags.
			source = root
		}
		for from := 0; from <= len(source)-len(root); {
			// Overlapping occurrences can revisit the same root bytes. Charge
			// each comparison to the existing keyword inspection budget.
			if !c.decoded.owner.charge(len(root) + keywordSpanBytes) {
				return false
			}
			at := strings.Index(source[from:], root)
			if at < 0 {
				break
			}
			at += from
			found = true
			if c.exactDecoded {
				if c.assembledSourceKeyword(gate, source, at+rs, at+re) {
					return true
				}
			} else if gate.Matches(source, at+rs, at+re) {
				return true
			}
			from = at + 1
		}
		return false
	})
	if !matched && (!found || c.decoded.owner.incomplete || c.decoded.owner.budget.incomplete) {
		return c.unavailableURLContext(gate)
	}
	return matched
}

// urlKeywordContext holds only views already produced by this URL's DLP scan.
// It is active only inside checkDLPWithDecodesAt, never for text or responses.
type urlKeywordContext struct {
	targets []dlpTarget
	// Targets only grow during one URL scan, so a found keyword stays found
	// and a negative result needs checking only against later targets.
	matches map[*config.DLPKeywordMatcher]bool
	scanned map[*config.DLPKeywordMatcher]int
}

// unavailableURLContext uses the URL-wide superset only when exact mapping
// fails. A negative fallback completes keyword inspection; exhausted work still
// refuses. Scan checks maxURLLength before parsing or producing these views.
func (c *keywordCandidateContext) unavailableURLContext(gate *config.DLPKeywordMatcher) bool {
	if c.memo == nil {
		return false
	}
	m := c.memo
	if m.keywordURL == nil || m.keywordBudget != nil && m.keywordBudget.incomplete {
		m.markIncomplete()
		return false
	}
	u := m.keywordURL
	if u.matches[gate] {
		return true
	}
	if u.matches == nil {
		u.matches = make(map[*config.DLPKeywordMatcher]bool)
		u.scanned = make(map[*config.DLPKeywordMatcher]int)
	}
	budget := keywordDecodeSources{budget: m.keywordBudgetForScan()}
	for _, target := range u.targets[u.scanned[gate]:] {
		if !budget.charge(len(target.text)) {
			m.markIncomplete()
			return false
		}
		context := config.DLPKeywordContext(target.text)
		if gate.MatchesAnywhere(context) {
			u.matches[gate] = true
			return true
		}
		normalized := m.normalize(target.text)
		if normalized != context {
			if !budget.charge(len(normalized)) {
				m.markIncomplete()
				return false
			}
			if gate.MatchesAnywhere(normalized) {
				u.matches[gate] = true
				return true
			}
		}
	}
	u.scanned[gate] = len(u.targets)
	return false
}

// Escape decoders copy surrounding text. If that text came through a compacted
// view, recover its pre-compaction logical context before measuring distance.
// Bit encodings instead produce their own decoded characters and distances.
func (n *keywordDecodeSource) logicalContexts() []string {
	if n.logicalReady && n.logicalVersion == n.owner.budget.sourceVersion {
		return n.logicals
	}
	n.logicalReady = true
	n.logicalVersion = n.owner.budget.sourceVersion
	n.logicals = nil
	n.logicalUnavailable = false
	appendContext := func(text string) {
		for _, prior := range n.logicals {
			if text == prior {
				return
			}
		}
		if text != n.text && !n.owner.charge(len(text)) {
			n.logicalUnavailable = true
			return
		}
		n.logicals = append(n.logicals, text)
	}
	if n.parent == nil {
		appendContext(n.text)
		return n.logicals
	}
	variants := append([]*keywordDecodeSource{n}, n.variants...)
	for _, edge := range variants {
		switch edge.encoding {
		case "identity", "projection", encodingURL, encodingHTML, encodingJSONUnicode, keywordURLPercent, keywordPercentDrop, keywordPercentEscapeDrop, keywordQueryValues:
			for _, text := range edge.parent.logicalContexts() {
				switch edge.encoding {
				case keywordQueryValues:
					text = IterativeDecode(text)
				case keywordPercentDrop:
					text = dropInvalidPercent(text, 0)
				case keywordPercentEscapeDrop:
					text = dropInvalidPercentEscapes(text)
				case encodingURL:
					text = IterativeDecode(text)
				case keywordURLPercent:
					text = iterativePercentDecode(text)
				case encodingHTML:
					text, _ = decodeHTMLEntitiesChecked(text)
				case encodingJSONUnicode:
					text = normalize.DecodeJSONUnicodeEscapes(text)
				}
				appendContext(text)
			}
			n.logicalUnavailable = n.logicalUnavailable || edge.parent.logicalUnavailable
		default:
			appendContext(n.text)
		}
	}
	return n.logicals
}

func (c *keywordCandidateContext) projectionSpan(source, view string, start, end int) (int, int, bool) {
	if source == view {
		return start, end, start >= 0 && end <= len(source)
	}
	if start < 0 || end <= start || end > len(view) {
		return 0, 0, false
	}
	key := keywordProjectionKey{source: source, view: view}
	offsets, found := c.projections[key]
	if !found {
		if c.projections == nil {
			c.projections = make(map[keywordProjectionKey][]keywordByteSpan)
		}
		// Retain failed projections too. Copies used for alternate source
		// paths share this cache across candidates.
		c.projections[key] = nil
		if c.memo != nil {
			budget := keywordDecodeSources{budget: c.memo.keywordBudgetForScan()}
			if len(view) > maxDecodeTotalBytes/keywordSpanBytes || len(source) > maxDecodeTotalBytes/(2*keywordSpanBytes) || !budget.charge(len(view)*keywordSpanBytes+len(source)*(2*keywordSpanBytes)) {
				c.memo.incomplete = true
				budget.budget.incomplete = true
				return 0, 0, false
			}
		}
		offsets = keywordProjectionOffsets(source, view)
		c.projections[key] = offsets
	}
	if len(offsets) != len(view) {
		return 0, 0, false
	}
	return offsets[start].start, offsets[end-1].end, true
}

// Only reproduce the scanner's existing deletion transforms. An arbitrary
// subsequence is not proof of where a transformed candidate came from.
func keywordProjectionOffsets(source, view string) []keywordByteSpan {
	base := normalize.ForDLP(source)
	var iter norm.Iter
	iter.InitString(norm.NFKC, source)
	var b strings.Builder
	var baseOffsets []keywordByteSpan
	for !iter.Done() {
		a := iter.Pos()
		_ = iter.Next()
		z := iter.Pos()
		text := normalize.ForDLP(source[a:z])
		b.WriteString(text)
		for range len(text) {
			baseOffsets = append(baseOffsets, keywordByteSpan{a, z})
		}
	}
	if b.String() != base {
		return nil
	}
	if base == view {
		return baseOffsets
	}
	transforms := []func(string) string{compactTextDLPWhitespace, removeHostnameDots, stripURLNoise, stripToAlphanumeric}
	for _, transform := range transforms {
		if transform(base) != view {
			continue
		}
		var offsets []keywordByteSpan
		for i, r := range base {
			text := transform(string(r))
			if text == "" {
				continue
			}
			width := len(string(r))
			for range len(text) {
				offsets = append(offsets, keywordByteSpan{baseOffsets[i].start, baseOffsets[i+width-1].end})
			}
		}
		if len(offsets) == len(view) {
			return offsets
		}
	}
	return nil
}

// keywordNormalizedSpan reconstructs only text-preserving normalization. Each
// normalization segment owns a source hull, including combining sequences.
// Equality with the production normalizer is mandatory; no guessed map is used.
func keywordNormalizedSpan(source, view string, start, end int) (int, int, bool) {
	if source == view {
		return start, end, start >= 0 && end <= len(source)
	}
	var iter norm.Iter
	iter.InitString(norm.NFKC, source)
	var b strings.Builder
	first, last := -1, -1
	for !iter.Done() {
		a := iter.Pos()
		_ = iter.Next()
		z := iter.Pos()
		text := config.DLPKeywordContext(source[a:z])
		before := b.Len()
		b.WriteString(text)
		if len(text) > 0 && before <= start && start < b.Len() {
			first = a
		}
		if len(text) > 0 && before < end && end <= b.Len() {
			last = z
		}
	}
	return first, last, b.String() == view && first >= 0 && last > first
}

func keywordDecodeOffsets(source, decoded, encoding string) []keywordByteSpan {
	switch encoding {
	case "identity":
		if source != decoded {
			return nil
		}
		offsets := make([]keywordByteSpan, len(decoded))
		for i := range offsets {
			offsets[i] = keywordByteSpan{i, i + 1}
		}
		return offsets
	case "projection":
		return keywordProjectionOffsets(source, decoded)
	case keywordQueryValues:
		return keywordQueryValueOffsets(source, decoded)
	case keywordPercentDrop:
		return keywordPercentOffsets(source, decoded, 0)
	case keywordPercentEscapeDrop:
		return keywordPercentOffsets(source, decoded, 2)
	case encodingHex:
		symbols, offsets := keywordEncodingSymbols(source, encodingHex, 0, false)
		if b, err := hex.DecodeString(symbols); err == nil && string(b) == decoded {
			return keywordBitOffsets(offsets, len(decoded), 4)
		}
	case encodingBase64:
		for _, kind := range []encodedTokenKind{encodedTokenBase64Std, encodedTokenBase64URL} {
			for _, project := range []bool{false, true} {
				symbols, offsets := keywordEncodingSymbols(source, encodingBase64, kind, project)
				for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
					if b, err := enc.DecodeString(symbols); err == nil && string(b) == decoded {
						return keywordBitOffsets(offsets, len(decoded), 6)
					}
				}
			}
		}
	case encodingBase32:
		for _, project := range []bool{false, true} {
			symbols, offsets := keywordEncodingSymbols(source, encodingBase32, encodedTokenBase32, project)
			for _, enc := range []*base32.Encoding{base32.StdEncoding, base32.StdEncoding.WithPadding(base32.NoPadding), base32.HexEncoding, base32.HexEncoding.WithPadding(base32.NoPadding)} {
				if b, err := enc.DecodeString(symbols); err == nil && string(b) == decoded {
					return keywordBitOffsets(offsets, len(decoded), 5)
				}
			}
		}
	case encodingURL, keywordURLPercent, encodingHTML, encodingJSONUnicode:
		return keywordEscapeOffsets(source, decoded, encoding)
	case encodingDecimal, encodingOctal, encodingBinary, encodingQuotedPrintable:
		return keywordTextEncodingOffsets(source, decoded, encoding)
	case encodingUnicodeTags:
		return keywordTagOffsets(source, decoded)
	case keywordSegment:
		return keywordSegmentOffsets(source, decoded)
	}
	return nil
}

// keywordSegmentOffsets maps a segment only when it occurs once in its parent.
// A repeated segment has no single source position, so it fails closed.
func keywordSegmentOffsets(source, segment string) []keywordByteSpan {
	at := strings.Index(source, segment)
	if segment == "" || at < 0 || strings.Contains(source[at+1:], segment) {
		return nil
	}
	offsets := make([]keywordByteSpan, len(segment))
	for i := range offsets {
		offsets[i] = keywordByteSpan{at + i, at + i + 1}
	}
	return offsets
}

// keywordTagOffsets mirrors normalize.DecodeTags: untouched bytes map to
// themselves, a printable tag maps to its whole rune, and begin/cancel tags
// produce nothing. A mismatch returns nil so the caller fails closed.
func keywordTagOffsets(source, decoded string) []keywordByteSpan {
	offsets := make([]keywordByteSpan, 0, len(decoded))
	copied := 0
	for i, r := range source {
		printable := r >= 0xe0020 && r <= 0xe007e
		if !printable && r != 0xe0001 && r != 0xe007f {
			continue
		}
		for j := copied; j < i; j++ {
			offsets = append(offsets, keywordByteSpan{j, j + 1})
		}
		width := utf8.RuneLen(r)
		if printable {
			offsets = append(offsets, keywordByteSpan{i, i + width})
		}
		copied = i + width
	}
	for j := copied; j < len(source); j++ {
		offsets = append(offsets, keywordByteSpan{j, j + 1})
	}
	if len(offsets) != len(decoded) || normalize.DecodeTags(source) != decoded {
		return nil
	}
	return offsets
}

// keywordTextEncodingOffsets reuses the byte ranges the text-encoding decoders
// already report for opaque-fragment mapping (mapTextEncodingSources). Any
// mismatch returns nil so the caller keeps its fail-closed behavior.
func keywordTextEncodingOffsets(source, decoded, encoding string) []keywordByteSpan {
	var text string
	var ranges []encodingSourceRange
	switch encoding {
	case encodingDecimal:
		text, ranges = decodeCharacterCodes(source, characterCodeSeparator, parseDecimalCharacterCode, true)
	case encodingOctal, encodingBinary:
		text, ranges = decodePrefixedCharacterCodes(source, encoding, true)
	case encodingQuotedPrintable:
		text, ranges = decodeQuotedPrintable(source, true)
	}
	if text != decoded || len(ranges) != len(decoded) {
		return nil
	}
	offsets := make([]keywordByteSpan, len(ranges))
	for i, r := range ranges {
		if r.start < 0 || r.end <= r.start || r.end > len(source) {
			return nil
		}
		offsets[i] = keywordByteSpan(r)
	}
	return offsets
}

func keywordEncodingSymbols(source, encoding string, kind encodedTokenKind, project bool) (string, []keywordByteSpan) {
	var b strings.Builder
	offsets := make([]keywordByteSpan, 0, len(source))
	for i := 0; i < len(source); i++ {
		c := source[i]
		if encoding == encodingHex {
			if i+3 < len(source) && (c == '0' || c == '\\') && (source[i+1] == 'x' || source[i+1] == 'X') && isHexDigitByte(source[i+2]) && isHexDigitByte(source[i+3]) {
				i++
				continue
			}
			if !isHexDigitByte(c) {
				continue
			}
		} else {
			if encoding == encodingBase32 {
				c = asciiUpperByte(c)
			}
			if project && !isEncodedTokenByte(c, kind) {
				continue
			}
			if !project && (c == '\n' || c == '\r') && encoding == encodingBase64 {
				continue
			}
		}
		b.WriteByte(c)
		offsets = append(offsets, keywordByteSpan{i, i + 1})
	}
	return b.String(), offsets
}

func keywordBitOffsets(symbols []keywordByteSpan, size, bits int) []keywordByteSpan {
	offsets := make([]keywordByteSpan, size)
	for i := range offsets {
		a, z := i*8/bits, ((i+1)*8-1)/bits
		if z >= len(symbols) {
			return nil
		}
		offsets[i] = keywordByteSpan{symbols[a].start, symbols[z].end}
	}
	return offsets
}

func keywordEscapeOffsets(source, decoded, encoding string) []keywordByteSpan {
	text := source
	var previous []keywordByteSpan
	// Use the same per-transform pass bounds as the producing decoder.
	rounds := 1
	if encoding == encodingURL || encoding == keywordURLPercent {
		rounds = maxDecodeRounds
	}
	if encoding == encodingHTML {
		rounds = maxHTMLEntityDecodePasses
	}
	for range rounds {
		var b strings.Builder
		var offsets []keywordByteSpan
		for i := 0; i < len(text); {
			end, value := i+1, text[i:i+1]
			switch encoding {
			case encodingURL, keywordURLPercent:
				if text[i] == '%' && i+2 < len(text) && isHexDigitByte(text[i+1]) && isHexDigitByte(text[i+2]) {
					end = i + 3
					value = normalize.QueryUnescapePartial(text[i:end])
				} else if text[i] == '+' && encoding == encodingURL {
					value = " "
				}
			case encodingHTML:
				if text[i] == '&' {
					for end < len(text) && (text[end] >= 'a' && text[end] <= 'z' || text[end] >= 'A' && text[end] <= 'Z' || text[end] >= '0' && text[end] <= '9' || text[end] == '#') {
						end++
					}
					if end < len(text) && text[end] == ';' {
						end++
					}
					value = html.UnescapeString(text[i:end])
				}
			case encodingJSONUnicode:
				if text[i] == '\\' && i+5 < len(text) && text[i+1] == 'u' {
					end = i + 6
					if end+5 < len(text) && text[end:end+2] == `\u` {
						high, hiErr := strconv.ParseUint(text[i+2:i+6], 16, 16)
						low, lowErr := strconv.ParseUint(text[end+2:end+6], 16, 16)
						if hiErr == nil && lowErr == nil && high >= 0xD800 && high <= 0xDBFF && low >= 0xDC00 && low <= 0xDFFF {
							end += 6
						}
					}
					value = normalize.DecodeJSONUnicodeEscapes(text[i:end])
				}
			}
			span := keywordByteSpan{i, end}
			if previous != nil {
				span = keywordByteSpan{previous[i].start, previous[end-1].end}
			}
			b.WriteString(value)
			for range len(value) {
				offsets = append(offsets, span)
			}
			i = end
		}
		next := b.String()
		if next == decoded {
			return offsets
		}
		if next == text {
			return nil
		}
		text, previous = next, offsets
	}
	return nil
}

func (s *Scanner) hasDLPKeywords() bool { return s.keywordPatterns }

// keywordsActive reports whether this scan tracks keyword context, so callers
// can skip building context strings when no pattern uses keywords.
func (m *decodingMemo) keywordsActive() bool {
	return m != nil && m.keywordMode
}

// registerKeywordURLSegments recovers literal escaped source slices for the
// existing URL component and segment views. Decoding may introduce delimiters,
// so splitting the escaped spelling first cannot recover all segment roots.
// The shared escape mapper proves each byte hull, including repeated segments;
// the normal tracked decoder then binds its children to these source edges.
func (m *decodingMemo) registerKeywordURLSegments(escaped string, segments []string) {
	if !m.keywordsActive() {
		return
	}
	seen := make(map[keywordProjectionKey]bool)
	seenViews := make(map[string]bool)
	for _, decoded := range []struct{ encoding, text string }{
		{keywordURLPercent, normalize.PercentUnescapePartial(escaped)},
		{encodingURL, IterativeDecode(escaped)},
		{keywordURLPercent, iterativePercentDecode(escaped)},
	} {
		encoding, view := decoded.encoding, decoded.text
		if view == escaped || seenViews[view] {
			continue
		}
		seenViews[view] = true
		budget := keywordDecodeSources{budget: m.keywordBudgetForScan()}
		if len(view) > maxDecodeTotalBytes/keywordSpanBytes || len(escaped) > maxDecodeTotalBytes/(2*keywordSpanBytes) || !budget.charge(len(view)*keywordSpanBytes+len(escaped)*(2*keywordSpanBytes)) {
			m.markIncomplete()
			return
		}
		offsets := keywordEscapeOffsets(escaped, view, encoding)
		if len(offsets) != len(view) {
			m.markIncomplete()
			return
		}
		seenSegments := make(map[string]bool)
		for _, segment := range segments {
			if segment == "" || seenSegments[segment] {
				continue
			}
			seenSegments[segment] = true
			for from := 0; from <= len(view)-len(segment); {
				if !budget.charge(len(view) - from + keywordSpanBytes) {
					m.markIncomplete()
					return
				}
				at := strings.Index(view[from:], segment)
				if at < 0 {
					break
				}
				at += from
				source := escaped[offsets[at].start:offsets[at+len(segment)-1].end]
				key := keywordProjectionKey{source: source, view: segment}
				if !seen[key] {
					seen[key] = true
					m.registerKeywordTransform(source, segment, encoding)
				}
				from = at + 1
			}
		}
	}
}

func (m *decodingMemo) registerKeywordTransform(source, view, encoding string) {
	if m == nil || !m.keywordMode || source == view {
		return
	}
	graph := newKeywordDecodeSources(source)
	graph.budget = m.keywordBudgetForScan()

	if parents := m.keywordSources[source]; len(parents) > 0 {
		graph.bindParents(source, parents)
	}
	node := graph.add(source, view, encoding)

	if node != nil {
		if m.keywordSources == nil {
			m.keywordSources = make(map[string][]*keywordDecodeSource)
		}
		m.keywordSources[view] = append(m.keywordSources[view], node)
	}
}

func (p *compiledPattern) matchSpanWithDecodes(view, source string, memo *decodingMemo) (start, end int, matched bool) {
	if p.keywords == nil {
		return p.matchSpanInView(view, source)
	}
	pattern := *p
	logical := config.DLPKeywordContext(source)
	context := keywordCandidateContext{logical: logical, memo: memo}
	if memo != nil {
		context.source = memo.keywordUnit
		context.alternatives = memo.keywordSources[view]
		if len(context.alternatives) == 0 {
			context.alternatives = memo.keywordSources[source]
		}
		context.sourceUnavailable = len(context.alternatives) == 0 && memo.keywordBudget != nil && memo.keywordBudget.incomplete && !strings.Contains(memo.keywordUnit, logical) && !strings.ContainsRune(source, 0)
	}
	pattern.keywordContext = &context
	return pattern.matchSpanInView(view, source)
}

func (s *keywordDecodeSources) bindParents(text string, parents []*keywordDecodeSource) {
	root := s.nodes[text]
	for _, parent := range parents {
		if parent == root || parent.hasSourceAncestor(root) {
			continue
		}
		encoding := "identity"
		if parent.text != text {
			encoding = "projection"
		}
		if root.parent == parent && root.encoding == encoding {
			continue
		}
		duplicate := false
		for _, variant := range root.variants {
			duplicate = duplicate || variant.parent == parent && variant.encoding == encoding
		}
		if duplicate {
			continue
		}
		if root.parent == nil {
			s.budget.sourceVersion++
			root.parent = parent
			root.encoding = encoding
			continue
		}
		if !s.chargeNode() {
			return
		}
		s.budget.sourceVersion++
		root.variants = append(root.variants, &keywordDecodeSource{text: text, encoding: encoding, parent: parent, owner: s})
	}
}

// keywordPercentOffsets maps the exact deletion transform used by
// invalidPercentEscapeViews. Equality with that producer is required.
func keywordPercentOffsets(source, view string, extra int) []keywordByteSpan {
	if dropInvalidPercent(source, extra) != view {
		return nil
	}
	offsets := make([]keywordByteSpan, 0, len(view))
	for i := 0; i < len(source); i++ {
		if source[i] != '%' {
			offsets = append(offsets, keywordByteSpan{i, i + 1})
			continue
		}
		if i+2 < len(source) && isHexByte(source[i+1]) && isHexByte(source[i+2]) {
			for j := i; j < i+3; j++ {
				offsets = append(offsets, keywordByteSpan{j, j + 1})
			}
			i += 2
			continue
		}
		skip := 0
		for skip < extra && i+1+skip < len(source) && source[i+1+skip] != '%' {
			skip++
		}
		i += skip
	}
	return offsets
}

// keywordQueryValueOffsets follows orderedQueryConcat, retaining the key and
// separator distances in the source hull around the reconstructed values.
func keywordQueryValueOffsets(source, view string) []keywordByteSpan {
	if orderedQueryConcat(source) != view {
		return nil
	}
	var offsets []keywordByteSpan
	from := 0
	for _, pair := range strings.Split(source, "&") {
		key, raw, found := strings.Cut(pair, "=")
		if found && raw != "" {
			value := IterativeDecode(raw)
			positions := keywordDecodeOffsets(raw, value, encodingURL)
			if raw == value {
				positions = keywordDecodeOffsets(raw, value, "identity")
			}
			if len(positions) != len(value) {
				return nil
			}
			for _, span := range positions {
				offsets = append(offsets, keywordByteSpan{from + len(key) + 1 + span.start, from + len(key) + 1 + span.end})
			}
		}
		from += len(pair) + 1
	}
	return offsets
}
