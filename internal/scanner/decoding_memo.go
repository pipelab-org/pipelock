// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"sync"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

type decodingMemoKey struct {
	text       string
	includeURL bool
	minPrefix  int
	inbound    bool
}

// decodingMemo shares immutable decoded and normalized views within one scan. It never
// stores findings, policy decisions or state on the Scanner. Its retention
// limits stop caching, not decoding or detection.
//
// incomplete records that some decode or HTML entity chain in this scan
// stopped at a depth or work bound with decodable work left. It is a property of the
// scan, not of one view, so it survives cache hits and unretained decodes.
type decodingMemo struct {
	views         map[decodingMemoKey]memoDecode
	normalized    map[string]string
	retainedBytes int
	incomplete    bool
	inbound       bool
	// shared, when set, replaces views and normalized as the cache. It is
	// owned by a caller that scans several views of one message.
	shared *sharedDecodes
	// decodedMatches holds pattern results for decoded candidates; see
	// matchDecoded. Its entries count toward their own byte budget.
	decodedMatches      map[decodedMatchKey][]TextDLPMatch
	decodedMatchesBytes int
	// The whitespace-compacted view of the last text compacted in this scan.
	// The core floor and configured patterns both compact the same view.
	compactSource, compactText string
	compactOffsets             []int
	compactReady               bool
}

// compactWhitespace returns compactTextDLPWhitespaceWithOffsets(text) when
// text holds whitespace, and text with nil offsets when it holds none; for
// normalized (valid UTF-8) text that is exactly compactTextDLPWhitespace's
// result. Callers only read the offsets.
func (m *decodingMemo) compactWhitespace(text string) (string, []int) {
	if m != nil && m.compactReady && m.compactSource == text {
		return m.compactText, m.compactOffsets
	}
	compacted, offsets := text, []int(nil)
	if strings.ContainsFunc(text, unicode.IsSpace) {
		compacted, offsets = compactTextDLPWhitespaceWithOffsets(text)
	}
	if m != nil {
		m.compactSource, m.compactText, m.compactOffsets, m.compactReady = text, compacted, offsets, true
	}
	return compacted, offsets
}

// decodedMatchKey identifies one pattern-set match over a decoded candidate:
// the core floor or the configured patterns. The result depends only on the
// scanner's compiled patterns, the candidate bytes and its encoding label.
type decodedMatchKey struct {
	scanner  *Scanner
	text     string
	encoding string
	core     bool
	// cardOnly marks a configured-pattern result restricted to card rules.
	cardOnly bool
}

func (k decodedMatchKey) match(normalized string, lowered *dlpLoweredBytes) []TextDLPMatch {
	if k.core {
		return k.scanner.matchCoreDLPPatternsLowered(normalized, k.encoding, lowered)
	}
	patterns := textDLPAllPatterns
	if k.cardOnly {
		patterns = textDLPCardPatterns
	}
	return k.scanner.matchDLPPatternsLowered(normalized, k.encoding, k.text, lowered, patterns)
}

// sharedDecodes lets the scans of one message's views reuse each other's
// immutable decoded and normalized results. A decode is a pure function of
// its key and a normalization of its input, so a reused entry is the value a
// fresh call would compute. Per-scan state (incomplete, inbound) stays on
// each scan's own decodingMemo; an incomplete entry still marks every scan
// that reads it. The same retention limits as one scan stop caching, never
// decoding.
type sharedDecodes struct {
	mu    sync.Mutex
	store decodingMemo
}

type sharedDecodesKey struct{}

// sharedDecodesPool recycles stores between messages. A recycled store is
// cleared first, and every entry is a pure function of its full key, so even a
// scan still holding an old context reads only values it would compute.
var sharedDecodesPool = sync.Pool{New: func() any { return &sharedDecodes{} }}

// WithSharedDecodes returns a context whose text DLP scans share decoded
// views, and a release function the caller runs once those scans finish.
func WithSharedDecodes(ctx context.Context) (context.Context, func()) {
	shared, _ := sharedDecodesPool.Get().(*sharedDecodes)
	if shared == nil {
		shared = &sharedDecodes{}
	}
	return context.WithValue(ctx, sharedDecodesKey{}, shared), func() {
		shared.mu.Lock()
		shared.store.reset()
		shared.mu.Unlock()
		sharedDecodesPool.Put(shared)
	}
}

// reset empties the caches and keeps their storage for reuse.
func (m *decodingMemo) reset() {
	clear(m.views)
	clear(m.normalized)
	clear(m.decodedMatches)
	m.retainedBytes = 0
	m.decodedMatchesBytes = 0
}

func sharedDecodesFrom(ctx context.Context) *sharedDecodes {
	if ctx == nil {
		return nil
	}
	shared, _ := ctx.Value(sharedDecodesKey{}).(*sharedDecodes)
	return shared
}

func (s *sharedDecodes) decode(key decodingMemoKey) ([]decodedResult, bool) {
	s.mu.Lock()
	cached, ok := s.store.views[key]
	s.mu.Unlock()
	if ok {
		return cached.views, cached.complete
	}
	decoded, complete := decodeEncodingsBudgetMode(key.text, key.includeURL, key.minPrefix, key.inbound)
	s.mu.Lock()
	s.store.retainDecode(key, decoded, complete)
	s.mu.Unlock()
	return decoded, complete
}

func (s *sharedDecodes) matchDecoded(key decodedMatchKey) []TextDLPMatch {
	s.mu.Lock()
	cached, ok := s.store.decodedMatches[key]
	s.mu.Unlock()
	if ok {
		return slices.Clone(cached)
	}
	normalized := s.normalize(key.text)
	var lowered dlpLoweredBytes
	lowered.add(normalized)
	matches := key.match(normalized, &lowered)
	s.mu.Lock()
	s.store.retainDecodedMatches(key, matches)
	s.mu.Unlock()
	return slices.Clone(matches)
}

func (s *sharedDecodes) normalize(text string) string {
	s.mu.Lock()
	normalized, ok := s.store.normalized[text]
	s.mu.Unlock()
	if ok {
		return normalized
	}
	normalized = normalize.ForDLP(text)
	s.mu.Lock()
	s.store.retainNormalized(text, normalized)
	s.mu.Unlock()
	return normalized
}

type memoDecode struct {
	views    []decodedResult
	complete bool
}

// markIncomplete records a bound reached outside the fixpoint decoder. A nil
// memo has no scan to mark; callers that need the signal pass a memo.
func (m *decodingMemo) markIncomplete() {
	if m != nil {
		m.incomplete = true
	}
}

// inspectionIncomplete reports whether any bound in this scan returned a
// partial result.
func (m *decodingMemo) inspectionIncomplete() bool {
	return m != nil && m.incomplete
}

// decodeHTML is decodeHTMLEntities that records a chain left undecoded at the
// pass limit.
func (m *decodingMemo) decodeHTML(text string) string {
	decoded, converged := decodeHTMLEntitiesChecked(text)
	if !converged {
		m.markIncomplete()
	}
	return decoded
}

func (m *decodingMemo) decode(text string, includeURL bool) []decodedResult {
	return m.decodeMode(text, includeURL, 0)
}

func (m *decodingMemo) decodeKnownSecret(text string, minimum int) []decodedResult {
	return m.decodeMode(text, true, minimum)
}

func (m *decodingMemo) decodeMode(text string, includeURL bool, minPrefix int) []decodedResult {
	if m == nil {
		decoded, _ := decodeEncodingsFixpointMode(text, includeURL, minPrefix)
		return decoded
	}
	key := decodingMemoKey{text: text, includeURL: includeURL, minPrefix: minPrefix, inbound: m.inbound}
	if m.shared != nil {
		decoded, complete := m.shared.decode(key)
		if !complete {
			m.incomplete = true
		}
		return decoded
	}
	if cached, ok := m.views[key]; ok {
		if !cached.complete {
			m.incomplete = true
		}
		return cached.views
	}
	decoded, complete := decodeEncodingsBudgetMode(text, includeURL, minPrefix, m.inbound)
	if !complete {
		m.incomplete = true
	}
	m.retainDecode(key, decoded, complete)
	return decoded
}

func (m *decodingMemo) retainDecode(key decodingMemoKey, decoded []decodedResult, complete bool) {
	if key.text == "" || len(m.views)+len(m.normalized) >= maxDecodeCandidates {
		return
	}
	remaining := maxDecodeTotalBytes - m.retainedBytes
	cost := len(key.text)
	if cost > remaining {
		return
	}
	for _, view := range decoded {
		if len(view.text) > remaining-cost {
			return
		}
		cost += len(view.text)
	}
	if m.views == nil {
		m.views = make(map[decodingMemoKey]memoDecode)
	}
	m.views[key] = memoDecode{views: decoded, complete: complete}
	m.retainedBytes += cost
}

// normalize preserves each call's exact input and normalization depth. A
// normalized output is not treated as already normalized on a later call.
func (m *decodingMemo) normalize(text string) string {
	if m == nil {
		return normalize.ForDLP(text)
	}
	if m.shared != nil {
		return m.shared.normalize(text)
	}
	if normalized, ok := m.normalized[text]; ok {
		return normalized
	}
	normalized := normalize.ForDLP(text)
	m.retainNormalized(text, normalized)
	return normalized
}

func (m *decodingMemo) retainNormalized(text, normalized string) {
	if text == "" || len(m.views)+len(m.normalized) >= maxDecodeCandidates {
		return
	}
	remaining := maxDecodeTotalBytes - m.retainedBytes
	if len(text) > remaining || len(normalized) > remaining-len(text) {
		return
	}
	if m.normalized == nil {
		m.normalized = make(map[string]string)
	}
	m.normalized[text] = normalized
	m.retainedBytes += len(text) + len(normalized)
}

// matchDecoded runs the configured patterns over a decoded candidate, and
// matchDecodedCore the core floor. The fixpoint walk and per-segment decoding
// often reach the same candidate more than once in one scan (padded and raw
// base64 of the same bytes, the same segment in several views); every repeat
// returns the first call's matches, in the same order and multiplicity, as a
// fresh slice the caller may filter.
func (m *decodingMemo) matchDecoded(sc *Scanner, text, encoding string) []TextDLPMatch {
	return m.matchDecodedKey(decodedMatchKey{scanner: sc, text: text, encoding: encoding})
}

// matchDecodedFor returns patterns.selectMatches of matchDecoded. A card-only
// scan reuses a cached result for every configured pattern when one exists,
// and otherwise runs only the card rules: the same rules, in the same order,
// select the same matches.
func (m *decodingMemo) matchDecodedFor(sc *Scanner, text, encoding string, patterns textDLPPatternSet) []TextDLPMatch {
	full := decodedMatchKey{scanner: sc, text: text, encoding: encoding}
	if patterns != textDLPCardPatterns {
		return patterns.selectMatches(m.matchDecodedKey(full))
	}
	if cached, ok := m.cachedDecodedMatches(full); ok {
		return patterns.selectMatches(cached)
	}
	card := full
	card.cardOnly = true
	return patterns.selectMatches(m.matchDecodedKey(card))
}

// cachedDecodedMatches returns a copy of a retained result without computing.
func (m *decodingMemo) cachedDecodedMatches(key decodedMatchKey) ([]TextDLPMatch, bool) {
	if m == nil {
		return nil, false
	}
	if m.shared != nil {
		m.shared.mu.Lock()
		defer m.shared.mu.Unlock()
		cached, ok := m.shared.store.decodedMatches[key]
		return slices.Clone(cached), ok
	}
	cached, ok := m.decodedMatches[key]
	return slices.Clone(cached), ok
}

func (m *decodingMemo) matchDecodedCore(sc *Scanner, text, encoding string) []TextDLPMatch {
	return m.matchDecodedKey(decodedMatchKey{scanner: sc, text: text, encoding: encoding, core: true})
}

func (m *decodingMemo) matchDecodedKey(key decodedMatchKey) []TextDLPMatch {
	if m == nil {
		normalized := normalize.ForDLP(key.text)
		var lowered dlpLoweredBytes
		lowered.add(normalized)
		return key.match(normalized, &lowered)
	}
	if m.shared != nil {
		return m.shared.matchDecoded(key)
	}
	if cached, ok := m.decodedMatches[key]; ok {
		return slices.Clone(cached)
	}
	normalized := m.normalize(key.text)
	var lowered dlpLoweredBytes
	lowered.add(normalized)
	matches := key.match(normalized, &lowered)
	m.retainDecodedMatches(key, matches)
	return slices.Clone(matches)
}

// textDLPMatchSize is the storage one retained match takes in its slice.
// Match strings are pattern labels shared with the scanner, so they are not
// charged again.
var textDLPMatchSize = int(reflect.TypeFor[TextDLPMatch]().Size())

func (m *decodingMemo) retainDecodedMatches(key decodedMatchKey, matches []TextDLPMatch) {
	cost := len(key.text) + len(key.encoding) + len(matches)*textDLPMatchSize
	if key.text == "" || len(m.decodedMatches) >= maxDecodeCandidates || cost > maxDecodeTotalBytes-m.decodedMatchesBytes {
		return
	}
	if m.decodedMatches == nil {
		m.decodedMatches = make(map[decodedMatchKey][]TextDLPMatch)
	}
	m.decodedMatches[key] = matches
	m.decodedMatchesBytes += cost
}
