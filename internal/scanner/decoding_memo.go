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
	text             string
	includeURL       bool
	minPrefix        int
	inbound          bool
	keyword          bool
	reportWorkLimits bool
}

// decodingMemo shares immutable decoded and normalized views within one scan.
// Findings and scan policy remain request-scoped. The compiled terminal plan
// separately retains bounded, context-independent proofs of no lane admission.
// Payload-cache limits stop caching, not decoding. If required replay
// metadata cannot fit its separate bounded charge, inspection is marked
// incomplete and the existing directional policy applies.
//
// incomplete records that some decode or HTML entity chain in this scan
// stopped at a depth or work bound with decodable work left. It is a property of the
// scan, not of one view, so it survives cache hits and unretained decodes.
type decodingMemo struct {
	reassemblyReplayPayloads     map[assembledPayloadKey][]*assembledPayload
	reassemblyReplayPayloadCount int
	reassemblyRecipeCache        *assembledRecipeCache
	reassemblyPendingReplay      map[int]*assembledPayload
	reassemblyReplayParents      map[string]*assembledPayload
	reassemblyKindInsensitive    bool
	reassemblyPatternLimit       textDLPPatternSet
	reassemblyPatternSelected    bool
	reassemblyPatterns           textDLPPatternSet
	assembledBytes               int
	assembledKeywordReplays      map[assembledReplayKey][]assembledKeywordCandidate
	assembledAllowance           *assembledAllowance
	reassemblyBudget             assembledBudget
	assembledProjectionTable     []assembledProjectionEntry
	assembledProjectionStorage   *assembledProjectionStorage
	assembledProjectionFirst     [5]assembledProjectionEntry
	assembledProjectionEntries   int
	reassemblyDeferred           bool
	reassemblyNestedDeferred     bool
	reassemblyNestedPending      []int
	reassemblyInbound            bool
	reassemblyPending            []string
	reassemblyViewKinds          map[string]assembledViewKind
	reassemblyTextRoots          map[string]bool
	reassemblyDecoded            map[decodingMemoKey]assembledViewKind
	reassemblyDecodedBytes       int
	reassemblyParents            map[string]string
	reassemblyIncomplete         bool
	// scanCtx bounds terminal finalization. A canceled caller stops later
	// views and long walks. That stop stays off the inspection-limit flags:
	// the caller reports cancellation from its own context check.
	scanCtx                 context.Context
	assembledCharged        map[string]*assembledCharges
	assembledChargeRegistry *assembledChargeRegistry
	reassemblyInspected     int
	reassemblyProduced      map[assembledIdentity]struct{}
	reassemblyPlan          *reassemblyPlan
	reassemblySeen          map[string]int
	reassemblyFindings      []TextDLPMatch

	keywordPresence map[keywordPresenceKey]bool
	keywordMode     bool
	keywordBudget   *keywordWorkBudget
	keywordUnit     string
	// keywordInput is the text DLP input whose keyword unit is keywordUnit.
	keywordInput   string
	keywordRawURL  string
	keywordURL     *urlKeywordContext
	keywordSources map[string][]*keywordDecodeSource
	views          map[decodingMemoKey]memoDecode
	normalized     map[string]string
	retainedBytes  int
	incomplete     bool
	inbound        bool
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

// Complete text scans own these memos until finalization. Resetting every field
// before reuse releases payloads and prevents one scan's state crossing into
// another; retained projection metadata has its own cleared storage pool.
var textDecodingMemoPool = sync.Pool{New: func() any { return &decodingMemo{} }}

func textDecodingMemo(shared *sharedDecodes, inbound bool, allowance *assembledAllowance, kindInsensitive bool) *decodingMemo {
	memo, _ := textDecodingMemoPool.Get().(*decodingMemo)
	if memo == nil {
		memo = &decodingMemo{}
	}
	*memo = decodingMemo{shared: shared, reassemblyDeferred: true, reassemblyInbound: inbound, assembledAllowance: allowance, reassemblyKindInsensitive: kindInsensitive}
	memo.assembledStorage()
	return memo
}

func (m *decodingMemo) releaseTextDecodingMemo() {
	m.releaseProjection()
	*m = decodingMemo{}
	textDecodingMemoPool.Put(m)
}

// compactWhitespace returns compactTextDLPWhitespaceWithOffsets(text) when
// text holds whitespace, and text with nil offsets when it holds none; for
// normalized (valid UTF-8) text that is exactly compactTextDLPWhitespace's
// result. Callers only read the offsets.
func (m *decodingMemo) compactWhitespace(text string) (string, []int) {
	if m != nil && m.compactReady && m.compactSource == text {
		m.reassemblyDerive(text, m.compactText)
		return m.compactText, m.compactOffsets
	}
	compacted, offsets := text, []int(nil)
	if strings.ContainsFunc(text, unicode.IsSpace) {
		compacted, offsets = compactTextDLPWhitespaceWithOffsets(text)
	}
	if m != nil {
		compacted = m.rememberGraphTransform(text, compacted, assembledPayloadWhitespace)
		if m.replayPayload(text) == nil && m.replayPayload(compacted) == nil && m.reservePayloadBytes(cap(offsets)*int(reflect.TypeFor[int]().Size())) {
			m.compactSource, m.compactText, m.compactOffsets, m.compactReady = m.canonicalPayload(text), compacted, offsets, true
		}
		m.reassemblyDerive(text, compacted)
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
	// Normalized core keys cannot alias source-context lookup keys.
	normalizedCore bool
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
	mu            sync.Mutex
	store         decodingMemo
	lowered       map[string]int
	loweredValues []dlpLoweredBytes
	loweredBytes  int
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
	shared.mu.Lock()
	// A caller may still hold a released context. Its immutable computations
	// remain valid, but any entries it added belong to the old borrow.
	shared.store.reset()
	clear(shared.lowered)
	clear(shared.loweredValues)
	shared.loweredValues = shared.loweredValues[:0]
	shared.loweredBytes = 0
	shared.store.retainedBytes = cap(shared.loweredValues) * loweredViewSize
	shared.mu.Unlock()
	return context.WithValue(ctx, sharedDecodesKey{}, shared), func() {
		shared.mu.Lock()
		shared.store.reset()
		clear(shared.lowered)
		clear(shared.loweredValues)
		shared.loweredValues = shared.loweredValues[:0]
		shared.loweredBytes = 0
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
	m.reassemblyRecipeCache.release()
	m.reassemblyRecipeCache = nil
}

func sharedDecodesFrom(ctx context.Context) *sharedDecodes {
	if ctx == nil {
		return nil
	}
	shared, _ := ctx.Value(sharedDecodesKey{}).(*sharedDecodes)
	return shared
}

func (s *sharedDecodes) decode(key decodingMemoKey) ([]decodedResult, bool, bool) {
	s.mu.Lock()
	cached, ok := s.store.views[key]
	s.mu.Unlock()
	if ok {
		return cached.views, cached.complete, true
	}
	decoded, complete := decodeEncodingsForScan(key.text, key.includeURL, key.minPrefix, decodeBudgetMode{inbound: key.inbound, reportWorkLimits: key.reportWorkLimits}, nil)
	s.mu.Lock()
	s.store.retainDecode(key, decoded, complete)
	cached, retained := s.store.views[key]
	s.mu.Unlock()
	if retained {
		return cached.views, cached.complete, true
	}
	return decoded, complete, false
}

func (s *sharedDecodes) matchDecoded(key decodedMatchKey) []TextDLPMatch {
	filter := key.scanner.dlpPreFilter
	if key.core {
		filter = key.scanner.core.dlpPreFilter
	}
	if filter.rejectsUnnormalizedLength(key.text) {
		return nil
	}
	var normalized string
	if key.core {
		// Core matching consumes only normalized bytes. Configured matching
		// also consumes key.text as source context, and retains its exact key.
		normalized = s.normalize(key.text)
		key.text = normalized
		key.normalizedCore = true
	}
	s.mu.Lock()
	cached, ok := s.store.decodedMatches[key]
	s.mu.Unlock()
	if ok {
		return slices.Clone(cached)
	}
	if !key.core {
		normalized = s.normalize(key.text)
	}
	if !key.cardOnly && !filter.admitsLength(normalized) {
		s.mu.Lock()
		s.store.retainDecodedMatches(key, nil)
		s.mu.Unlock()
		return nil
	}
	var lowered dlpLoweredBytes
	if !key.cardOnly {
		lowered = s.loweredFor(normalized)
	}
	matches := key.match(normalized, &lowered)
	s.mu.Lock()
	s.store.retainDecodedMatches(key, matches)
	s.mu.Unlock()
	return slices.Clone(matches)
}

var loweredViewSize = int(reflect.TypeFor[dlpLoweredBytes]().Size())

// Return a value copy so releasing/recycling a message's store cannot mutate
// the byte summary an in-flight matcher is using.
func (s *sharedDecodes) loweredFor(text string) dlpLoweredBytes {
	s.mu.Lock()
	if index, ok := s.lowered[text]; ok {
		value := s.loweredValues[index]
		s.mu.Unlock()
		return value
	}
	s.mu.Unlock()
	var value dlpLoweredBytes
	value.add(text)
	s.mu.Lock()
	defer s.mu.Unlock()
	if index, ok := s.lowered[text]; ok {
		return s.loweredValues[index]
	}
	capacity := cap(s.loweredValues)
	if len(s.loweredValues) == capacity {
		capacity = min(maxDecodeCandidates, max(1, 2*capacity))
	}
	if len(s.loweredValues) >= maxDecodeCandidates || len(text) > maxDecodeTotalBytes-s.loweredBytes-capacity*loweredViewSize {
		return value
	}
	cost := len(text) + (capacity-cap(s.loweredValues))*loweredViewSize
	if cost > maxDecodeTotalBytes-s.store.retainedBytes {
		return value
	}
	if s.lowered == nil {
		s.lowered = make(map[string]int)
	}
	if capacity > cap(s.loweredValues) {
		values := make([]dlpLoweredBytes, len(s.loweredValues), capacity)
		copy(values, s.loweredValues)
		s.loweredValues = values
	}
	s.lowered[strings.Clone(text)] = len(s.loweredValues)
	s.loweredValues = append(s.loweredValues, value)
	s.loweredBytes += len(text)
	s.store.retainedBytes += cost
	return value
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
	if cached, retained := s.store.normalized[text]; retained {
		normalized = cached
	}
	s.mu.Unlock()
	return normalized
}

type memoDecode struct {
	views    []decodedResult
	complete bool
	sources  *keywordDecodeSources
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
	decoded = m.rememberGraphTransform(text, decoded, assembledPayloadHTML)
	m.reassemblyDerive(text, decoded)
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
	var mode decodeBudgetMode
	if m != nil {
		// Card-only outbound passes retain inbound accounting, but their work
		// stops must not create a new outbound refusal. The enclosing text scan
		// owns direction; standalone decode memos use their explicit inbound bit.
		mode = decodeBudgetMode{inbound: m.inbound, reportWorkLimits: m.inbound && (m.reassemblyPlan == nil || m.reassemblyInbound)}
	}
	if m != nil && m.keywordMode && minPrefix == 0 {
		key := decodingMemoKey{text: text, includeURL: includeURL, minPrefix: minPrefix, inbound: m.inbound, keyword: true, reportWorkLimits: mode.reportWorkLimits}
		if cached, ok := m.views[key]; ok {
			if cached.sources != nil {
				cached.sources.bindParents(text, m.keywordSources[text])
			}
			if !cached.complete {
				m.incomplete = true
			}
			if (cached.complete || m.inbound) && m.textualView(text) && !m.isTextRoot(text) {
				m.observeDecodedRecipe(key, cached.views, true)
			}
			return cached.views
		}
		sources := newKeywordDecodeSources(text)
		sources.budget = m.keywordBudgetForScan()
		if parents := m.keywordSources[text]; len(parents) > 0 {
			sources.bindParents(text, parents)
		}
		views, complete := decodeEncodingsForScan(text, includeURL, minPrefix, mode, sources)
		m.retainDecode(key, views, complete)
		if cached, ok := m.views[key]; ok {
			cached.sources = sources
			m.views[key] = cached
		}
		if m.keywordSources == nil {
			m.keywordSources = make(map[string][]*keywordDecodeSource)
		}
		for _, d := range views {
			if d.source != nil {
				m.keywordSources[d.text] = append(m.keywordSources[d.text], d.source)
				if normalized := m.normalizeUntracked(d.text); normalized != d.text {
					m.keywordSources[normalized] = append(m.keywordSources[normalized], d.source)
				}
			}
		}
		m.incomplete = m.incomplete || !complete
		if complete || m.inbound {
			_, retained := m.views[key]
			m.observeDecodedRecipe(key, views, retained)
		}
		return views
	}
	if m == nil {
		decoded, _ := decodeEncodingsFixpointMode(text, includeURL, minPrefix)
		return decoded
	}
	key := decodingMemoKey{text: text, includeURL: includeURL, minPrefix: minPrefix, inbound: m.inbound, reportWorkLimits: mode.reportWorkLimits}
	if m.shared != nil {
		decoded, complete, retained := m.shared.decode(key)
		if !complete {
			m.incomplete = true
		}
		if complete || m.inbound {
			kind, _ := m.viewKind(text)
			previous, observed := m.reassemblyDecoded[key]
			if !observed || !previous.textual() && kind.textual() {
				m.observeDecodedRecipe(key, decoded, retained)
				if m.replayPayload(text) == nil && (observed || len(m.reassemblyDecoded) < maxDecodeCandidates && len(text) <= maxDecodeTotalBytes-m.reassemblyDecodedBytes) {
					if m.reassemblyDecoded == nil {
						m.reassemblyDecoded = make(map[decodingMemoKey]assembledViewKind)
					}
					m.reassemblyDecoded[key] = kind
					if !observed {
						m.reassemblyDecodedBytes += len(text)
					}
				}
			}
		}
		return decoded
	}
	if cached, ok := m.views[key]; ok {
		if !cached.complete {
			m.incomplete = true
		}
		if (cached.complete || m.inbound) && m.textualView(text) && !m.isTextRoot(text) {
			m.observeDecodedRecipe(key, cached.views, true)
		}
		return cached.views
	}
	decoded, complete := decodeEncodingsForScan(text, includeURL, minPrefix, mode, nil)
	if !complete {
		m.incomplete = true
	}
	m.retainDecode(key, decoded, complete)
	_, retained := m.views[key]
	// An existing outbound refusal already decides this scan. Inbound keeps
	// its partial-view contract and never turns this skip into a refusal.
	if complete || m.inbound {
		m.observeDecodedRecipe(key, decoded, retained)
	}
	return decoded
}

func (m *decodingMemo) retainDecode(key decodingMemoKey, decoded []decodedResult, complete bool) {
	// Two scans sharing a store can both miss a key and both retain it. The
	// map keeps one entry, so only the first may charge the budget.
	if _, ok := m.views[key]; ok {
		return
	}
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
	normalized := m.normalizeUntracked(text)
	if m != nil {
		if !m.normalizedRetained(text) {
			m.replayTransformUnretained(text, normalized, assembledPayloadNormalize)
		}
		m.reassemblyDerive(text, normalized)
	}
	return normalized
}

// normalizeUntracked records no terminal ancestry. A decoded view's kind is
// set only after its decode completes; deriving before then would give a
// decoder view's normalization the text kind.
func (m *decodingMemo) normalizeUntracked(text string) string {
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
	if _, ok := m.normalized[text]; ok {
		return
	}
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
	if cached, ok := m.cachedDecodedMatches(full); ok && !m.keywordMode {
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
	if m != nil && m.keywordMode && !key.core {
		normalized := m.normalize(key.text)
		var lowered dlpLoweredBytes
		lowered.add(normalized)
		patterns := textDLPAllPatterns
		if key.cardOnly {
			patterns = textDLPCardPatterns
		}
		return key.scanner.matchDLPPatternsLoweredWithDecodes(normalized, key.encoding, key.text, &lowered, patterns, m)
	}
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

// textDLPMatchSize is the storage one retained match slot takes in its slice.
// Match strings are pattern labels shared with the scanner, so they are not
// charged again.
var textDLPMatchSize = int(reflect.TypeFor[TextDLPMatch]().Size())

func (m *decodingMemo) retainDecodedMatches(key decodedMatchKey, matches []TextDLPMatch) {
	if _, ok := m.decodedMatches[key]; ok {
		return
	}
	// The retained slice holds its whole backing array, spare capacity included.
	cost := len(key.text) + len(key.encoding) + cap(matches)*textDLPMatchSize
	if key.text == "" || len(m.decodedMatches) >= maxDecodeCandidates || cost > maxDecodeTotalBytes-m.decodedMatchesBytes || cost > maxDecodeTotalBytes-m.retainedBytes {
		return
	}
	if m.decodedMatches == nil {
		m.decodedMatches = make(map[decodedMatchKey][]TextDLPMatch)
	}
	m.decodedMatches[key] = matches
	m.decodedMatchesBytes += cost
	m.retainedBytes += cost
}

func (m *decodingMemo) keywordBudgetForScan() *keywordWorkBudget {
	if m.keywordBudget == nil {
		m.keywordBudget = &keywordWorkBudget{}
	}
	return m.keywordBudget
}
