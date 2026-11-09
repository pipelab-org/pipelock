// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"reflect"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// A rejected cache entry must not acquire a second payload owner in terminal
// metadata. Replay records refer to the existing decoder and its ordinal,
// preserving its exact admission order and work/completeness policy.
type assembledPayload struct {
	literal, current string
	decode           *assembledDecodeRecipe
	ordinal          int
	parent           *assembledPayload
	operation        assembledPayloadOperation
	start, end       int
	kind             assembledViewKind
	known, textRoot  bool
	digestSet        bool
	admitted         bool
	contextParent    *assembledPayload
	pending          int
	cache            *assembledRecipeCache
	digest           [sha256.Size]byte
}

type assembledDecodeRecipe struct {
	source     *assembledPayload
	includeURL bool
	minPrefix  int
	inbound    bool
	current    []decodedResult // borrowed while draining or held as the scan's one replayed decode
	cache      *assembledRecipeCache
}

// assembledRecipeCache holds the decoded views of at most one recipe and
// at most four source-sized transformed strings per scan. These transient
// transforms are not charged to retainedBytes and are released by
// finishAssembled. Sibling views share a walk or transform; replacing a slot
// releases its previous bytes, independently of the replay registry size.
type assembledRecipeCache struct {
	active *assembledDecodeRecipe
	text   [assembledHeldTexts]*assembledPayload
	next   int
}

// One scan replays segments of the raw, normalized and compacted texts
// against each other, so a single held transform would be evicted on every
// comparison. A few slots cover each distinct transform chain a scan builds.
const assembledHeldTexts = 4

func (r *assembledDecodeRecipe) hold(views []decodedResult) {
	c := r.cache
	if c == nil {
		return
	}
	if c.active != nil && c.active != r {
		c.active.current = nil
	}
	r.current = views
	c.active = r
}

func (p *assembledPayload) holdText(text string) {
	c := p.cache
	if c == nil || text == "" {
		return
	}
	for _, held := range c.text {
		if held == p {
			p.current = text
			return
		}
	}
	if old := c.text[c.next]; old != nil {
		old.current = ""
	}
	p.current = text
	c.text[c.next] = p
	c.next = (c.next + 1) % assembledHeldTexts
}

func (c *assembledRecipeCache) release() {
	if c == nil {
		return
	}
	if c.active != nil {
		c.active.current = nil
		c.active = nil
	}
	for i, held := range c.text {
		if held != nil {
			held.current = ""
			c.text[i] = nil
		}
	}
	c.next = 0
}

type assembledPayloadOperation uint8

const (
	assembledPayloadLiteral assembledPayloadOperation = iota
	assembledPayloadNormalize
	assembledPayloadHTML
	assembledPayloadWhitespace
	assembledPayloadSegment
	assembledPayloadRedactExamples
	assembledPayloadImageText
	assembledPayloadImageDecoded
)

type assembledPayloadKey struct {
	hash uint64
	size int
}

func assembledPayloadFingerprint(text string) assembledPayloadKey {
	hash := uint64(14695981039346656037)
	for i := range len(text) {
		hash = (hash ^ uint64(text[i])) * 1099511628211
	}
	return assembledPayloadKey{hash, len(text)}
}

// inspectionText verifies the bytes at an inspection boundary. Recursive
// recipe inputs do not rehash a whole parent for each small segment; the
// segment's own registered digest verifies the bytes passed to matching.
func (p *assembledPayload) inspectionText() (string, bool) {
	text, ok := p.materialize()
	if !ok || p.digestSet && sha256.Sum256([]byte(text)) != p.digest {
		return "", false
	}
	return text, true
}

func (p *assembledPayload) materialize() (string, bool) {
	if p.current != "" {
		return p.current, true
	}
	if p.decode != nil {
		views := p.decode.current
		if views == nil {
			source, ok := p.decode.source.materialize()
			if !ok {
				return "", false
			}
			views, _ = decodeEncodingsBudgetMode(source, p.decode.includeURL, p.decode.minPrefix, p.decode.inbound)
			p.decode.hold(views)
		}
		if p.ordinal < 0 || p.ordinal >= len(views) {
			return "", false
		}
		return views[p.ordinal].text, true
	}
	if p.operation == assembledPayloadLiteral {
		return p.literal, true
	}
	source, ok := p.parent.materialize()
	if !ok {
		return "", false
	}
	if p.operation == assembledPayloadSegment {
		if p.start < 0 || p.end > len(source) || p.end < p.start {
			return "", false
		}
		return source[p.start:p.end], true
	}
	// Segments of one transformed text replay in sequence, so the transform is
	// held instead of being recomputed over the whole source for each segment.
	text, ok := p.transform(source)
	if ok {
		p.holdText(text)
	}
	return text, ok
}

func (p *assembledPayload) transform(source string) (string, bool) {
	switch p.operation {
	case assembledPayloadNormalize:
		return normalize.ForDLP(source), true
	case assembledPayloadHTML:
		text, _ := decodeHTMLEntitiesChecked(source)
		return text, true
	case assembledPayloadWhitespace:
		return compactTextDLPWhitespace(source), true
	case assembledPayloadRedactExamples:
		return redactOfficialAWSExampleCredentialsForDocs(source), true
	case assembledPayloadImageText:
		return exciseVerifiedImageDataURLs(source), true
	case assembledPayloadImageDecoded:
		return exciseImagesRetainingDecodedForDLP(source), true
	default:
		return "", false
	}
}

// The fingerprint is only an index. Every hit compares the SHA-256 of the
// bytes the payload was registered for, so neither a fingerprint collision nor
// a different producing path can suppress inspection, and a lookup never
// rebuilds a payload's bytes. Replay itself still fails closed when a payload
// cannot reproduce its bytes (see pendingText).
func (m *decodingMemo) replayPayload(text string) *assembledPayload {
	if m == nil || len(m.reassemblyReplayPayloads) == 0 {
		return nil
	}
	candidates := m.reassemblyReplayPayloads[assembledPayloadFingerprint(text)]
	if len(candidates) == 0 {
		return nil
	}
	digest := sha256.Sum256([]byte(text))
	for _, payload := range candidates {
		if payload.digest == digest {
			return payload
		}
	}
	return nil
}

func (m *decodingMemo) payloadSource(text string) *assembledPayload {
	if payload := m.replayPayload(text); payload != nil {
		return payload
	}
	if id, ok := m.reassemblySeen[text]; ok {
		text = m.reassemblyPending[id]
	}
	return &assembledPayload{literal: text, pending: -1}
}

// Charge logical descriptor, index, recipe and source-wrapper sizes against
// the existing decode byte bound. Go map/allocator overhead, borrowed source
// strings and the transient transform cache remain separate from this charge;
// the bounded entry count prevents them growing per distinct decoded view.
var assembledReplayMetadataBytes = int(reflect.TypeFor[assembledPayload]().Size()*2 + reflect.TypeFor[assembledDecodeRecipe]().Size() + reflect.TypeFor[assembledPayloadKey]().Size() + reflect.TypeFor[[]*assembledPayload]().Size() + reflect.TypeFor[*assembledPayload]().Size())

func (m *decodingMemo) addReplayPayload(text string, payload *assembledPayload) *assembledPayload {
	if _, ok := m.reassemblySeen[text]; ok {
		return nil
	}
	if existing := m.replayPayload(text); existing != nil {
		return nil
	}
	// Replay descriptors are scan metadata, not another unbounded cache.
	// The existing decode byte limit bounds descriptors and their recipes.
	// Reaching it must retain the ordinary directional incomplete policy.
	if !m.reassemblyIncomplete && m.reassemblyReplayPayloadCount >= maxDecodeTotalBytes/assembledReplayMetadataBytes {
		m.trimReplayPayloads(payload)
	}
	if m.reassemblyIncomplete || m.reassemblyReplayPayloadCount >= maxDecodeTotalBytes/assembledReplayMetadataBytes {
		m.markIncomplete()
		m.reassemblyIncomplete = true
		return nil
	}
	if payload.cache == nil {
		payload.cache = m.recipeCache()
	}
	if m.reassemblyReplayPayloads == nil {
		m.reassemblyReplayPayloads = make(map[assembledPayloadKey][]*assembledPayload)
	}
	payload.pending = -1
	payload.digest = sha256.Sum256([]byte(text))
	payload.digestSet = true
	key := assembledPayloadFingerprint(text)
	m.reassemblyReplayPayloads[key] = append(m.reassemblyReplayPayloads[key], payload)
	m.reassemblyReplayPayloadCount++
	return payload
}

// Descriptors with no pending consumer are a lookup optimization. Reclaim
// them before refusing new work, while preserving the complete dependency
// graph of every pending view and the decoder walk currently being observed.
func (m *decodingMemo) trimReplayPayloads(incoming *assembledPayload) {
	// Reuse the terminal's exact admission walk. A view with no lane or
	// nested admission needs no future matching, regardless of keyword context
	// or a later textual-kind upgrade. This proof does not spend decode work.
	if m.reassemblyPlan != nil {
		// Preserve recipe order, like reassemblyDrain: neighboring decoded
		// views share one replay instead of evicting it in map iteration order.
		for id := m.reassemblyInspected; id < len(m.reassemblyPending); id++ {
			p := m.reassemblyPendingReplay[id]
			if p == nil {
				continue
			}
			text, ok := p.inspectionText()
			if !ok {
				m.markIncomplete()
				m.reassemblyIncomplete = true
				return
			}
			// Admission depends only on these digest-verified bytes and the
			// immutable plan. Do not rescan a large live parent at every trim.
			if p.admitted || m.reassemblyPlan.admitsAssembledView(text) {
				p.admitted = true
				continue
			}
			delete(m.reassemblyPendingReplay, id)
			m.reassemblyPending[id] = ""
			p.pending = -1
		}
	}
	// Before the deferred drain, no projection or keyword replay has consumed
	// an ID. Compact proven-empty slots so the pending index is bounded too.
	if m.reassemblyInspected == 0 {
		pending := m.reassemblyPending[:0]
		replays := make(map[int]*assembledPayload, len(m.reassemblyPendingReplay))
		for id, text := range m.reassemblyPending {
			p := m.reassemblyPendingReplay[id]
			if p == nil && text == "" {
				continue
			}
			next := len(pending)
			pending = append(pending, text)
			if p != nil {
				p.pending = next
				replays[next] = p
			} else {
				m.reassemblySeen[text] = next
			}
		}
		clear(m.reassemblyPending[len(pending):])
		m.reassemblyPending = pending
		m.reassemblyPendingReplay = replays
	}
	live := make(map[*assembledPayload]bool)
	var visit func(*assembledPayload)
	visit = func(p *assembledPayload) {
		if p == nil || live[p] {
			return
		}
		live[p] = true
		visit(p.parent)
		visit(p.contextParent)
		if p.decode != nil {
			visit(p.decode.source)
		}
	}
	for _, p := range m.reassemblyPendingReplay {
		visit(p)
	}
	for _, p := range m.reassemblyReplayParents {
		visit(p)
	}
	if cache := m.reassemblyRecipeCache; cache != nil {
		for _, p := range cache.text {
			visit(p)
		}
		if cache.active != nil {
			visit(cache.active.source)
		}
	}
	if incoming != nil {
		visit(incoming.parent)
		visit(incoming.contextParent)
		if incoming.decode != nil {
			visit(incoming.decode.source)
		}
	}
	for _, bucket := range m.reassemblyReplayPayloads {
		for _, p := range bucket {
			// A caller-owned borrow needs its descriptor until observation
			// ends. Known origin state can also be needed by a later transform,
			// even when these bytes have no terminal admission of their own.
			if p.current != "" || p.known {
				visit(p)
			}
		}
	}
	for key, bucket := range m.reassemblyReplayPayloads {
		kept := bucket[:0]
		for _, p := range bucket {
			if live[p] {
				kept = append(kept, p)
			}
		}
		clear(bucket[len(kept):])
		if len(kept) == 0 {
			delete(m.reassemblyReplayPayloads, key)
		} else {
			m.reassemblyReplayPayloads[key] = kept
		}
	}
	m.reassemblyReplayPayloadCount = 0
	for p := range live {
		if p.digestSet {
			m.reassemblyReplayPayloadCount++
		}
	}
}

func (m *decodingMemo) recipeCache() *assembledRecipeCache {
	if m.reassemblyRecipeCache == nil {
		m.reassemblyRecipeCache = new(assembledRecipeCache)
	}
	return m.reassemblyRecipeCache
}

func (m *decodingMemo) observeDecodedRecipe(key decodingMemoKey, views []decodedResult, retained bool) {
	if m.reassemblyIncomplete {
		return
	}
	if retained || len(views) == 0 || !m.reassemblyDeferred && m.reassemblyPlan == nil {
		m.reassemblyObserveDecoded(key.text, views)
		return
	}
	recipe := &assembledDecodeRecipe{source: m.payloadSource(key.text), includeURL: key.includeURL, minPrefix: key.minPrefix, inbound: key.inbound, cache: m.recipeCache()}
	var borrowed []*assembledPayload
	for ordinal, view := range views {
		if existing := m.replayPayload(view.text); existing != nil {
			if existing.current == "" {
				existing.current = view.text
				borrowed = append(borrowed, existing)
			}
			continue
		}
		payload := &assembledPayload{decode: recipe, ordinal: ordinal, current: view.text}
		if m.addReplayPayload(view.text, payload) != nil {
			borrowed = append(borrowed, payload)
		}
	}
	m.reassemblyObserveDecoded(key.text, views)
	// The decoder's caller still owns these strings while matching. Terminal
	// metadata keeps only recipes after observation returns.
	for _, payload := range borrowed {
		payload.current = ""
	}
}

// Computed projections join the same retention budget as decoded and
// normalized cache entries. A full cache switches ownership to a recipe,
// without changing which bytes the scanner inspects.
func (m *decodingMemo) rememberGraphTransform(source, text string, operation assembledPayloadOperation) string {
	if m == nil || m.reassemblyIncomplete || source == text || !m.reassemblyDeferred && m.reassemblyPlan == nil {
		return text
	}
	parent := m.replayPayload(source)
	if parent == nil && m.reservePayloadBytes(len(text)) {
		return text
	}
	if parent == nil {
		parent = m.payloadSource(source)
	}
	payload := &assembledPayload{parent: parent, operation: operation}
	m.addReplayPayload(text, payload)
	return text
}

func (m *decodingMemo) replayTransformUnretained(source, text string, operation assembledPayloadOperation) {
	if m == nil || m.reassemblyIncomplete || source == text || !m.reassemblyDeferred && m.reassemblyPlan == nil {
		return
	}
	m.addReplayPayload(text, &assembledPayload{parent: m.payloadSource(source), operation: operation})
}

func (m *decodingMemo) reservePayloadBytes(cost int) bool {
	owner := m
	if m.shared != nil {
		m.shared.mu.Lock()
		defer m.shared.mu.Unlock()
		owner = &m.shared.store
	}
	if cost > maxDecodeTotalBytes-owner.retainedBytes {
		return false
	}
	owner.retainedBytes += cost
	return true
}

func (m *decodingMemo) normalizedRetained(source string) bool {
	owner := m
	if m.shared != nil {
		m.shared.mu.Lock()
		defer m.shared.mu.Unlock()
		owner = &m.shared.store
	}
	_, ok := owner.normalized[source]
	return ok
}

func (m *decodingMemo) canonicalPayload(text string) string {
	if id, ok := m.reassemblySeen[text]; ok {
		return m.reassemblyPending[id]
	}
	return text
}

func (m *decodingMemo) borrowPending(view int, text string) func() {
	payload := m.reassemblyPendingReplay[view]
	if payload == nil || payload.current != "" {
		return func() {}
	}
	payload.current = text
	return func() { payload.current = "" }
}

func (m *decodingMemo) pendingText(view int) string {
	if payload := m.reassemblyPendingReplay[view]; payload != nil {
		text, ok := payload.inspectionText()
		if !ok {
			m.markIncomplete()
			m.reassemblyIncomplete = true
		}
		return text
	}
	return m.reassemblyPending[view]
}

func (m *decodingMemo) viewKind(text string) (assembledViewKind, bool) {
	if payload := m.replayPayload(text); payload != nil {
		return payload.kind, payload.known
	}
	kind, known := m.reassemblyViewKinds[text]
	return kind, known
}

func (m *decodingMemo) textualView(text string) bool {
	kind, _ := m.viewKind(text)
	return kind.textual()
}

func (m *decodingMemo) isTextRoot(text string) bool {
	if payload := m.replayPayload(text); payload != nil {
		return payload.textRoot
	}
	return m.reassemblyTextRoots[text]
}

func (m *decodingMemo) findView(text string) (int, bool) {
	if id, ok := m.reassemblySeen[text]; ok {
		return id, true
	}
	if payload := m.replayPayload(text); payload != nil {
		return payload.pending, payload.pending >= 0
	}
	return 0, false
}

func (m *decodingMemo) viewParent(text string) (string, bool) {
	var parent *assembledPayload
	if payload := m.replayPayload(text); payload != nil {
		parent = payload.contextParent
	} else {
		parent = m.reassemblyReplayParents[text]
	}
	if parent != nil {
		value, ok := parent.inspectionText()
		if !ok {
			m.markIncomplete()
			m.reassemblyIncomplete = true
		}
		return value, ok
	}
	value, ok := m.reassemblyParents[text]
	return value, ok
}

func (m *decodingMemo) parentLimit() int {
	return len(m.reassemblyParents) + len(m.reassemblyReplayParents) + m.reassemblyReplayPayloadCount
}
