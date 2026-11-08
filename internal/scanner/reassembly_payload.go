// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"

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
	contextParent    *assembledPayload
	pending          int
}

type assembledDecodeRecipe struct {
	source     *assembledPayload
	includeURL bool
	minPrefix  int
	inbound    bool
	current    []decodedResult // borrowed only while draining this decoder's siblings
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

func (p *assembledPayload) materialize() (string, bool) {
	if p.current != "" {
		return p.current, true
	}
	if p.decode != nil {
		if p.decode.current != nil {
			if p.ordinal < 0 || p.ordinal >= len(p.decode.current) {
				return "", false
			}
			return p.decode.current[p.ordinal].text, true
		}
		source, ok := p.decode.source.materialize()
		if !ok {
			return "", false
		}
		views, _ := decodeEncodingsBudgetMode(source, p.decode.includeURL, p.decode.minPrefix, p.decode.inbound)
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
	switch p.operation {
	case assembledPayloadNormalize:
		return normalize.ForDLP(source), true
	case assembledPayloadHTML:
		text, _ := decodeHTMLEntitiesChecked(source)
		return text, true
	case assembledPayloadWhitespace:
		return compactTextDLPWhitespace(source), true
	case assembledPayloadSegment:
		if p.start < 0 || p.end > len(source) || p.end < p.start {
			return "", false
		}
		return source[p.start:p.end], true
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

// The fingerprint is only an index. Every hit compares replayed bytes, so
// neither a collision nor a different producing path can suppress inspection.
func (m *decodingMemo) replayPayload(text string) *assembledPayload {
	if m == nil || len(m.reassemblyReplayPayloads) == 0 {
		return nil
	}
	for _, payload := range m.reassemblyReplayPayloads[assembledPayloadFingerprint(text)] {
		value, ok := payload.materialize()
		if !ok {
			m.reassemblyIncomplete = true
			m.markIncomplete()
			continue
		}
		if value == text {
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

func (m *decodingMemo) addReplayPayload(text string, payload *assembledPayload) *assembledPayload {
	if _, ok := m.reassemblySeen[text]; ok {
		return nil
	}
	if existing := m.replayPayload(text); existing != nil {
		return nil
	}
	if m.reassemblyReplayPayloads == nil {
		m.reassemblyReplayPayloads = make(map[assembledPayloadKey][]*assembledPayload)
	}
	payload.pending = -1
	key := assembledPayloadFingerprint(text)
	m.reassemblyReplayPayloads[key] = append(m.reassemblyReplayPayloads[key], payload)
	m.reassemblyReplayPayloadCount++
	return payload
}

func (m *decodingMemo) observeDecodedRecipe(key decodingMemoKey, views []decodedResult, retained bool) {
	if retained || len(views) == 0 || !m.reassemblyDeferred && m.reassemblyPlan == nil {
		m.reassemblyObserveDecoded(key.text, views)
		return
	}
	recipe := &assembledDecodeRecipe{source: m.payloadSource(key.text), includeURL: key.includeURL, minPrefix: key.minPrefix, inbound: key.inbound}
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

func (m *decodingMemo) replayTransform(source, text string, operation assembledPayloadOperation) {
	if m == nil || source == text || !m.reassemblyDeferred && m.reassemblyPlan == nil {
		return
	}
	parent := m.replayPayload(source)
	if parent == nil {
		return
	}
	payload := &assembledPayload{parent: parent, operation: operation}
	if operation == assembledPayloadSegment {
		payload.start = strings.Index(source, text)
		payload.end = payload.start + len(text)
		if payload.start < 0 {
			m.markIncomplete()
			m.reassemblyIncomplete = true
			return
		}
	}
	m.addReplayPayload(text, payload)
}

// Computed projections join the same retention budget as decoded and
// normalized cache entries. A full cache switches ownership to a recipe,
// without changing which bytes the scanner inspects.
func (m *decodingMemo) rememberGraphTransform(source, text string, operation assembledPayloadOperation) string {
	if m == nil || source == text || !m.reassemblyDeferred && m.reassemblyPlan == nil {
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
	if operation == assembledPayloadSegment {
		payload.start = strings.Index(source, text)
		payload.end = payload.start + len(text)
	}
	m.addReplayPayload(text, payload)
	return text
}

func (m *decodingMemo) replayTransformUnretained(source, text string, operation assembledPayloadOperation) {
	if m == nil || source == text || !m.reassemblyDeferred && m.reassemblyPlan == nil {
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
		text, ok := payload.materialize()
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
		value, ok := parent.materialize()
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
