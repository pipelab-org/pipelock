// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

type assembledViewKind uint8

const (
	assembledInputView assembledViewKind = iota
	assembledTextView
	assembledDecoderView
)

func (k assembledViewKind) textual() bool { return k != assembledDecoderView }

func (m *decodingMemo) reassemblySetKind(text string, kind assembledViewKind) bool {
	if m == nil || !m.reassemblyDeferred && m.reassemblyPlan == nil {
		return false
	}
	// produce rejects binary ancestry only for decoder-disallowed patterns;
	// keyword-free plans admitting both kinds need no ancestry state.
	if m.reassemblyKindInsensitive {
		return true
	}
	text = m.canonicalPayload(text)
	if payload := m.replayPayload(text); payload != nil {
		previous, known := payload.kind, payload.known
		if !known || kind < previous {
			payload.kind, payload.known = kind, true
			if known && !previous.textual() && kind.textual() && !m.reassemblyDeferred && payload.pending >= 0 && payload.pending < m.reassemblyInspected {
				m.reassemblyInspect(payload.pending)
			}
		}
		return true
	}
	if m.reassemblyViewKinds == nil {
		m.assembledStorage()
	}
	if m.reassemblyViewKinds == nil {
		m.reassemblyViewKinds = make(map[string]assembledViewKind)
	}
	previous, known := m.reassemblyViewKinds[text]
	if !known || kind < previous {
		m.reassemblyViewKinds[text] = kind
		if known && !previous.textual() && kind.textual() && !m.reassemblyDeferred {
			if id, seen := m.reassemblySeen[text]; seen && id < m.reassemblyInspected {
				m.reassemblyInspect(id)
			}
		}
	}
	return true
}

// Text transformations inherit a binary origin. An independently established
// text path to exactly the same bytes can still supply textual eligibility.
func (m *decodingMemo) reassemblyDerive(source, text string) {
	if m != nil && m.reassemblyKindInsensitive {
		return
	}
	if m != nil && source == text {
		if _, known := m.viewKind(text); known {
			return
		}
	}
	if !m.reassemblySetKind(text, m.reassemblyDerivedKind(source)) {
		return
	}
	m.reassemblyParent(source, text)
}

func (m *decodingMemo) reassemblyParent(source, text string) {
	source, text = m.canonicalPayload(source), m.canonicalPayload(text)
	if source != text && m.reassemblyPlan != nil && m.reassemblyPlan.keywords {
		if _, known := m.viewKind(source); known {
			m.reassemblyParentFrom(source, text, m.replayPayload(source))
		}
	}
}

// The segment walker already resolved its parent's identity and kind. Reuse
// those exact results instead of hashing a whole document for each segment.
func (m *decodingMemo) reassemblyParentFrom(source, text string, parent *assembledPayload) {
	child := m.replayPayload(text)
	if child != nil || parent != nil {
		if _, exists := m.viewParent(text); exists {
			return
		}
		if parent == nil {
			parent = m.payloadSource(source)
		}
		if child != nil {
			child.contextParent = parent
		} else {
			if m.reassemblyReplayParents == nil {
				m.reassemblyReplayParents = make(map[string]*assembledPayload)
			}
			m.reassemblyReplayParents[text] = parent
		}
		return
	}
	if m.reassemblyParents == nil {
		m.reassemblyParents = make(map[string]string)
	}
	if _, exists := m.reassemblyParents[text]; !exists {
		m.reassemblyParents[text] = source
	}
}

// A parent keeps its origin while its segments are decoded. Resolve it once
// before walking those segments instead of hashing the parent for every edge.
func (m *decodingMemo) reassemblyDerivedKind(source string) assembledViewKind {
	if m == nil || m.reassemblyKindInsensitive {
		return assembledTextView
	}
	kind, known := m.viewKind(source)
	if !known || kind.textual() {
		return assembledTextView
	}
	return kind
}

// PartialEncodedContentPattern is non-enforcing evidence that an inbound
// terminal stopped at its existing decoded-byte allowance.
const PartialEncodedContentPattern = "Partial encoded content inspection"

func partialEncodedContentMatch() TextDLPMatch {
	return TextDLPMatch{PatternName: PartialEncodedContentPattern, Severity: config.SeverityHigh, Warn: true, informational: true}
}

type assembledSegmentSource struct {
	memo            *decodingMemo
	text            string
	replay          *assembledPayload
	kind            assembledViewKind
	known, borrowed bool
}

func (m *decodingMemo) reassemblySegmentSource(text string) assembledSegmentSource {
	source := assembledSegmentSource{memo: m, text: text, kind: assembledTextView}
	if m == nil {
		return source
	}
	source.text = m.canonicalPayload(text)
	source.replay = m.replayPayload(text)
	if !m.reassemblyKindInsensitive {
		kind, known := m.viewKind(text)
		source.known = known
		if known && !kind.textual() {
			source.kind = assembledDecoderView
		}
	}
	// The caller's segment slice already keeps these bytes alive. Borrow them
	// only for this walk; a deferred release also covers early match returns.
	if source.replay != nil && source.replay.current == "" {
		source.replay.current, source.borrowed = text, true
	}
	return source
}

func (s *assembledSegmentSource) release() {
	if s.borrowed {
		s.replay.current = ""
	}
}

func (s *assembledSegmentSource) observe(segment string) {
	m := s.memo
	if m == nil {
		return
	}
	if s.replay != nil && segment != s.text {
		start := strings.Index(s.text, segment)
		if start < 0 {
			m.markIncomplete()
			m.reassemblyIncomplete = true
			return
		}
		m.addReplayPayload(segment, &assembledPayload{parent: s.replay, operation: assembledPayloadSegment, start: start, end: start + len(segment)})
	}
	if m.reassemblyKindInsensitive {
		return
	}
	if m.reassemblySetKind(segment, s.kind) && s.known && s.text != segment && m.reassemblyPlan != nil && m.reassemblyPlan.keywords {
		m.reassemblyParentFrom(s.text, m.canonicalPayload(segment), s.replay)
	}
}
