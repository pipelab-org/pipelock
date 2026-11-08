// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
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
		if _, known := m.reassemblyViewKinds[text]; known {
			return
		}
	}
	if !m.reassemblySetKind(text, m.reassemblyDerivedKind(source)) {
		return
	}
	m.reassemblyParent(source, text)
}

func (m *decodingMemo) reassemblyParent(source, text string) {
	if source != text && m.reassemblyPlan != nil && m.reassemblyPlan.keywords {
		if _, known := m.reassemblyViewKinds[source]; known {
			if m.reassemblyParents == nil {
				m.reassemblyParents = make(map[string]string)
			}
			if _, exists := m.reassemblyParents[text]; !exists {
				m.reassemblyParents[text] = source
			}
		}
	}
}

// A parent keeps its origin while its segments are decoded. Resolve it once
// before walking those segments instead of hashing the parent for every edge.
func (m *decodingMemo) reassemblyDerivedKind(source string) assembledViewKind {
	if m == nil || m.reassemblyKindInsensitive {
		return assembledTextView
	}
	kind, known := m.reassemblyViewKinds[source]
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

// Segments retain the source ancestry used by keyword-window decisions.
func (m *decodingMemo) reassemblySegment(source, segment string, kind assembledViewKind) {
	if m != nil && m.reassemblyKindInsensitive {
		return
	}
	if m.reassemblySetKind(segment, kind) {
		m.reassemblyParent(source, segment)
	}
}
