// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "github.com/luckyPipewrench/pipelock/internal/config"

type assembledViewKind uint8

const (
	assembledInputView assembledViewKind = iota
	assembledTextView
	assembledDecoderView
)

func (k assembledViewKind) textual() bool { return k != assembledDecoderView }

func (m *decodingMemo) reassemblySetKind(text string, kind assembledViewKind) {
	if m == nil || !m.reassemblyDeferred && m.reassemblyPlan == nil {
		return
	}
	if m.reassemblyViewKinds == nil {
		m.reassemblyViewKinds = make(map[string]assembledViewKind)
	}
	if previous, known := m.reassemblyViewKinds[text]; !known || kind < previous {
		m.reassemblyViewKinds[text] = kind
		if known && !previous.textual() && kind.textual() && !m.reassemblyDeferred {
			if id, seen := m.reassemblySeen[text]; seen && id < m.reassemblyInspected {
				m.reassemblyInspect(id)
			}
		}
	}
}

// Text transformations inherit a binary origin. An independently established
// text path to exactly the same bytes can still supply textual eligibility.
func (m *decodingMemo) reassemblyDerive(source, text string) {
	m.reassemblySetKind(text, m.reassemblyDerivedKind(source))
}

// A parent keeps its origin while its segments are decoded. Resolve it once
// before walking those segments instead of hashing the parent for every edge.
func (m *decodingMemo) reassemblyDerivedKind(source string) assembledViewKind {
	if m == nil {
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
