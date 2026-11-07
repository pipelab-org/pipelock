// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

type keywordPresenceKey struct {
	text       string
	gate       *config.DLPKeywordMatcher
	normalized bool
}

var keywordPresenceBytes = int(reflect.TypeFor[keywordPresenceKey]().Size() + reflect.TypeFor[bool]().Size())

// Keyword absence is a necessary-condition check, never a window decision.
// Sources pay for one normalized presence scan. Decoded lanes have already
// paid their byte traversal to the decoder allowance; only their cached
// predicate is retained here. Unknown or exhausted context remains eligible
// for the existing exact, fail-closed path.
func (m *decodingMemo) keywordPresent(gate *config.DLPKeywordMatcher, text string, decoded, normalized bool) bool {
	if text == "" {
		return false
	}
	logical := text
	if m == nil || decoded {
		if !normalized {
			logical = config.DLPKeywordContext(text)
		}
		return gate.MatchesAnywhere(logical)
	}
	key := keywordPresenceKey{text, gate, normalized}
	if present, ok := m.keywordPresence[key]; ok {
		return present
	}
	work := keywordDecodeSources{budget: m.keywordBudgetForScan()}
	// An unchanged raw unit can borrow the normalized unit's presence scan.
	// Keep both keys: DLP normalization is not generally idempotent.
	if !normalized {
		prior, known := m.keywordPresence[keywordPresenceKey{text, gate, true}]
		if known && keywordPresenceBytes <= maxDecodeTotalBytes-work.budget.used && config.DLPKeywordContext(text) == text {
			if !work.charge(keywordPresenceBytes) {
				m.markIncomplete()
				return true
			}
			m.keywordPresence[key] = prior
			return prior
		}
	}
	cost := keywordPresenceBytes + len(text)
	// This optional shortcut must not consume unavailable work. The exact
	// predicate can still complete using its existing proximity and maps.
	if cost > maxDecodeTotalBytes-work.budget.used || !work.charge(cost) {
		return true
	}
	if !normalized {
		logical = config.DLPKeywordContext(text)
	}
	present := gate.MatchesAnywhere(logical)
	if m.keywordPresence == nil {
		m.keywordPresence = make(map[keywordPresenceKey]bool)
	}
	m.keywordPresence[key] = present
	return present
}

func (c *keywordCandidateContext) keywordPossible(gate *config.DLPKeywordMatcher, logical string, sourceNormalized bool) (possible bool) {
	if present, ok := c.presence[gate]; ok {
		return present
	}
	defer func() {
		if c.presence == nil {
			c.presence = make(map[*config.DLPKeywordMatcher]bool)
		}
		c.presence[gate] = possible
	}()
	// Absence relies on the scan's tracked source units. An arbitrary
	// caller-supplied memo or unavailable projection keeps the exact path.
	if c.memo != nil && (!c.memo.keywordMode || c.memo.keywordURL != nil) || c.logicalUnavailable || c.sourceUnavailable {
		return true
	}
	if c.memo.keywordPresent(gate, logical, true, true) || (!sourceNormalized || c.source != logical) && c.memo.keywordPresent(gate, c.source, false, sourceNormalized) {
		return true
	}
	pending := append([]*keywordDecodeSource{c.decoded}, c.alternatives...)
	seen := make(map[*keywordDecodeSource]bool)
	for len(pending) > 0 {
		node := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if node == nil || seen[node] {
			continue
		}
		seen[node] = true
		if node.owner.incomplete || node.owner.budget.incomplete {
			return true
		}
		if c.memo.keywordPresent(gate, node.text, node.parent != nil, false) {
			return true
		}
		pending = append(pending, node.parent)
		pending = append(pending, node.variants...)
	}
	return false
}
