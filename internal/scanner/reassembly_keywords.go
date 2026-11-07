// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"

	"golang.org/x/text/unicode/norm"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// keywordMatches joins the existing context predicate. Exact RFC bit positions
// supply source hulls; separators retain their original distance. Source maps
// use the existing keyword work budget and are built only after decoded context
// fails to qualify a candidate.
func (s *assembledScan) keywordMatches(pattern *compiledPattern, lane *assembledLane, codec, phase, start, end int) bool {
	if pattern.keywords == nil {
		return true
	}
	if s.budget.memo == nil {
		s.budget.memo = &decodingMemo{keywordMode: true}
	}
	if lane.keyword == nil {
		lane.keyword = &keywordCandidateContext{exactDecoded: true, logical: config.DLPKeywordContext(lane.view), memo: s.budget.memo}
		if s.budget.memo != nil {
			lane.keyword.source = s.budget.memo.keywordUnit
		}
	}
	if lane.keyword.matches(pattern.keywords, lane.view, start, end) {
		return true
	}
	if !lane.keywordMapped {
		lane.keywordMapped = true
		memo := s.budget.memo
		if memo == nil {
			memo = &decodingMemo{keywordMode: true}
		}
		node := memo.registerReassemblyKeywordView(s.text, lane.view, codec, phase)
		if node == nil {
			s.keywordIncomplete()
			return false
		}
		lane.keyword.decoded = node
	}
	matched := lane.keyword.matches(pattern.keywords, lane.view, start, end)
	if !matched && (s.budget.memo.inspectionIncomplete() || lane.keyword.decoded != nil && (lane.keyword.decoded.owner.incomplete || lane.keyword.decoded.owner.budget.incomplete)) {
		s.keywordIncomplete()
	}
	return matched
}

func (s *assembledScan) keywordIncomplete() {
	s.budget.incomplete = true
	s.result.incomplete = true
	if s.budget.memo != nil {
		s.budget.memo.markIncomplete()
	}
}

// Mirror keywordNormalizedSpan in the forward direction. Whole normalization
// segments own the candidate hull, so combining characters cannot become
// independent corroborating context. Equality with the real normalizer is
// required, including when unrelated bytes in an exact lane are invalid UTF-8.
func (c *keywordCandidateContext) assembledNormalizedSpan(source, logical string, start, end int) (int, int, bool) {
	if start < 0 || end <= start || end > len(source) {
		return 0, 0, false
	}
	if source == logical {
		return start, end, true
	}
	key := keywordProjectionKey{source: source, view: logical}
	offsets, found := c.projections[key]
	if !found {
		if c.projections == nil {
			c.projections = make(map[keywordProjectionKey][]keywordByteSpan)
		}
		c.projections[key] = nil
		budget := keywordDecodeSources{budget: c.memo.keywordBudgetForScan()}
		if len(source) > maxDecodeTotalBytes/keywordSpanBytes || !budget.charge(len(source)*keywordSpanBytes) || !budget.charge(len(logical)) {
			c.memo.markIncomplete()
			return 0, 0, false
		}
		offsets = assembledKeywordNormalizationOffsets(source, logical)
		c.projections[key] = offsets
	}
	if len(offsets) != len(source) {
		return 0, 0, false
	}
	first, last := offsets[start].start, offsets[end-1].end
	return first, last, last > first
}

func assembledKeywordNormalizationOffsets(source, logical string) []keywordByteSpan {
	var iter norm.Iter
	iter.InitString(norm.NFKC, source)
	var b strings.Builder
	offsets := make([]keywordByteSpan, len(source))
	for !iter.Done() {
		a := iter.Pos()
		_ = iter.Next()
		z := iter.Pos()
		before := b.Len()
		b.WriteString(config.DLPKeywordContext(source[a:z]))
		for i := a; i < z; i++ {
			offsets[i] = keywordByteSpan{before, b.Len()}
		}
	}
	if b.String() != logical {
		return nil
	}
	return offsets
}

// The keyword source graph owns lazy maps and charges them to its existing
// work bound. RFC phase coordinates identify the same bytes as the lane replay.
type assembledKeywordBits struct{ codec, phase int }

func (m *decodingMemo) registerReassemblyKeywordView(source, view string, codec, phase int) *keywordDecodeSource {
	graph := newKeywordDecodeSources(source)
	graph.budget = m.keywordBudgetForScan()
	graph.bindParents(source, m.keywordSources[source])
	node := graph.add(source, view, "reassembly")
	if node == nil {
		return nil
	}
	if node.parent != nil && source != view {
		node.reassembly = &assembledKeywordBits{codec, phase}
	}
	if m.keywordSources == nil {
		m.keywordSources = make(map[string][]*keywordDecodeSource)
	}
	m.keywordSources[view] = append(m.keywordSources[view], node)
	return node
}

func (bits assembledKeywordBits) offsets(source, view string) []keywordByteSpan {
	offsets := make([]keywordByteSpan, len(view))
	c := reassemblyCodecs[bits.codec]
	raw, symbol, at := 0, -1, 0
	valid := true
	assembledReplay(source, bits.codec, 0, len(source), uint8(bits.phase*c.width&0xff), func(b byte, rawEnd int) bool {
		if at >= len(view) || b != view[at] {
			valid = false
			return false
		}
		first := (bits.phase*c.width + at*8) / c.width
		for symbol < first {
			if symbol >= 0 {
				raw++
			}
			for c.values[source[raw]] < 0 {
				raw++
			}
			symbol++
		}
		offsets[at] = keywordByteSpan{raw, rawEnd}
		at++
		return true
	})
	if !valid || at != len(view) {
		return nil
	}
	return offsets
}

// Source-only labels follow the same DLP normalization as decoded labels.
// Keep successful and failed normalization in the existing scan-local context;
// another candidate must not repeat a failed or already-charged whole-source pass.
func (c *keywordCandidateContext) assembledSourceKeyword(gate *config.DLPKeywordMatcher, source string, start, end int) bool {
	logical, found := c.exactSources[source]
	if !found {
		c.exactSources[source] = nil
		budget := keywordDecodeSources{budget: c.memo.keywordBudgetForScan()}
		if !budget.charge(len(source)) {
			c.memo.markIncomplete()
			return false
		}
		text := config.DLPKeywordContext(source)
		if !budget.charge(len(text) + keywordSpanBytes) {
			c.memo.markIncomplete()
			return false
		}
		logical = &text
		c.exactSources[source] = logical
	}
	if logical == nil {
		c.memo.markIncomplete()
		return false
	}
	normalStart, normalEnd, ok := c.assembledNormalizedSpan(source, *logical, start, end)
	return ok && gate.Matches(*logical, normalStart, normalEnd)
}
