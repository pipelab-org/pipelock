// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"fmt"
	"reflect"
)

// Projection reuse keeps context-free candidates, not keyword decisions.
// Candidate retention and each replay spend the existing keyword work bound.
// Decoding, regular expressions and validators run once per projection.
type (
	assembledReplayKey        struct{ view, codec int }
	assembledKeywordCandidate struct {
		lane                       *assembledLane
		pattern, phase, begin, end int
	}
)

var assembledKeywordCandidateBytes = int(reflect.TypeFor[assembledKeywordCandidate]().Size())

func (s *assembledScan) rememberKeyword(lane *assembledLane, codec, phase, id, begin, end int) {
	m := s.budget.memo
	if m == nil || m.reassemblyPlan == nil {
		return
	}
	view, ok := m.reassemblySeen[s.text]
	if !ok {
		return
	} // Nested terminal layers have no projection reuse entry.
	key := assembledReplayKey{view, codec}
	candidates := m.assembledKeywordReplays[key]
	cost := 0
	capacity := cap(candidates)
	if len(candidates) == capacity {
		capacity = max(1, 2*capacity)
		cost += (capacity - cap(candidates)) * assembledKeywordCandidateBytes
	}
	if begin >= 0 && !lane.retained {
		cost += len(lane.view)
	}
	work := keywordDecodeSources{budget: m.keywordBudgetForScan()}
	if !work.charge(cost) {
		s.keywordIncomplete()
		return
	}
	if begin >= 0 {
		lane.retained = true
	} else {
		lane = nil
	}
	if m.assembledKeywordReplays == nil {
		m.assembledKeywordReplays = make(map[assembledReplayKey][]assembledKeywordCandidate)
	}
	if capacity > cap(candidates) {
		grown := make([]assembledKeywordCandidate, len(candidates), capacity)
		copy(grown, candidates)
		candidates = grown
	}
	m.assembledKeywordReplays[key] = append(candidates, assembledKeywordCandidate{lane, id, phase, begin, end})
}

func (m *decodingMemo) replayKeywords(view, previous, codec int) {
	candidates := m.assembledKeywordReplays[assembledReplayKey{previous, codec}]
	if len(candidates) == 0 || m.assembledSameSource(view, previous) {
		return
	}
	scan := assembledScan{p: m.reassemblyPlan, text: m.reassemblyPending[view], budget: &m.reassemblyBudget}
	// A source owns its mapping. Normalization maps of the immutable decoded
	// lane can still be shared, as can exact source-normalization results.
	lanes := make(map[*assembledLane]*assembledLane)
	for _, candidate := range candidates {
		work := keywordDecodeSources{budget: m.keywordBudgetForScan()}
		if !work.charge(assembledKeywordCandidateBytes) {
			scan.keywordIncomplete()
			break
		}
		pattern := m.reassemblyPlan.patterns[candidate.pattern]
		if scan.budget.decoderOnly && !scan.p.assembled.decoderAllowed[candidate.pattern] {
			continue
		}
		if candidate.begin < 0 {
			if scan.keywordPossible(pattern, &assembledLane{}) {
				// A newly labeled source may enumerate the previously absent lane.
				// Charge this rework before replay; cached presence cannot make
				// repeated whole-lane regex work free.
				if !work.charge(len(scan.text)) {
					scan.keywordIncomplete()
					break
				}
				scan.checked[codec] = make([]uint8, len(scan.p.patterns))
				scan.searchLane(codec, candidate.phase, candidate.pattern)
			}
			continue
		}
		identity := assembledIdentity{candidate.pattern, sha256.Sum256([]byte(candidate.lane.view[candidate.begin:candidate.end]))}
		if _, produced := m.reassemblyProduced[identity]; produced {
			continue
		}
		lane := lanes[candidate.lane]
		if lane == nil {
			copyLane := *candidate.lane
			copyLane.keywordMapped = false
			copyLane.presence = nil
			if copyLane.keyword != nil {
				context := *copyLane.keyword
				context.decoded = nil
				context.presence = nil
				copyLane.keyword = &context
			}
			lane = &copyLane
			lanes[candidate.lane] = lane
		}
		if scan.keywordMatches(pattern, lane, codec, candidate.phase, candidate.begin, candidate.end) {
			scan.encoding = reassemblyCodecs[codec].name
			scan.viewLabel = fmt.Sprintf("reassembly:%s:phase_%d", scan.encoding, candidate.phase)
			scan.produce(candidate.pattern, lane.view, candidate.begin, candidate.end)
		}
		if scan.budget.incomplete {
			break
		}
	}
	m.reassemblyFindings = append(m.reassemblyFindings, scan.result.findings...)
}

// A deletion-only projection derived from an already inspected source has
// the same source context. It must not shorten that source's keyword window.
func (m *decodingMemo) assembledSameSource(view, previous int) bool {
	text, prior := m.reassemblyPending[view], m.reassemblyPending[previous]
	work := keywordDecodeSources{budget: m.keywordBudgetForScan()}
	charge := func() bool {
		if work.charge(keywordSpanBytes) {
			return true
		}
		m.reassemblyBudget.incomplete = true
		m.markIncomplete()
		return false
	}
	for current, steps := text, 0; steps <= len(m.reassemblyParents); steps++ {
		if !charge() {
			return true
		}
		parent, ok := m.reassemblyParents[current]
		if !ok {
			break
		}
		if parent == prior {
			return true
		}
		current = parent
	}
	pending := append([]*keywordDecodeSource(nil), m.keywordSources[text]...)
	seen := make(map[*keywordDecodeSource]bool)
	for len(pending) > 0 {
		node := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if node == nil || seen[node] {
			continue
		}
		if !charge() {
			return true
		}
		seen[node] = true
		if node.text == prior {
			return true
		}
		pending = append(pending, node.parent)
		pending = append(pending, node.variants...)
	}
	return false
}
