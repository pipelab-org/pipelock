// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"slices"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

type reassemblyResult struct {
	findings   []TextDLPMatch
	incomplete bool
}

// reassemblyRemember joins the existing per-scan view graph. The projection index
// holds only these stable IDs, never another owning reference to a payload.
func (m *decodingMemo) reassemblyRemember(text string) (int, bool) {
	if id, ok := m.reassemblySeen[text]; ok {
		return id, false
	}
	if m.reassemblySeen == nil {
		m.assembledStorage()
	}
	if m.reassemblySeen == nil {
		m.reassemblySeen = make(map[string]int)
	}
	id := len(m.reassemblyPending)
	m.reassemblySeen[text] = id
	m.reassemblyPending = append(m.reassemblyPending, text)
	return id, true
}

// Exact text-preserving paths determine which views also admit configured
// class-only patterns. A result's last-edge label cannot establish its origin.
// Defaults and literal-qualified patterns retain every existing decoder view.
func (m *decodingMemo) reassemblyObserveDecoded(text string, decoded []decodedResult) {
	if m == nil || !m.reassemblyDeferred && (m.reassemblyPlan == nil || m.incomplete && !m.inbound) {
		return
	}
	m.reassemblyObserve(text)
	if len(decoded) == 0 {
		return
	}
	if m.reassemblyKindInsensitive {
		for _, view := range decoded {
			m.reassemblyObserveView(view.text, assembledTextView)
		}
		return
	}
	if m.reassemblyPlan != nil {
		minimum := m.reassemblyPlan.assembled.nestedMinimum
		longEnough := false
		for _, view := range decoded {
			longEnough = longEnough || len(view.text) >= minimum
		}
		if !longEnough {
			return
		}
	}
	// Only the textual escape transforms can give an existing decoder result
	// textual ancestry. Without their introducers every result is binary.
	if !strings.ContainsAny(text, "%+&\\") {
		for _, view := range decoded {
			m.reassemblyObserveView(view.text, assembledDecoderView)
		}
		return
	}
	// This selects from already admitted graph results; it adds no decoder,
	// candidate, budget, or terminal recursion. Exact byte equality also admits
	// a textual path when a binary path happened to reach the same result first.
	remaining := make(map[string]struct{}, len(decoded))
	for _, view := range decoded {
		if view.text != text {
			remaining[view.text] = struct{}{}
		}
	}
	pending := []string{text}
	textRoot := m.reassemblyViewKinds[text].textual()
	if textRoot {
		if m.reassemblyTextRoots == nil {
			m.reassemblyTextRoots = make(map[string]bool)
		}
		m.reassemblyTextRoots[text] = true
	}
	eligible := make(map[string]struct{})
	for head := 0; head < len(pending) && len(remaining) > 0; head++ {
		source := pending[head]
		admit := func(view string) {
			if _, ok := remaining[view]; !ok {
				return
			}
			delete(remaining, view)
			pending = append(pending, view)
			eligible[view] = struct{}{}
		}
		// These are the text transforms in decodeEncodingsOnceInto. Binary
		// alphabets remain solely in the ordinary decoder and admitted nested hex.
		if strings.ContainsAny(source, "%+") {
			admit(IterativeDecode(source))
		}
		if strings.Contains(source, "&") {
			view, _ := decodeHTMLEntitiesChecked(source)
			admit(view)
		}
		if strings.Contains(source, `\u`) {
			admit(normalize.DecodeJSONUnicodeEscapes(source))
		}
	}
	// Selection removes graph views without changing the order of those kept.
	// Their order also determines which confirmation spends the shared budget.
	for _, view := range decoded {
		_, textual := eligible[view.text]
		kind := assembledDecoderView
		if textRoot && textual {
			kind = assembledTextView
		}
		m.reassemblyObserveView(view.text, kind)
	}
}

func (m *decodingMemo) reassemblyObserve(text string) {
	if m == nil {
		return
	}
	kind, known := m.reassemblyViewKinds[text]
	if !known {
		kind = assembledInputView
	}
	m.reassemblyObserveView(text, kind)
}

func (m *decodingMemo) reassemblyObserveView(text string, kind assembledViewKind) {
	if m == nil {
		return
	}
	if !m.reassemblyDeferred && (m.reassemblyPlan == nil || m.incomplete && !m.inbound) {
		return
	}
	// shapeMinLen is a lower bound in runes, hence also in UTF-8 bytes.
	// RFC 4648's widest alphabet needs ceil(8*m/6) symbols for m bytes.
	// Neither the outer hex nor the single escape pass can expand this bound.
	if m.reassemblyPlan != nil && len(text) < m.reassemblyPlan.assembled.nestedMinimum {
		return
	}
	if !m.reassemblySetKind(text, kind) {
		return
	}
	if m.reassemblyPlan != nil && !assembledEnoughSymbols(text, m.reassemblyPlan.assembled.nestedMinimum) {
		return
	}
	if m.reassemblyPlan != nil && m.reassemblyPlan.emptyTerminal(assembledEmptyKey{m.reassemblyPlan, text, m.reassemblyPatternLimit, false}, false) {
		return
	}
	_, fresh := m.reassemblyRemember(text)
	if !fresh || m.reassemblyDeferred {
		return
	}
	m.reassemblyDrain()
}

// Each admitted match needs nestedMinimum symbols even in RFC 4648's widest
// alphabet. The union over all five alphabets can only overcount a lane.
// Outer hex and the admitted escape transforms cannot expand its symbol count.
func assembledEnoughSymbols(text string, minimum int) bool {
	if minimum <= 0 {
		return true
	}
	for i := range len(text) {
		if reassemblyAlphabet[text[i]] {
			minimum--
			if minimum == 0 {
				return true
			}
		}
	}
	return false
}

func (m *decodingMemo) reassemblyDrain() {
	for m.reassemblyInspected < len(m.reassemblyPending) {
		id := m.reassemblyInspected
		m.reassemblyInspected++
		m.reassemblyInspect(id)
	}
}

func (m *decodingMemo) reassemblyInspect(view int) {
	if m.reassemblyPlan == nil || m.reassemblyIncomplete || m.incomplete && !m.inbound {
		return
	}
	text := m.reassemblyPending[view]
	key := assembledEmptyKey{m.reassemblyPlan, text, m.reassemblyPatterns, !m.reassemblyViewKinds[text].textual()}
	if m.reassemblyPlan.emptyTerminal(key, false) {
		return
	}
	budget := &m.reassemblyBudget
	*budget = assembledBudget{memo: m, used: m.assembledBytes, produced: m.reassemblyProduced, patterns: m.reassemblyPatterns, decoderOnly: !m.reassemblyViewKinds[text].textual(), charged: m.assembledCharged, registry: m.assembledChargeRegistry}
	skip := m.assembledSkip(view)
	r := assembledLayer(m.reassemblyPlan, text, budget, skip)
	nested := m.reassemblyPlan.assembled.nestedHex && skip&1 == 0 && !budget.incomplete && assembledOuterAdmits(m.reassemblyPlan, text, 0)
	if nested {
		if m.reassemblyNestedDeferred {
			m.reassemblyNestedPending = append(m.reassemblyNestedPending, view)
		} else {
			more := assembledNestedHexAdmitted(m.reassemblyPlan, text, budget)
			assembledMerge(&r, more)
		}
	}
	if skip == 0 && !nested && !budget.admitted && !budget.incomplete {
		m.reassemblyPlan.emptyTerminal(key, true)
	}
	m.assembledBytes = budget.used
	m.assembledCharged = budget.charged
	m.assembledChargeRegistry = budget.registry
	if r.incomplete {
		m.reassemblyIncomplete = true
		if !m.inbound {
			m.markIncomplete()
		}
	}
	m.reassemblyFindings = append(m.reassemblyFindings, r.findings...)
}

type assembledEmptyKey struct {
	plan        *reassemblyPlan
	text        string
	patterns    textDLPPatternSet
	decoderOnly bool
}

// Only complete inspections that admitted no lane and no nested terminal are
// reusable without replaying candidates, keyword context or allowance charges.
func (s *reassemblyPlan) emptyTerminal(key assembledEmptyKey, remember bool) bool {
	if !remember {
		s.emptyMu.RLock()
		_, ok := s.emptyTerminals[key]
		s.emptyMu.RUnlock()
		return ok
	}
	s.emptyMu.Lock()
	defer s.emptyMu.Unlock()
	if _, ok := s.emptyTerminals[key]; ok {
		return true
	}
	if remember && len(s.emptyTerminals) < maxDecodeCandidates && len(key.text) <= maxDecodeTotalBytes-s.emptyTerminalBytes {
		if s.emptyTerminals == nil {
			s.emptyTerminals = make(map[assembledEmptyKey]struct{})
		}
		// A segment must not retain the larger response it was sliced from.
		key.text = strings.Clone(key.text)
		s.emptyTerminals[key] = struct{}{}
		s.emptyTerminalBytes += len(key.text)
	}
	return false
}

// finishAssembled gives the complete text scan sole ownership of terminal
// production. Regular producers keep their existing ordering and occurrence
// counts. Exact value identities enter the terminal producer before scanning,
// so one matched value cannot create the same finding twice.
func finishAssembled(result TextDLPResult, memos ...*decodingMemo) TextDLPResult {
	var fallback assembledAllowance
	for _, m := range memos {
		if m == nil || m.reassemblyPlan == nil {
			continue
		}
		if len(m.reassemblyPending) == 0 && !m.inspectionIncomplete() {
			continue
		}
		if m.assembledAllowance == nil {
			m.assembledAllowance = &fallback
		}
		allowance := m.assembledAllowance
		m.assembledBytes = max(m.assembledBytes, allowance.used)
		m.assembledCharged = allowance.charged
		m.assembledChargeRegistry = allowance.registry
		m.reassemblyProduced = make(map[assembledIdentity]struct{})
		for id, p := range m.reassemblyPlan.patterns {
			for _, matches := range [][]TextDLPMatch{result.Matches, result.InformationalMatches} {
				for _, match := range matches {
					if p.name == match.PatternName && match.hasValueIdentity {
						m.reassemblyProduced[assembledIdentity{pattern: id, value: match.valueIdentity}] = struct{}{}
					}
				}
			}
		}
		m.reassemblyDeferred = false
		m.inbound = m.reassemblyInbound
		m.reassemblyNestedDeferred = true
		m.reassemblyDrain()
		m.reassemblyNestedDeferred = false
		for _, view := range m.reassemblyNestedPending {
			text := m.reassemblyPending[view]
			if m.incomplete && !m.inbound {
				break
			}
			budget := &m.reassemblyBudget
			*budget = assembledBudget{memo: m, used: m.assembledBytes, produced: m.reassemblyProduced, patterns: m.reassemblyPatterns, decoderOnly: !m.reassemblyViewKinds[text].textual(), charged: m.assembledCharged, registry: m.assembledChargeRegistry}
			more := assembledNestedHexAdmitted(m.reassemblyPlan, text, budget)
			m.assembledBytes = budget.used
			m.assembledCharged = budget.charged
			m.assembledChargeRegistry = budget.registry
			m.reassemblyFindings = append(m.reassemblyFindings, more.findings...)
			if more.incomplete {
				m.reassemblyIncomplete = true
				if !m.inbound {
					m.markIncomplete()
				}
			}
		}
		m.reassemblyNestedPending = nil
		for _, match := range m.reassemblyFindings {
			if match.Warn {
				result.InformationalMatches = append(result.InformationalMatches, match)
			} else {
				result.Matches = append(result.Matches, match)
			}
		}
		m.reassemblyFindings = nil
		allowance.used = m.assembledBytes
		allowance.charged = m.assembledCharged
		allowance.registry = m.assembledChargeRegistry
		if m.inbound && m.reassemblyIncomplete && !slices.ContainsFunc(result.Matches, func(match TextDLPMatch) bool { return match.PatternName == PartialEncodedContentPattern }) {
			result.Matches = append(result.Matches, partialEncodedContentMatch())
		}
		if !m.inbound && m.inspectionIncomplete() && !HasInspectionLimit(result.Matches) {
			result.Matches = append(result.Matches, uninspectableEncodedContentMatch())
		}
	}
	result.Clean = !result.Incomplete && !HasEnforcingMatch(result.Matches)
	return result
}
