// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// responseMatchMemo reuses only proven empty pattern results within one response
// scan. Core and configured patterns often repeat the same regex on the exact
// same normalized bytes. Positive results, attribution, spans, suppression and
// redaction are never cached here. The existing cross-request verdict cache is
// independent of this request-local optimization.
//
// Calls are sequential; the underlying matcher joins its workers before this
// object is read or written again. A Scanner never retains or shares the memo.
type responseMatchMemo struct {
	outboundMatch func(*compiledPattern, string) []ResponseMatch
	outboundErr   func() error
	views         map[string]map[responseNegativeKey]struct{}
	filterViews   map[string]*responsePreFilterView
	derivedBytes  int
	bytes         int
	entries       int
	matchingRoot  *matchingView
	chainWindows  *responseChainWindowMemo
	normalized    [matchingVowel + 1]responseNormalizedView
	deltaParent   *responseDeltaParent
	deltaProof    responseDeltaProof
	deltaViews    [matchingVowel + 1]*responseDeltaView
	deltaReady    [matchingVowel + 1]bool
}

func (m *responseMatchMemo) outboundError() error {
	if m == nil || m.outboundErr == nil {
		return nil
	}
	return m.outboundErr()
}

type responseNormalizedView struct {
	source, text string
	ready        bool
}

// Core and configured passes consume the same normalization of the same
// bytes. Keep one result per transform within their shared scan.
func (m *responseMatchMemo) normalize(text string, kind matchingTransform) string {
	if m == nil {
		return normalizeResponseMatchingView(text, kind)
	}
	view := &m.normalized[kind]
	if !view.ready || view.source != text {
		*view = responseNormalizedView{text, normalizeResponseMatchingView(text, kind), true}
	}
	return view.text
}

func normalizeResponseMatchingView(text string, kind matchingTransform) string {
	switch kind {
	case matchingPrimary:
		return normalize.ForMatching(text)
	case matchingSpaced:
		return normalize.ForMatchingSpaced(text)
	case matchingLeet:
		return normalize.Leetspeak(text)
	case matchingVowel:
		return normalize.FoldVowels(text)
	default:
		return text
	}
}

type responseNegativeKey struct {
	regex      string
	companions bool
	literals   string
}

const (
	responseMemoMinBytes   = 4096
	responseMemoMaxBytes   = 16 << 20
	responseMemoMaxViews   = 8
	responseMemoMaxEntries = 512
)

func newResponseMatchMemo(size int) *responseMatchMemo {
	if size < responseMemoMinBytes || size > responseMemoMaxBytes {
		return nil
	}
	return &responseMatchMemo{views: make(map[string]map[responseNegativeKey]struct{})}
}

func responseNegativePatternKey(p *compiledPattern) (responseNegativeKey, bool) {
	// Equal expression text alone does not establish the same syntax mode for
	// arbitrary regex objects. Only immutable response regexes built by our
	// regexp.Compile path can participate. Required-literal gates are part of
	// the identity: their negative means this exact matching pipeline was empty,
	// not necessarily that the standalone expression was empty.
	if p.responseMemoRegexp == nil || p.responseMemoRegexp != p.re {
		return responseNegativeKey{}, false
	}
	var literals strings.Builder
	for _, literal := range p.requiredLiteralsAny {
		literals.WriteString(strconv.Itoa(len(literal)))
		literals.WriteByte(':')
		literals.WriteString(literal)
	}
	return responseNegativeKey{regex: p.re.String(), companions: hasExternalTransferCompanions(p), literals: literals.String()}, true
}

func (m *responseMatchMemo) matchingView(kind matchingTransform, text string, program *matchingLiterals) *matchingView {
	if m == nil || program == nil {
		return nil
	}
	if kind != matchingPrimary {
		return m.matchingRoot.transformed(kind, text)
	}
	if m.matchingRoot == nil {
		m.matchingRoot = newMatchingView(text, program)
	}
	if root := m.matchingRoot; root != nil && root.text == text && root.program == program {
		return root
	}
	return nil
}

func (m *responseMatchMemo) matchTransformed(pf *responsePreFilter, patterns []*compiledPattern, content string, program *matchingLiterals, kind matchingTransform) []ResponseMatch {
	var delta *responseDeltaView
	if m != nil && m.deltaParent != nil {
		if !m.deltaReady[kind] {
			m.deltaViews[kind] = m.deltaParent.view(kind, content)
			m.deltaReady[kind] = true
		}
		delta = m.deltaViews[kind]
	}
	positions := m.matchingView(kind, content, program)
	if positions != nil {
		positions.responseChainWindows = m.chainWindows
	}
	result := m.matchPositioned(pf, patterns, content, positions, delta)
	if m != nil {
		m.deltaProof[kind] = m.views[content]
	}
	return result
}

func (m *responseMatchMemo) match(pf *responsePreFilter, patterns []*compiledPattern, content string) []ResponseMatch {
	return m.matchPositioned(pf, patterns, content, nil, nil)
}

func (m *responseMatchMemo) matchPositioned(pf *responsePreFilter, patterns []*compiledPattern, content string, positions *matchingView, delta *responseDeltaView) []ResponseMatch {
	if m.outboundError() != nil {
		return nil
	}
	if m == nil || len(content) < responseMemoMinBytes || len(content) > responseMemoMaxBytes {
		return matchPatternsPreFiltered(pf, patterns, content)
	}
	// String keys compare exact bytes, with no digest collision assumption.
	known := m.views[content]
	remaining := patterns
	remainingFilter := pf
	if len(known) > 0 {
		remaining = make([]*compiledPattern, 0, len(patterns))
		if pf != nil {
			remainingFilter = &responsePreFilter{windows: pf.windows, chains: pf.chains, deltaWidths: pf.deltaWidths}
		}
		for i, p := range patterns {
			key, eligible := responseNegativePatternKey(p)
			_, clean := known[key]
			if eligible && clean {
				continue
			}
			remaining = append(remaining, p)
			if pf != nil {
				remainingFilter.gates = append(remainingFilter.gates, pf.gates[i])
				if i < len(pf.proofs) {
					remainingFilter.proofs = append(remainingFilter.proofs, pf.proofs[i])
				} else {
					remainingFilter.proofs = append(remainingFilter.proofs, nil)
				}
				if i < len(pf.prefixes) {
					remainingFilter.prefixes = append(remainingFilter.prefixes, pf.prefixes[i])
				} else {
					remainingFilter.prefixes = append(remainingFilter.prefixes, nil)
				}
				if i < len(pf.companionProofs) {
					remainingFilter.companionProofs = append(remainingFilter.companionProofs, pf.companionProofs[i])
				} else {
					remainingFilter.companionProofs = append(remainingFilter.companionProofs, nil)
				}
			}
		}
	}
	if len(remaining) == 0 {
		return nil
	}
	view := m.filterViews[content]
	retained := view != nil && view.ready
	if !retained {
		var literals responseLiteralMemo
		if view != nil {
			literals = view.literals
		}
		view = &responsePreFilterView{literals: literals, outboundMatch: m.outboundMatch}
	}
	view.positions = positions
	view.delta = delta
	result := matchPatternsPreFilteredWithMemo(remainingFilter, remaining, content, view)
	view.positions = nil
	view.delta = nil
	if m.outboundError() != nil {
		return nil
	}
	if len(result) != 0 {
		return result
	}
	// Record only an entirely empty raw match result, before any caller can
	// remove defensive, suppressed or observed findings. A filtered finding
	// must never become evidence that the underlying regex had no match.
	if known == nil {
		if len(m.views) >= responseMemoMaxViews || m.bytes+len(content) > responseMemoMaxBytes || m.entries >= responseMemoMaxEntries {
			return nil
		}
		known = make(map[responseNegativeKey]struct{})
		m.views[content] = known
		m.bytes += len(content)
	}
	if m.filterViews == nil {
		m.filterViews = make(map[string]*responsePreFilterView)
	}
	if !retained {
		size := len(view.folded) + len(view.distance)
		if m.derivedBytes+size <= responseMemoMaxBytes {
			m.derivedBytes += size
		} else {
			view.folded, view.distance, view.ready = "", "", false
		}
	}
	m.filterViews[content] = view
	for _, p := range remaining {
		key, eligible := responseNegativePatternKey(p)
		if !eligible {
			continue
		}
		if _, exists := known[key]; exists {
			continue
		}
		if m.entries >= responseMemoMaxEntries {
			break
		}
		known[key] = struct{}{}
		m.entries++
	}
	return nil
}
