// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"html"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func assembledMerge(result *reassemblyResult, more reassemblyResult) {
	result.findings = append(result.findings, more.findings...)
	result.incomplete = result.incomplete || more.incomplete
	result.stopped = result.stopped || more.stopped
}

// RFC 4648 hex has two nibble alignments. Adjacent raw alphabet symbols
// generate both byte streams in one pass; separators never advance symbols.
// The shared allowance charges each emitted byte before it enters a view.
func assembledHexViews(text string, budget *assembledBudget) (views [2]string) {
	charges := budget.chargesFor(text)
	var data [2][]byte
	capacity := min(len(text)/2, (maxDecodeTotalBytes-budget.used)/2)
	for phase := range data {
		data[phase] = make([]byte, 0, capacity)
	}
	previous := byte(0)
	symbols := 0
	nextCancel := responseBodyContextCheckBytes
	for i := range len(text) {
		if i >= nextCancel {
			nextCancel = i + responseBodyContextCheckBytes
			if budget.strideCanceled() {
				return views
			}
		}
		v := reassemblyCodecs[0].values[text[i]]
		if v < 0 {
			continue
		}
		nibble := byte(v & 15)
		if symbols > 0 {
			phase := (symbols - 1) & 1
			if !budget.charge(charges, 0, phase, (symbols-1)/2) {
				return views
			}
			data[phase] = append(data[phase], previous<<4|nibble)
		}
		previous = nibble
		symbols++
	}
	for phase := range views {
		views[phase] = string(data[phase])
	}
	return views
}

// This terminal adds one outer hex layer, with one shipped HTML or JSON
// escape transform after it. Inner search stays at one RFC layer. It does
// not recurse into another outer layer or claim other outer alphabets.
// The caller has proved the existing outer admission condition.
func assembledNestedHexAdmitted(p *reassemblyPlan, text string, budget *assembledBudget) (result reassemblyResult) {
	previousPolicy := budget.decoderOnly
	budget.decoderOnly = true
	defer func() { budget.decoderOnly = previousPolicy }()
	views := assembledHexViews(text, budget)
	if budget.incomplete {
		result.incomplete = true
		return result
	}
	if budget.stopped {
		result.stopped = true
		return result
	}
	for phase, view := range views {
		if budget.stopped {
			result.stopped = true
			break
		}
		if view == "" {
			continue
		}
		if budget.memo.keywordsActive() {
			budget.memo.registerReassemblyKeywordView(text, view, 0, phase)
		}
		more := assembledLayer(p, view, budget, 0)
		assembledMerge(&result, more)
		if budget.stopped || result.stopped {
			break
		}
		if budget.incomplete {
			break
		}
		var prior string
		for escape := 1; escape <= 2; escape++ {
			decoded := view
			if escape == 1 && strings.Contains(view, "&") {
				decoded = html.UnescapeString(view)
			}
			if escape == 2 && strings.Contains(view, `\u`) {
				decoded = normalize.DecodeJSONUnicodeEscapes(view)
			}
			if decoded == view || decoded == prior {
				continue
			}
			prior = decoded
			if budget.memo.keywordsActive() {
				encoding := encodingHTML
				if escape == 2 {
					encoding = encodingJSONUnicode
				}
				budget.memo.registerKeywordTransform(view, decoded, encoding)
			}
			remaining := maxDecodeTotalBytes - budget.used
			if len(decoded) > remaining {
				budget.used = maxDecodeTotalBytes
				budget.incomplete = true
				break
			}
			budget.used += len(decoded)
			encoding := encodingHTML
			if escape == 2 {
				encoding = encodingJSONUnicode
			}
			plain := assembledScan{p: p, text: decoded, budget: budget, encoding: encoding, viewLabel: spanViewLabel("reassembly", encodingHex, encoding)}
			for id, pattern := range p.patterns {
				pattern = p.assembled.terminalPattern(id, pattern)
				if pattern == nil {
					continue
				}
				if !p.assembled.decoderAllowed[id] || !budget.patterns.includes(pattern.genericCard) {
					continue
				}
				if pattern.keywords != nil && budget.memo != nil {
					copyPattern := *pattern
					copyPattern.keywordContext = &keywordCandidateContext{exactDecoded: true, sourceUnavailable: len(budget.memo.keywordSources[decoded]) == 0 && budget.memo.keywordBudget != nil && budget.memo.keywordBudget.incomplete, memo: budget.memo, source: budget.memo.keywordUnit, alternatives: budget.memo.keywordSources[decoded]}
					pattern = &copyPattern
				}
				start, end, ok := pattern.matchSpanInView(decoded, decoded)
				if !ok && pattern.keywords != nil && budget.memo != nil && (budget.memo.inspectionIncomplete() || budget.memo.keywordBudget != nil && budget.memo.keywordBudget.incomplete) {
					plain.keywordIncomplete()
				}
				if ok {
					plain.produce(id, decoded, start, end)
				}
			}
			assembledMerge(&result, plain.result)
			more = assembledLayer(p, decoded, budget, 0)
			assembledMerge(&result, more)
			if budget.stopped || result.stopped || budget.incomplete {
				break
			}
		}
		if budget.stopped || result.stopped || budget.incomplete {
			break
		}
	}
	if budget.stopped {
		result.stopped = true
		return result
	}
	result.incomplete = budget.incomplete
	return result
}

// RFC 4648 packs symbols most-significant-bit first. These overlapping raw
// windows test every possible outer byte alignment without retaining decoded
// streams. A true inner encoding needs nestedMinimum alphabet bytes. Any escape
// transform that changes a view needs '&' or '\\', so those bytes always admit.
// Separators never advance the outer symbol index or the inner-byte count.
func assembledOuterAdmits(p *reassemblyPlan, text string, codec int) bool {
	minimum := p.assembled.nestedMinimum
	if minimum == 0 {
		return true
	}
	c := &reassemblyCodecs[codec]
	var counts [8]int
	var window uint32
	symbols := 0
	for i := range len(text) {
		v := c.values[text[i]]
		if v < 0 {
			continue
		}
		window = window<<uint(c.width) | uint32(v)
		symbols++
		for phase := range c.quantum {
			bits := ((symbols - phase) & 7) * c.width
			// Every RFC alphabet here needs two symbols for its first byte.
			if symbols-phase < 2 || bits%8 >= c.width {
				continue
			}
			b := byte(window >> uint(bits%8) & 255)
			if b == '&' || b == '\\' {
				return true
			}
			// All five RFC alphabets are subsets of this exact byte union.
			if reassemblyAlphabet[b] {
				counts[phase]++
				if counts[phase] >= minimum {
					return true
				}
			}
		}
	}
	return false
}
