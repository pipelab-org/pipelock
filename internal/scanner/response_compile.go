// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"slices"
	"sync"
)

// Keep one current syntax per configured or core response pattern group,
// replacing it when configuration changes, rather than accumulating a history
// of configuration or request content.
type responseSyntaxGroup uint8

const (
	responseSyntaxPrimary responseSyntaxGroup = iota
	responseSyntaxOptionalSpace
	responseSyntaxVowelFold
	responseSyntaxCorePrimary
	responseSyntaxCoreOptionalSpace
	responseSyntaxCoreVowelFold
	responseSyntaxGroups
)

type responseSyntaxKey struct {
	name, expression string
	windowRE         *regexp.Regexp
}

var responseSyntaxCache [responseSyntaxGroups]struct {
	sync.Mutex
	key    []responseSyntaxKey
	filter *responsePreFilter
}

func reusableResponsePreFilter(patterns []*compiledPattern, group responseSyntaxGroup) *responsePreFilter {
	key := make([]responseSyntaxKey, len(patterns))
	for id, pattern := range patterns {
		// Proven Perl patterns can carry window plans bound to the exact
		// compiled regexp. Rebuild if an eviction replaced that regexp.
		var windowRE *regexp.Regexp
		if pattern.responseMemoRegexp == pattern.re {
			windowRE = pattern.responseMemoRegexp
		}
		key[id] = responseSyntaxKey{pattern.name, pattern.re.String(), windowRE}
	}
	cache := &responseSyntaxCache[group]
	cache.Lock()
	defer cache.Unlock()
	if cache.filter == nil || !slices.Equal(key, cache.key) {
		cache.key, cache.filter = key, newResponsePreFilter(patterns)
	}
	// Gate syntax is immutable; lazy proof compilation is guarded by its Once.
	// Each scanner owns its slice headers and index lists. Findings, validators,
	// rule metadata and request-local literal memoization are never cached here.
	filter := *cache.filter
	filter.gates = slices.Clone(filter.gates)
	filter.proofs = slices.Clone(filter.proofs)
	filter.prefixes = slices.Clone(filter.prefixes)
	filter.alwaysRun = slices.Clone(filter.alwaysRun)
	filter.windowAnchors = slices.Clone(filter.windowAnchors)
	filter.companionProofs = slices.Clone(filter.companionProofs)
	for id, proofs := range filter.companionProofs {
		filter.companionProofs[id] = slices.Clone(proofs)
	}
	return &filter
}
