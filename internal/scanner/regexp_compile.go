// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"sync"
)

// Bound retention across arbitrary configuration reloads. The working set of
// built-in primary and transformed expressions fits here; eviction only costs
// recompilation. Entries contain syntax, never active rules or scanner policy.
const scannerRegexpCacheEntries = 512

type regexpCompileCache struct {
	mu          sync.Mutex
	expressions map[string]*regexp.Regexp
	order       []string
	next        int
}

var scannerRegexpCache regexpCompileCache

// compileScannerRegexp is exclusively the regexp.Compile (Perl, first-match)
// path. Inline flags are part of the exact source key. Callers must not mutate
// the returned expression with Longest; matching is safe across scanners.
func compileScannerRegexp(expression string) (*regexp.Regexp, error) {
	return scannerRegexpCache.compile(expression, scannerRegexpCacheEntries)
}

func (c *regexpCompileCache) compile(expression string, capacity int) (*regexp.Regexp, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if re := c.expressions[expression]; re != nil {
		return re, nil
	}
	// Serialize misses as well as publication, so concurrent New calls compile
	// a cold expression once. Errors are returned at the activation boundary
	// on every attempt, just as they are without a cache.
	re, err := regexp.Compile(expression)
	if err != nil {
		return nil, err
	}
	if c.expressions == nil {
		c.expressions = make(map[string]*regexp.Regexp)
	}
	if len(c.order) < capacity {
		c.order = append(c.order, expression)
	} else {
		delete(c.expressions, c.order[c.next])
		c.order[c.next] = expression
		c.next = (c.next + 1) % capacity
	}
	c.expressions[expression] = re
	return re, nil
}

// Derived expressions already came from valid syntax. Preserve
// regexp.MustCompile's panic for a programming error; configured source
// expressions use the error-returning path above.
func mustCompileScannerRegexp(expression string) *regexp.Regexp {
	re, err := compileScannerRegexp(expression)
	if err != nil {
		return regexp.MustCompile(expression)
	}
	return re
}
