// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"sync"
)

// Scanner rebuilds share compiled expressions. The cache holds syntax only,
// never rules or policy. It is bounded in size, and an expression that no
// successful build has used for scannerRegexpIdleBuilds builds is dropped, so
// patterns removed from configuration do not stay cached.
const (
	scannerRegexpCacheEntries = 512
	scannerRegexpIdleBuilds   = 8
)

type cachedRegexp struct {
	re        *regexp.Regexp
	lastBuild uint64
}

type regexpCompileCache struct {
	mu          sync.Mutex
	expressions map[string]*cachedRegexp
	builds      uint64
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
	if entry := c.expressions[expression]; entry != nil {
		entry.lastBuild = c.builds
		return entry.re, nil
	}
	// Serialize misses as well as publication, so concurrent New calls compile
	// a cold expression once. Errors are returned at the activation boundary
	// on every attempt, just as they are without a cache.
	re, err := regexp.Compile(expression)
	if err != nil {
		return nil, err
	}
	if c.expressions == nil {
		c.expressions = make(map[string]*cachedRegexp)
	}
	if len(c.expressions) >= capacity {
		c.evictLeastRecent()
	}
	c.expressions[expression] = &cachedRegexp{re: re, lastBuild: c.builds}
	return re, nil
}

func (c *regexpCompileCache) evictLeastRecent() {
	var oldest string
	var oldestBuild uint64
	first := true
	for expression, entry := range c.expressions {
		if first || entry.lastBuild < oldestBuild {
			oldest, oldestBuild, first = expression, entry.lastBuild, false
		}
	}
	delete(c.expressions, oldest)
}

// finishBuild marks one successful scanner construction and drops expressions
// that no build has used within the idle window. A live scanner keeps its own
// pointers, so a dropped expression only costs a later recompile.
func (c *regexpCompileCache) finishBuild(idle uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.builds++
	for expression, entry := range c.expressions {
		if c.builds-entry.lastBuild > idle {
			delete(c.expressions, expression)
		}
	}
}

// Derived expressions already came from valid syntax; an error here is a
// programming error. Configured source expressions use compileScannerRegexp.
func mustCompileScannerRegexp(expression string) *regexp.Regexp {
	re, err := compileScannerRegexp(expression)
	if err != nil {
		panic(err)
	}
	return re
}
