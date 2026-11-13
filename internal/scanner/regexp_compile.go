// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"regexp"
	"runtime"
	"sync"
)

// Bound one construction that compiles more expressions than it retains.
// Eviction only costs recompilation. A successful build then drops expressions
// it did not compile, so removed configuration is not retained. Entries contain
// syntax, never active rules or policy.
const scannerRegexpCacheEntries = 512

type regexpCompileCache struct {
	mu          sync.Mutex
	expressions map[string]*regexp.Regexp
	order       []string
	next        int
}

var scannerRegexpCache regexpCompileCache

// regexpScope is the set of expressions compiled by one scanner construction.
// Removed configuration must not remain cached after a later successful build,
// and a failed build must not publish expressions that belong to no scanner.
type regexpScope struct {
	mu    sync.Mutex
	used  map[string]struct{}
	added map[string]struct{}
}

var regexpScopes sync.Map // goroutine id -> *regexpScope

// compileScannerRegexp is exclusively the regexp.Compile (Perl, first-match)
// path. Inline flags are part of the exact source key. Callers must not mutate
// the returned expression with Longest; matching is safe across scanners.
func compileScannerRegexp(expression string) (*regexp.Regexp, error) {
	return scannerRegexpCache.compile(expression, scannerRegexpCacheEntries, currentRegexpScope())
}

func (c *regexpCompileCache) compile(expression string, capacity int, scope *regexpScope) (*regexp.Regexp, error) {
	// Mark the expression in use before it is published. A concurrent build
	// keeps in-flight expressions, and must see this one before insertion.
	scope.note(expression, false)
	c.mu.Lock()
	if re := c.expressions[expression]; re != nil {
		c.mu.Unlock()
		return re, nil
	}
	// Serialize misses as well as publication, so concurrent New calls compile
	// a cold expression once. Errors are returned at the activation boundary
	// on every attempt, just as they are without a cache.
	re, err := regexp.Compile(expression)
	if err != nil {
		c.mu.Unlock()
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
	c.mu.Unlock()
	scope.note(expression, true)
	return re, nil
}

func (s *regexpScope) note(expression string, added bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.used[expression] = struct{}{}
	if added {
		s.added[expression] = struct{}{}
	}
	s.mu.Unlock()
}

// beginScannerRegexpScope records expressions compiled on this goroutine until
// the returned function runs. kept keeps this construction's expressions and
// drops every other cached expression that no in-flight construction used.
// A discarded construction drops only the expressions it added.
func beginScannerRegexpScope() func(kept bool) {
	id, ok := currentGoroutineID()
	if !ok {
		return func(bool) {}
	}
	scope := &regexpScope{
		used:  make(map[string]struct{}),
		added: make(map[string]struct{}),
	}
	if _, loaded := regexpScopes.LoadOrStore(id, scope); loaded {
		return func(bool) {}
	}
	return func(kept bool) {
		regexpScopes.Delete(id)
		if kept {
			scannerRegexpCache.retain(scope.unionUsed())
			return
		}
		scannerRegexpCache.drop(scope.addedWithoutInFlight())
	}
}

func currentRegexpScope() *regexpScope {
	id, ok := currentGoroutineID()
	if !ok {
		return nil
	}
	scope, ok := regexpScopes.Load(id)
	if !ok {
		return nil
	}
	return scope.(*regexpScope)
}

func (s *regexpScope) unionUsed() map[string]struct{} {
	keep := make(map[string]struct{}, len(s.used))
	for expression := range s.used {
		keep[expression] = struct{}{}
	}
	regexpScopes.Range(func(_, value any) bool {
		other := value.(*regexpScope)
		other.mu.Lock()
		for expression := range other.used {
			keep[expression] = struct{}{}
		}
		other.mu.Unlock()
		return true
	})
	return keep
}

func (s *regexpScope) addedWithoutInFlight() map[string]struct{} {
	drop := make(map[string]struct{}, len(s.added))
	for expression := range s.added {
		drop[expression] = struct{}{}
	}
	regexpScopes.Range(func(_, value any) bool {
		other := value.(*regexpScope)
		other.mu.Lock()
		for expression := range other.used {
			delete(drop, expression)
		}
		other.mu.Unlock()
		return true
	})
	return drop
}

func (c *regexpCompileCache) retain(keep map[string]struct{}) {
	c.deleteUnless(func(expression string) bool {
		_, ok := keep[expression]
		return ok
	})
}

func (c *regexpCompileCache) drop(expressions map[string]struct{}) {
	if len(expressions) == 0 {
		return
	}
	c.deleteUnless(func(expression string) bool {
		_, ok := expressions[expression]
		return !ok
	})
}

func (c *regexpCompileCache) deleteUnless(keep func(string) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for expression := range c.expressions {
		if !keep(expression) {
			delete(c.expressions, expression)
		}
	}
	order := make([]string, 0, len(c.expressions))
	seen := make(map[string]struct{}, len(c.expressions))
	for _, expression := range c.order {
		if _, ok := c.expressions[expression]; !ok {
			continue
		}
		if _, dup := seen[expression]; dup {
			continue
		}
		seen[expression] = struct{}{}
		order = append(order, expression)
	}
	c.order = order
	c.next = 0
}

var goroutineIDPrefix = []byte("goroutine ")

// currentGoroutineID reads the id from the first line of runtime.Stack.
// Construction compiles on the goroutine that entered the scope.
func currentGoroutineID() (uint64, bool) {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	if n <= len(goroutineIDPrefix) || !bytes.Equal(buf[:len(goroutineIDPrefix)], goroutineIDPrefix) {
		return 0, false
	}
	var id uint64
	i := len(goroutineIDPrefix)
	if buf[i] < '0' || buf[i] > '9' {
		return 0, false
	}
	for ; i < n && buf[i] >= '0' && buf[i] <= '9'; i++ {
		id = id*10 + uint64(buf[i]-'0')
	}
	if i == len(goroutineIDPrefix) || i >= n || buf[i] != ' ' {
		return 0, false
	}
	return id, true
}

// Derived expressions already came from valid syntax. Preserve
// regexp.MustCompile's panic for a programming error; configured source
// expressions use the error-returning path above.
func mustCompileScannerRegexp(expression string) *regexp.Regexp {
	re, err := compileScannerRegexp(expression)
	if err != nil {
		panic(err)
	}
	return re
}
