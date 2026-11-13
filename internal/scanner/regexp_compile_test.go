// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"sync"
	"testing"
)

func TestRegexpCompileCache(t *testing.T) {
	var cache regexpCompileCache
	compile := func(expression string) *regexp.Regexp {
		t.Helper()
		re, err := cache.compile(expression, 2, nil)
		if err != nil {
			t.Fatal(err)
		}
		return re
	}
	first := compile("abc")
	if compile("abc") != first {
		t.Fatal("cache hit recompiled expression")
	}
	folded := compile("(?i)abc")
	if first == folded || first.MatchString("ABC") || !folded.MatchString("ABC") {
		t.Fatal("flags were not preserved")
	}
	if re, err := cache.compile("[", 2, nil); err == nil || re != nil {
		t.Fatal("invalid expression accepted")
	}
	if len(cache.expressions) != 2 {
		t.Fatal("error changed cache contents")
	}
	compile("def")
	if len(cache.expressions) != 2 || len(cache.order) != 2 {
		t.Fatal("cache exceeded retention bound")
	}
	if compile("abc") == first {
		t.Fatal("evicted expression remained cached")
	}
	// An old scanner's regexp remains valid after eviction.
	if !first.MatchString("abc") {
		t.Fatal("eviction changed a live expression")
	}
}

func TestRegexpCompileCacheConcurrentMiss(t *testing.T) {
	var cache regexpCompileCache
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan *regexp.Regexp, 8)
	for range cap(results) {
		wg.Go(func() {
			<-start
			re, err := cache.compile("cold-expression", 2, nil)
			if err != nil {
				t.Error(err)
				return
			}
			results <- re
		})
	}
	close(start)
	wg.Wait()
	close(results)
	var first *regexp.Regexp
	for re := range results {
		if first == nil {
			first = re
		}
		if re != first {
			t.Fatal("concurrent cache miss compiled twice")
		}
	}
	if len(cache.expressions) != 1 {
		t.Fatal("cold expression not published")
	}
}

func TestMustCompileScannerRegexp(t *testing.T) {
	if !mustCompileScannerRegexp("valid-expression").MatchString("valid-expression") {
		t.Fatal("valid constant did not compile")
	}
	defer func() {
		if recover() == nil {
			t.Error("invalid constant must panic")
		}
	}()
	mustCompileScannerRegexp("[")
}
