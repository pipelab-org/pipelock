// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestKeywordOccurrenceExaminedBytesCharged(t *testing.T) {
	root := strings.Repeat("kw", 180)
	gap := strings.Repeat("x", 4000)
	const candidates = 6
	var built strings.Builder
	for range candidates {
		built.WriteString(gap)
		built.WriteString(root)
	}
	source := built.String()
	// Each candidate accepts the next copy and skips copies already cached.
	// The examined count is what strings.Index has to read, measured independently.
	examined := 0
	from := 0
	var want []int
	for range candidates {
		rel := strings.Index(source[from:], root)
		if rel < 0 {
			t.Fatal("fixture lost an occurrence")
		}
		examined += rel + len(root)
		want = append(want, from+rel)
		from += rel + 1
	}
	sources := newKeywordDecodeSources(source)
	before := sources.budget.used
	var got []int
	for i := range candidates {
		n := 0
		if !sources.visitOccurrences(source, root, func(at int) bool {
			take := n == i
			n++
			if take {
				got = append(got, at)
			}
			return take
		}) || sources.incomplete || sources.budget.incomplete {
			t.Fatalf("candidate %d refused a search that fits", i)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("positions %v, want %v", got, want)
	}
	charged := sources.budget.used - before
	if charged < examined {
		t.Fatalf("charged %d bytes for %d bytes examined", charged, examined)
	}
}

func TestKeywordOccurrenceShortMatchStaysComplete(t *testing.T) {
	source := "prefix account suffix account"
	root := "account"
	sources := newKeywordDecodeSources(source)
	var got []int
	if sources.visitOccurrences(source, root, func(at int) bool { got = append(got, at); return false }) {
		t.Fatal("visitor stopped the walk")
	}
	if !slices.Equal(got, []int{7, 22}) || sources.incomplete || sources.budget.incomplete {
		t.Fatalf("positions=%v incomplete=%v budget=%v used=%d", got, sources.incomplete, sources.budget.incomplete, sources.budget.used)
	}
	// A second candidate replays cached positions and does not search again.
	used := sources.budget.used
	var again []int
	sources.visitOccurrences(source, root, func(at int) bool { again = append(again, at); return false })
	if !slices.Equal(again, got) || sources.budget.used-used != len(got)*keywordSpanBytes {
		t.Fatalf("replay positions=%v charged=%d", again, sources.budget.used-used)
	}
}

func TestKeywordOccurrenceUnaffordableSuffixRefuses(t *testing.T) {
	root := strings.Repeat("kw", 50)
	source := strings.Repeat("x", 10000) + root
	sources := newKeywordDecodeSources(source)
	entryCost := int(reflect.TypeFor[keywordProjectionKey]().Size() + reflect.TypeFor[keywordSourceOccurrences]().Size())
	// Room for the cache entry and a needle-sized charge, not for the suffix.
	sources.budget.used = maxDecodeTotalBytes - entryCost - len(root) - keywordSpanBytes
	if sources.visitOccurrences(source, root, func(int) bool { return true }) || !sources.incomplete || !sources.budget.incomplete {
		t.Fatalf("ok incomplete=%v budgetIncomplete=%v used=%d", sources.incomplete, sources.budget.incomplete, sources.budget.used)
	}
}
