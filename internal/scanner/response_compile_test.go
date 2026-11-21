// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"regexp"
	"sync"
	"testing"
)

func TestResponseSyntaxReuseMatchesFreshFilter(t *testing.T) {
	for _, expression := range []string{`(?i)ignore\s+previous`, `(?i)other\s+instructions`} {
		re := regexp.MustCompile(expression)
		patterns := []*compiledPattern{{name: "Record", re: re, responseMemoRegexp: re}}
		fresh := newResponsePreFilter(patterns)
		first := reusableResponsePreFilter(patterns, responseSyntaxPrimary)
		second := reusableResponsePreFilter(patterns, responseSyntaxPrimary)
		if first.gates[0] != second.gates[0] {
			t.Fatal("identical syntax recompiled")
		}
		for _, input := range []string{"ordinary text", "ignore previous", "other instructions", "ignore other previous"} {
			want := fresh.patternsToCheck(input)
			if got := second.patternsToCheck(input); !reflect.DeepEqual(got, want) {
				t.Fatal("filter changed candidate indices", got, want)
			}
		}
		first.proofs[0] = nil
		if second.proofs[0] == nil {
			t.Fatal("scanner-local index mutation crossed filter instances")
		}
		first.windowAnchors[0] = "local mutation"
		if second.windowAnchors[0] == first.windowAnchors[0] {
			t.Fatal("scanner-local anchor mutation crossed filter instances")
		}
		// The regexp cache can evict an expression while the syntax cache
		// still holds its filter. A reload of the same expression then has
		// the same syntax and a new compiled regexp.
		recompiled := regexp.MustCompile(expression)
		reloadedPatterns := []*compiledPattern{
			{name: "Record", re: recompiled, responseMemoRegexp: recompiled},
		}
		reloaded := reusableResponsePreFilter(reloadedPatterns, responseSyntaxPrimary)
		if plan := reloaded.windows[recompiled]; plan == nil || plan.re != recompiled {
			t.Fatal("recompiled pattern has no window plan for its regexp")
		}
		if plan := second.windows[re]; plan == nil || plan.re != re {
			t.Fatal("reload changed an existing scanner's window plan")
		}
		// Keep the pointer fixed so losing provenance is the only cache-key change.
		reloadedPatterns[0].responseMemoRegexp = nil
		unproven := reusableResponsePreFilter(reloadedPatterns, responseSyntaxPrimary)
		if unproven.prefixes[0] != nil || unproven.windows[recompiled] != nil {
			t.Fatal("Perl compilation provenance crossed cache keys")
		}
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			re := regexp.MustCompile(`(?i)ignore\s+previous`)
			patterns := []*compiledPattern{{name: "Concurrent record", re: re, responseMemoRegexp: re}}
			pf := reusableResponsePreFilter(patterns, responseSyntaxOptionalSpace)
			if len(pf.patternsToCheck("ignore previous")) == 0 {
				t.Error("concurrent filter lost a candidate")
			}
		})
	}
	workers.Wait()
}
