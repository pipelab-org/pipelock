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
		patterns[0].responseMemoRegexp = nil
		unproven := reusableResponsePreFilter(patterns, responseSyntaxPrimary)
		if unproven.prefixes[0] != nil {
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
