// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"regexp"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestAssembledSyntaxReuseKeepsScannerPolicy(t *testing.T) {
	var iban config.DLPPattern
	for _, rule := range config.DefaultDLPPatterns() {
		if rule.Name == "IBAN" {
			iban = rule
		}
	}
	if iban.Regex == "" {
		t.Fatal("missing canonical fixture")
	}
	makePlan := func(accept bool) *reassemblyPlan {
		p, err := newReassemblyPlan([]*compiledPattern{{name: iban.Name, re: regexp.MustCompile("(?i)" + iban.Regex), validate: func(string) bool { return accept }}})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	first, second := makePlan(false), makePlan(true)
	if &first.assembled.raw[0].nodes[0] != &second.assembled.raw[0].nodes[0] {
		t.Fatal("identical syntax recompiled")
	}
	if len(first.assembled.shapes) == 0 || len(second.assembled.shapes) == 0 {
		t.Fatal("missing validation fixture")
	}
	if first.assembled.shapes[0].validate.validate("fixture") || !second.assembled.shapes[0].validate.validate("fixture") {
		t.Fatal("validator crossed scanner instances")
	}
	second.patterns[0].genericCard = true
	rebound, err := newAssembledPlan(second)
	if err != nil {
		t.Fatal(err)
	}
	if len(rebound.shapeGroups[textDLPCardPatterns][0]) == 0 || len(first.assembled.shapeGroups[textDLPCardPatterns][0]) != 0 {
		t.Fatal("card partition crossed scanner instances")
	}
}

func TestAssembledSyntaxReuseMatchesCompilation(t *testing.T) {
	for _, expression := range []string{`MARK[0-9]{4}`, `OTHER[0-9]{5}`, `[0-9]{16}`} {
		p := &reassemblyPlan{patterns: []*compiledPattern{{name: "Record", re: regexp.MustCompile(expression)}}, required: [][]string{{"MARK"}}}
		want, err := compileAssembledPlan(p)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			got, err := newAssembledPlan(p)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.raw, want.raw) || !reflect.DeepEqual(got.active, want.active) || got.nestedMinimum != want.nestedMinimum {
				t.Fatal("syntax key changed the compiled language")
			}
		}
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			p, err := newReassemblyPlan([]*compiledPattern{{name: "Concurrent record", re: regexp.MustCompile(`MARK[0-9]{4}`)}})
			if err != nil || p.assembled == nil {
				t.Error("concurrent construction failed", err)
			}
		})
	}
	workers.Wait()
}
