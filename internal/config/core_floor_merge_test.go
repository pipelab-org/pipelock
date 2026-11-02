// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"slices"
	"testing"
)

func TestWithCoreDLPFloor(t *testing.T) {
	core := CoreDLPPatterns()
	if got := WithCoreDLPFloor(nil); len(got) != len(core) {
		t.Fatalf("WithCoreDLPFloor(nil) = %d patterns, want %d", len(got), len(core))
	}
	// A configured copy identical to a core pattern is not duplicated.
	if got := WithCoreDLPFloor(core); len(got) != len(core) {
		t.Fatalf("identical configured copies duplicated: %d, want %d", len(got), len(core))
	}
	// A configured pattern reusing a core name with a different expression or
	// validator does not replace the core one.
	for _, mutate := range []func(*DLPPattern){
		func(p *DLPPattern) { p.Regex = `never-matches` },
		func(p *DLPPattern) { p.Validator = "luhn" },
	} {
		configured := core[0]
		mutate(&configured)
		if got := WithCoreDLPFloor([]DLPPattern{configured}); len(got) != len(core)+1 {
			t.Fatalf("a same-name configured pattern displaced the core pattern: %d", len(got))
		}
	}
	// The input slice is not modified.
	in := []DLPPattern{{Name: "Custom", Regex: `x`}}
	want := slices.Clone(in)
	_ = WithCoreDLPFloor(in)
	if !reflect.DeepEqual(in, want) {
		t.Fatalf("input modified: got %+v, want %+v", in, want)
	}
}
