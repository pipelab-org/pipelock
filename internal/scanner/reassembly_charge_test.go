// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"slices"
	"testing"
)

func TestPolicyChargeIntervals(t *testing.T) {
	uncached := &assembledBudget{}
	if !uncached.charge(nil, 0, 0, 0) || uncached.used != 1 {
		t.Fatal("uncached cursor escaped charge")
	}
	uncached.used = maxDecodeTotalBytes
	if uncached.charge(nil, 0, 0, 1) || !uncached.incomplete {
		t.Fatal("uncached cursor escaped cap")
	}
	b := &assembledBudget{}
	c := b.chargesFor("source")
	for _, offset := range []int{5, 6, 1, 2, 4, 3, 0, 7, 3, 7} {
		if !b.charge(c, 0, 0, offset) {
			t.Fatal("unexpected refusal")
		}
	}
	if b.used != 8 || !slices.Equal(c.lanes[0][0], []assembledInterval{{0, 8}}) {
		t.Fatal("overlap or hole mischarged", b.used, c.lanes[0][0])
	}
	if b.chargesFor("source") != c {
		t.Fatal("same view lost registry")
	}
	for _, lane := range [][2]int{{0, 1}, {1, 0}} {
		if !b.charge(c, lane[0], lane[1], 0) {
			t.Fatal("distinct lane refused")
		}
	}
	if !b.charge(b.chargesFor("other"), 0, 0, 0) || b.used != 11 {
		t.Fatal("distinct view or phase not charged", b.used)
	}
	b.used = maxDecodeTotalBytes
	if !b.charge(c, 0, 0, 0) {
		t.Fatal("paid byte refused at cap")
	}
	if b.charge(c, 0, 0, 8) || !b.incomplete {
		t.Fatal("new byte passed cap")
	}
}
