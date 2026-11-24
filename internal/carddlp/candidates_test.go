// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package carddlp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestCandidateEnumeration(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, tc := range []struct {
		value string
		count int
	}{
		{pan, 1},
		{"x" + pan, 1},
		{"order" + pan, 0},
		{"9" + pan, 0},
		{pan + "9", 0},
		{pan[:8] + " " + pan[8:], 0},
		{pan[:4] + "." + pan[4:], 0},
		{pan[:4] + "\t" + pan[4:], 0},
		{pan + " 12/28", 1},
		{"1234." + cardtest.Grouped(pan, "."), 1},
		{strings.Repeat("4242", 4) + "-" + cardtest.Grouped(pan, "-"), 2},
		{cardtest.Grouped(pan, "-") + "-" + cardtest.Grouped(pan, "-"), 2},
	} {
		t.Run(tc.value, func(t *testing.T) {
			count := 0
			Visit(tc.value, false, func(c Candidate) bool {
				count++
				if !ValidCardNumber(c.Digits) {
					t.Fatal("invalid candidate")
				}
				return false
			})
			if count != tc.count {
				t.Fatalf("count=%d want=%d", count, tc.count)
			}
		})
	}
	for _, sep := range []string{" ", "-", ".", "/", "_", "--", ".-"} {
		if !Visit(cardtest.Grouped(pan, sep), false, func(Candidate) bool { return true }) {
			t.Errorf("missing separator %q", sep)
		}
	}
	for _, text := range []string{pan[:8] + "," + pan[8:], pan[:4] + "." + pan[4:], pan[:4] + "///" + pan[4:], pan[:4] + "!!!" + pan[4:]} {
		if !Visit(text, true, func(Candidate) bool { return true }) {
			t.Errorf("missing reconstructed candidate %q", text)
		}
	}
}

func TestIssuerRangesAndGroupings(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		length int
		groups []int
	}{
		{"4", 16, []int{4, 4, 4, 4}},
		{"4", 19, []int{4, 4, 4, 4, 3}},
		{"51", 16, []int{4, 4, 4, 4}},
		{"2221", 16, []int{4, 4, 4, 4}},
		{"2720", 16, []int{4, 4, 4, 4}},
		{"34", 15, []int{4, 6, 5}},
		{"37", 15, []int{4, 4, 4, 3}},
		{"300", 14, []int{4, 6, 4}},
		{"3095", 14, []int{4, 4, 4, 2}},
		{"36", 16, []int{4, 4, 4, 4}},
		{"38", 14, []int{4, 6, 4}},
		{"39", 14, []int{4, 6, 4}},
		{"6011", 19, []int{4, 4, 4, 4, 3}},
		{"644", 16, []int{4, 4, 4, 4}},
		{"65", 16, []int{4, 4, 4, 4}},
		{"3528", 17, []int{4, 4, 4, 4, 1}},
		{"3589", 18, []int{4, 4, 4, 4, 2}},
		{"62", 19, []int{4, 4, 4, 4, 3}},
		{"81", 16, []int{4, 4, 4, 4}},
		{"2200", 16, []int{4, 4, 4, 4}},
		{"2204", 16, []int{4, 4, 4, 4}},
		{"5018", 16, []int{4, 4, 4, 4}},
		{"5020", 17, []int{4, 4, 4, 4, 1}},
		{"5038", 18, []int{4, 4, 4, 4, 2}},
		{"5893", 19, []int{4, 4, 4, 4, 3}},
		{"6304", 16, []int{4, 4, 4, 4}},
		{"6759", 16, []int{4, 4, 4, 4}},
		{"6761", 16, []int{4, 4, 4, 4}},
		{"6762", 16, []int{4, 4, 4, 4}},
		{"6763", 16, []int{4, 4, 4, 4}},
	} {
		t.Run(fmt.Sprintf("%s/%d", tc.prefix, tc.length), func(t *testing.T) {
			pan := cardtest.Issuer(tc.prefix, tc.length)
			if !ValidCardNumber(pan) {
				t.Fatal("issuer rejected")
			}
			for _, sep := range []string{" ", "-", ".", "/", "_", "--", ".-"} {
				var groups []string
				at := 0
				for _, size := range tc.groups {
					groups = append(groups, pan[at:at+size])
					at += size
				}
				if !Visit(strings.Join(groups, sep), false, func(Candidate) bool { return true }) {
					t.Errorf("grouping rejected %v sep=%q", tc.groups, sep)
				}
			}
		})
	}
	for _, tc := range []struct {
		prefix string
		length int
	}{{"4", 13}, {"4", 20}, {"81", 19}, {"2205", 16}, {"50", 16}, {"56", 16}, {"6764", 16}, {"3094", 14}, {"35", 14}} {
		if ValidCardNumber(cardtest.Issuer(tc.prefix, tc.length)) {
			t.Errorf("unsupported issuer admitted %s/%d", tc.prefix, tc.length)
		}
	}
}

func TestPublicExamplesExact(t *testing.T) {
	for pan := range publicTestPANs {
		if !IsPublicTestPAN(pan) || !IsPublicTestPAN(cardtest.Grouped(pan, "/")) {
			t.Errorf("published example not recognized")
		}
		if IsPublicTestPAN(pan+"0") || IsPublicTestPAN("x"+pan) || IsPublicTestPAN(pan[:4]+"\t"+pan[4:]) {
			t.Fatal("non-exact example admitted")
		}
	}
	if IsPublicTestPAN(strings.Repeat("4", 20)) {
		t.Fatal("oversize example")
	}
}

func BenchmarkCandidateEnumeration(b *testing.B) {
	for _, size := range []int{1024, 16384, 262144} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			text := strings.Repeat("1234.", size/5)
			b.SetBytes(int64(len(text)))
			for b.Loop() {
				Visit(text, false, func(Candidate) bool { return false })
			}
		})
	}
}

func TestTextSpanProjection(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, value := range []string{pan, pan[:4] + "\u200b" + pan[4:], "４" + pan[1:], pan[:4] + "\x00" + pan[4:]} {
		input := "prefix: " + value + " suffix"
		found := VisitText(input, func(c Candidate) bool {
			if input[c.Start:c.End] != value || c.Digits != pan {
				t.Fatalf("raw span projection changed: %+v", c)
			}
			return true
		})
		if !found {
			t.Errorf("missing folded card %q", value)
		}
	}
	if VisitText("１２３４\t５６７８", func(Candidate) bool { return true }) {
		t.Fatal("joined a table boundary")
	}
}
