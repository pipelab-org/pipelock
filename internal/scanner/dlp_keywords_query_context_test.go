// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"strings"
	"testing"
)

func TestDLPKeywordsQueryKeyContext(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)

	for _, tc := range []struct {
		query string
		want  bool
	}{
		{"?account=33333333&part=33333333", true},
		{"?reference=33333333&part=33333333", false},
		{"?account" + strings.Repeat("x", 100) + "=33333333&part=33333333", false},
		{"?first=33333333&account=33333333", false},
	} {
		u, err := url.Parse("https://api.vendor.example/" + tc.query)
		if err != nil {
			t.Fatal(err)
		}
		result, _ := sc.checkDLP(u)
		if got := strings.Contains(result.Reason, keywordPattern); got != tc.want {
			t.Fatalf("query=%q finding=%v want=%v: %+v", tc.query, got, tc.want, result)
		}
	}
}

func TestJoinQuerySubsequenceSourceBoundaries(t *testing.T) {
	values := []string{"first", "unused", "last"}
	for _, tc := range []struct {
		name     string
		indices  []int
		separate bool
		want     string
	}{
		{name: "match", indices: []int{2, 0}, want: "lastfirst"},
		{name: "source", indices: []int{2, 0}, separate: true, want: "last\x00first"},
		{name: "empty source", separate: true},
		{name: "one field", indices: []int{0}, separate: true, want: "first"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinQuerySubsequence(values, tc.indices, tc.separate); got != tc.want {
				t.Fatalf("join = %q, want %q", got, tc.want)
			}
		})
	}
}
