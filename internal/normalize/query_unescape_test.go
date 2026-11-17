// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"net/url"
	"strings"
	"testing"
)

func TestQueryUnescapePartial(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"", ""},
		{"plain", "plain"},
		{"%", "%"},
		{"%Z", "%Z"},
		{"%ZZ", "%ZZ"},
		{"%ZZ+%4Z", "%ZZ %4Z"},
		{"%ZZ%00%4Ztail", "%ZZ\x00%4Ztail"},
		{"a+b", "a b"},
		{"%41%ZZ%42", "A%ZZB"},
		{"%ZZ%41", "%ZZA"},
		{"%41%", "A%"},
		{"%41%4", "A%4"},
		{"%aF%fF", "\xaf\xff"},
		{"%00+%20", "\x00  "},
		{"%2B", "+"},
		{"%252B", "%2B"},
		{"%4Z%41", "%4ZA"},
		{"%%41", "%A"},
		{"café%41%ZZ", "caféA%ZZ"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := QueryUnescapePartial(tc.input); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPartialUnescapeUnchangedAllocations(t *testing.T) {
	text := strings.Repeat("text %ZZ %4Z % ", 4096)
	for _, decode := range []func(string) string{QueryUnescapePartial, PercentUnescapePartial} {
		if allocs := testing.AllocsPerRun(10, func() {
			if got := decode(text); got != text {
				t.Fatal("malformed escapes changed")
			}
		}); allocs != 0 {
			t.Fatalf("unchanged text allocated %v objects", allocs)
		}
	}
}

func TestPercentUnescapePartial(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"", ""},
		{"plain", "plain"},
		{"a+b", "a+b"},
		{"%41%ZZ%42", "A%ZZB"},
		{"%41%", "A%"},
		{"%00+%20", "\x00+ "},
		{"%2B", "+"},
		{"%252B", "%2B"},
		{"%%41", "%A"},
		{"café+%41%ZZ", "café+A%ZZ"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := PercentUnescapePartial(tc.input); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			// Well-formed input decodes exactly as the strict RFC 3986 decoder.
			if strict, err := url.PathUnescape(tc.input); err == nil && strict != tc.want {
				t.Fatalf("strict decode %q differs from %q", strict, tc.want)
			}
		})
	}
}
