// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"reflect"
	"strings"
	"testing"
)

func TestCSSResourceURLs(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		limit      int
		want       []string
	}{
		{"unquoted", `a{background:url(./a.png)}`, 8, []string{"./a.png"}},
		{"quoted", `a{background:URL( "/a.png" )}`, 8, []string{"/a.png"}},
		{"imports", `@import "a.css";@import url('b.css') screen;`, 8, []string{"a.css", "b.css"}},
		{"escaped", `a{background:u\72l(/a\2e png)}`, 8, []string{"/a.png"}},
		{"fragments and text", `a{filter:url(#x);content:"/not-a-url"}/*url(/ignored)*/`, 8, nil},
		{"malformed URL", `a{background:url(/a b)}`, 8, nil},
		{"malformed tail", `a{background:url(/a)}b{content:"unterminated}`, 8, nil},
		{"incomplete quoted URL", `a{background:url('/a'}`, 8, nil},
		{"two quoted URL arguments", `a{background:url("a" "b")}`, 8, nil},
		{"bounded", `@import 'a.css';@import 'b.css';`, 1, []string{"a.css"}},
		{"disabled limit", `@import 'a.css'`, 0, nil},
		{"oversize", strings.Repeat(" ", maxCSSStyleBytes+1), 8, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CSSResourceURLs(tc.body, tc.limit); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("references=%q, want %q", got, tc.want)
			}
		})
	}
}
