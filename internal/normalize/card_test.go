// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import "testing"

func TestForCardText(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"1234.5678\t9012\n3456\r7890", "1234.5678\t9012\n3456\r7890"},
		{"１２３４\u200b５６７８\t９０\x009\n１２\r３４", "12345678\t909\n12\r34"},
		{"1234-5678/9012_3456", "1234-5678/9012_3456"},
		{"１２３４\u200b５６７８", "12345678"},
		{"a\x00b\tc\nd\re\x7ff", "ab\tc\nd\ref"},
		{"plain ASCII\twith table\r\nlines", "plain ASCII\twith table\r\nlines"},
	} {
		if got := ForCardText(tc.input); got != tc.want {
			t.Errorf("got %q want %q", got, tc.want)
		}
	}
}
