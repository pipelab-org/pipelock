// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package termsafe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestEscape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		// Positive controls: ordinary text is returned unchanged.
		{name: "plain ascii", in: "https://api.vendor.example/v1?q=1", want: "https://api.vendor.example/v1?q=1"},
		{name: "non-ascii letters", in: "café naïve 東京 Ωmega", want: "café naïve 東京 Ωmega"},
		{name: "empty", in: "", want: ""},

		{name: "ansi colour", in: "ok\x1b[31mred\x1b[0m", want: `ok\x1b[31mred\x1b[0m`},
		{name: "ansi erase line and cursor up", in: "a\x1b[2K\x1b[1Ab", want: `a\x1b[2K\x1b[1Ab`},
		{name: "osc title and hyperlink", in: "\x1b]0;owned\x07\x1b]8;;https://evil.example\x1b\\x", want: `\x1b]0;owned\x07\x1b]8;;https://evil.example\x1b\\x`},
		{name: "carriage return overwrite", in: "evil.example\rapi.vendor.example", want: `evil.example\rapi.vendor.example`},
		{name: "backspace overwrite", in: "evil\b\b\b\bgood", want: `evil\x08\x08\x08\x08good`},
		{name: "newline and tab", in: "a\nURL: x\tb", want: `a\nURL: x\tb`},
		{name: "nul and bell", in: "a\x00b\x07", want: `a\x00b\x07`},
		{name: "del", in: "a\x7fb", want: `a\x7fb`},
		{name: "c1 csi and nel", in: "a\u009b31mb\u0085c", want: `a\x9b31mb\x85c`},
		{name: "bidi override", in: "invoice\u202Efdp.exe", want: `invoice\u202Efdp.exe`},
		{name: "bidi isolates and marks", in: "\u2066a\u2069\u200E\u200F\u061C", want: `\u2066a\u2069\u200E\u200F\u061C`},
		{name: "zero width and bom", in: "a\u200Bb\u200Dc\uFEFF", want: `a\u200Bb\u200Dc\uFEFF`},
		{name: "line and paragraph separators", in: "a\u2028b\u2029c", want: `a\u2028b\u2029c`},
		{name: "tag characters", in: "a\U000E0041\U000E007F", want: `a\U000E0041\U000E007F`},
		{name: "invalid utf8", in: "a\xff\xfeb\xc3", want: `a\xff\xfeb\xc3`},
		{name: "backslash stays unambiguous", in: `a\x1bb`, want: `a\\x1bb`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Escape(tt.in)
			if got != tt.want {
				t.Fatalf("Escape(%q) = %q, want %q", tt.in, got, tt.want)
			}
			assertTerminalInert(t, got)
		})
	}
}

// TestEscapeAllControls walks every C0, DEL and C1 code point so no single
// control slips through a table that only lists the well-known ones.
func TestEscapeAllControls(t *testing.T) {
	t.Parallel()
	for r := rune(0); r <= 0x9f; r++ {
		if r >= 0x20 && r < 0x7f {
			if got := Escape(string(r)); got != string(r) && r != '\\' {
				t.Errorf("printable %U changed to %q", r, got)
			}
			continue
		}
		got := Escape("x" + string(r) + "y")
		assertTerminalInert(t, got)
		if !strings.HasPrefix(got, "x\\") || !strings.HasSuffix(got, "y") {
			t.Errorf("control %U escaped to %q", r, got)
		}
	}
}

// assertTerminalInert fails if s still contains anything a terminal would
// interpret instead of printing.
func assertTerminalInert(t *testing.T, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatalf("escaped output is not valid UTF-8: %q", s)
	}
	for _, r := range s {
		if unsafeRune(r) {
			t.Fatalf("escaped output still contains %U: %q", r, s)
		}
	}
}
