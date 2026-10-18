// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package termsafe renders untrusted strings for interactive terminal output.
//
// Text that reaches a prompt can come from a request URL, a response body, a
// tool description or a release feed. Written raw, a single ESC byte lets that
// text move the cursor, recolour or erase earlier lines, retitle the window or
// emit hyperlinks; a carriage return or backspace overwrites what was printed
// before it; bidi controls reorder what the operator reads. Escape replaces
// every such character with a visible escape sequence so the operator sees
// exactly the bytes that arrived and nothing can rewrite the prompt around it.
package termsafe

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Escape returns s with every character that can change how a terminal
// renders surrounding text replaced by a printable escape:
//
//   - C0 controls (including ESC, CR, LF, TAB and BS), DEL and C1 controls
//     become \t, \n, \r or \xNN;
//   - format characters (Unicode category Cf: bidi embeddings, overrides and
//     isolates, zero-width characters, tag characters, the BOM) and the line
//     and paragraph separators U+2028/U+2029 become \uNNNN or \UNNNNNNNN;
//   - bytes that are not valid UTF-8 become \xNN;
//   - a literal backslash becomes \\ so the output stays unambiguous.
//
// Everything else, including ordinary non-ASCII letters, passes through.
func Escape(s string) string {
	if !needsEscape(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
			continue
		}
		writeRune(&b, r)
		i += size
	}
	return b.String()
}

func needsEscape(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || r == '\\' || unsafeRune(r) {
			return true
		}
		i += size
	}
	return false
}

func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == '\u2028', r == '\u2029':
		return true
	default:
		return unicode.Is(unicode.Cf, r)
	}
}

func writeRune(b *strings.Builder, r rune) {
	switch {
	case r == '\\':
		b.WriteString(`\\`)
	case r == '\t':
		b.WriteString(`\t`)
	case r == '\n':
		b.WriteString(`\n`)
	case r == '\r':
		b.WriteString(`\r`)
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		fmt.Fprintf(b, `\x%02x`, r)
	case unsafeRune(r) && r > 0xffff:
		fmt.Fprintf(b, `\U%08X`, r)
	case unsafeRune(r):
		fmt.Fprintf(b, `\u%04X`, r)
	default:
		b.WriteRune(r)
	}
}
