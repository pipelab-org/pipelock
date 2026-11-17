// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import "strings"

// QueryUnescapePartial keeps malformed escapes verbatim and decodes every
// complete percent escape. It has form semantics: plus becomes a space.
func QueryUnescapePartial(value string) string {
	return unescapePartial(value, true)
}

// PercentUnescapePartial is QueryUnescapePartial without form semantics.
// RFC 3986 section 2.1 percent-encoding has no plus-as-space rule; only
// application/x-www-form-urlencoded maps plus to a space. Plus stays data.
func PercentUnescapePartial(value string) string {
	return unescapePartial(value, false)
}

func unescapePartial(value string, plusAsSpace bool) string {
	special := "%"
	if plusAsSpace {
		special = "%+"
	}
	if !strings.ContainsAny(value, special) {
		return value
	}
	var out strings.Builder
	from := 0
	for i := 0; i < len(value); i++ {
		var decoded byte
		width := 1
		if value[i] == '%' && i+2 < len(value) {
			a, aOK := hexNibble(value[i+1])
			b, bOK := hexNibble(value[i+2])
			if aOK && bOK {
				decoded = a<<4 | b
				width = 3
			}
		}
		if width == 1 {
			if !plusAsSpace || value[i] != '+' {
				continue
			}
			decoded = ' '
		}
		// Malformed percent escapes leave the input unchanged. Allocate only
		// at the first real transformation, and copy unchanged runs together.
		if out.Cap() == 0 {
			out.Grow(len(value))
		}
		out.WriteString(value[from:i])
		out.WriteByte(decoded)
		i += width - 1
		from = i + 1
	}
	if from == 0 {
		return value
	}
	out.WriteString(value[from:])
	return out.String()
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
