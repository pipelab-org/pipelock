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
	out.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) {
			a, aOK := hexNibble(value[i+1])
			b, bOK := hexNibble(value[i+2])
			if aOK && bOK {
				out.WriteByte(a<<4 | b)
				i += 2
				continue
			}
		}
		if plusAsSpace && value[i] == '+' {
			out.WriteByte(' ')
		} else {
			out.WriteByte(value[i])
		}
	}
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
