// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strconv"
	"strings"
	"unicode"
)

type encodingSourceRange struct {
	start, end int
}

// canonicalMixedBase64 uses RFC 4648 sections 4 and 5: '+' and '-' both
// encode 62; '/' and '_' both encode 63. No symbol acquires a second meaning.
// Padding, invalid bytes and decode errors still belong to the existing decoder.
func canonicalMixedBase64(s string) string {
	if !strings.ContainsAny(s, "+/") || !strings.ContainsAny(s, "-_") {
		return s
	}
	return mixedBase64Symbols.Replace(s)
}

var mixedBase64Symbols = strings.NewReplacer("-", "+", "_", "/")

func hasTextEncoding(s string) bool {
	return hasQuotedPrintable(s) || hasMinimumASCIIDigits(s, minDecimalCodeRun)
}

// appendTextEncodingViews joins textual carriers to the existing decode graph.
// Each result is at most the input size; the caller owns recursive budgets.
func appendTextEncodingViews(out []decodedResult, s string) []decodedResult {
	if decoded, _ := decodeCharacterCodes(s, characterCodeSeparator, parseDecimalCharacterCode, false); decoded != "" && decoded != s {
		out = append(out, decodedResult{decoded, encodingDecimal})
	}
	for _, encoding := range []string{encodingOctal, encodingBinary} {
		prefix, upperPrefix := "0o", "0O"
		if encoding == encodingBinary {
			prefix, upperPrefix = "0b", "0B"
		}
		if !strings.Contains(s, prefix) && !strings.Contains(s, upperPrefix) {
			continue
		}
		if decoded, _ := decodePrefixedCharacterCodes(s, encoding, false); decoded != "" && decoded != s {
			out = append(out, decodedResult{decoded, encoding})
		}
	}
	if decoded, _ := decodeQuotedPrintable(s, false); decoded != s && decoded != "" {
		out = append(out, decodedResult{decoded, encodingQuotedPrintable})
	}
	return out
}

// A number literal cannot contain arbitrary letters. Keeping them attached
// prevents digits inside another carrier (such as JSON \u0041 escapes) from
// manufacturing numeric-code views. The numeric parser still owns exponent
// forms. Known-value matching retains its existing liberal delimiter handling.
func characterCodeSeparator(r rune) bool {
	return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '+' && r != '-' && r != '_'
}

// Prefixed codes use ECMAScript NumericLiteral (ECMA-262, 12.9.3): each
// integer has an explicit 0o/0O or 0b/0B prefix. Bare octal/binary digits and
// legacy leading-zero octal are deliberately not inferred. Numeric separators
// within a literal are outside this view's supported subset.
func decodePrefixedCharacterCodes(s, encoding string, withRanges bool) (string, []encodingSourceRange) {
	prefix, base := byte('o'), 8
	if encoding == encodingBinary {
		prefix, base = 'b', 2
	}
	return decodeCharacterCodes(s, characterCodeSeparator, func(field string) (rune, bool) {
		if len(field) < 3 || field[0] != '0' || field[1]|0x20 != prefix {
			return 0, false
		}
		value, err := strconv.ParseUint(field[2:], base, 32)
		if err != nil {
			return 0, false
		}
		return validDecimalCharacterCode(int64(value))
	}, withRanges)
}

func quotedPrintableByte(a, b byte) (byte, bool) {
	var value byte
	for _, c := range [2]byte{a, b} {
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value |= c - '0'
		case c >= 'a' && c <= 'f':
			value |= c - 'a' + 10
		case c >= 'A' && c <= 'F':
			value |= c - 'A' + 10
		default:
			return 0, false
		}
	}
	return value, true
}

// hasQuotedPrintable avoids allocating identity views for ordinary equals signs.
func hasQuotedPrintable(s string) bool {
	for offset := 0; offset < len(s); {
		i := strings.IndexByte(s[offset:], '=')
		if i < 0 {
			return false
		}
		i += offset
		if i+1 < len(s) && s[i+1] == '\n' {
			return true
		}
		if i+2 < len(s) {
			if s[i+1:i+3] == "\r\n" {
				return true
			}
			if _, ok := quotedPrintableByte(s[i+1], s[i+2]); ok {
				return true
			}
		}
		offset = i + 1
	}
	return false
}

// decodeQuotedPrintable implements the RFC 2045 section 6.7 byte escapes and
// soft line breaks (including the permitted local LF newline convention).
// Malformed escapes stay verbatim, so one cannot discard a later valid view.
// No line-length admission heuristic is used for this scanner-only view.
func decodeQuotedPrintable(s string, withRanges bool) (string, []encodingSourceRange) {
	if !hasQuotedPrintable(s) {
		return s, nil
	}
	var out strings.Builder
	out.Grow(len(s))
	var ranges []encodingSourceRange
	for i := 0; i < len(s); {
		start, end, value := i, i+1, s[i]
		if s[i] == '=' {
			if i+1 < len(s) && s[i+1] == '\n' {
				i += 2
				continue
			}
			if i+2 < len(s) && s[i+1:i+3] == "\r\n" {
				i += 3
				continue
			}
			if i+2 < len(s) {
				if decoded, ok := quotedPrintableByte(s[i+1], s[i+2]); ok {
					value, end = decoded, i+3
				}
			}
		}
		out.WriteByte(value)
		if withRanges {
			ranges = append(ranges, encodingSourceRange{start, end})
		}
		i = end
	}
	return out.String(), ranges
}

// mapTextEncodingSources retains exact source ranges for the existing opaque
// fragment boundary check. Build the byte map only after a match, not for every
// clean decoded view. Encoded matches remain ineligible for unsafe stripping.
func mapTextEncodingSources(set responseMatchSet, source string, view decodedResult) responseMatchSet {
	var ranges []encodingSourceRange
	switch view.encoding {
	case encodingDecimal:
		_, ranges = decodeCharacterCodes(source, characterCodeSeparator, parseDecimalCharacterCode, true)
	case encodingOctal, encodingBinary:
		_, ranges = decodePrefixedCharacterCodes(source, view.encoding, true)
	case encodingQuotedPrintable:
		_, ranges = decodeQuotedPrintable(source, true)
	}
	for i := range set.matches {
		m := &set.matches[i]
		start, end := m.decodedSourceStart, m.decodedSourceEnd
		hadDecodedSource := m.hasDecodedSource
		m.hasDecodedSource = false
		if !hadDecodedSource {
			var ok bool
			start, end, ok = normalizedMatchSourceRange(view.text, *m)
			if !ok {
				continue
			}
		}
		if start < 0 || end <= start || end > len(ranges) || ranges[start].end == 0 || ranges[end-1].end == 0 {
			continue
		}
		transformed := view.encoding != encodingQuotedPrintable
		if !transformed {
			// A leading or trailing soft break can change an anchor boundary.
			transformed = start == 0 && ranges[start].start > 0 || end == len(ranges) && ranges[end-1].end < len(source)
			// Adjacent decoded bytes can supply a regex word or line boundary.
			// Include those bytes when deciding whether this match depended on
			// a byte escape or soft break, rather than unrelated literal text.
			for j := max(0, start-1); j < min(len(ranges), end+1); j++ {
				if ranges[j].end-ranges[j].start != 1 || j > 0 && ranges[j].start != ranges[j-1].end {
					transformed = true
					break
				}
			}
		}
		m.decodedSourceTransformed = m.decodedSourceTransformed || transformed
		m.decodedSourceStart, m.decodedSourceEnd = ranges[start].start, ranges[end-1].end
		m.hasDecodedSource = true
	}
	if view.encoding == encodingQuotedPrintable {
		// Literal text was already checked before decoding. An escape elsewhere
		// must not promote unchanged opaque fragments into decoded prose, or
		// stop the decoder before another carrier exposes an actual match.
		kept := set.matches[:0]
		for _, match := range set.matches {
			if match.hasDecodedSource && !match.decodedSourceTransformed {
				continue
			}
			kept = append(kept, match)
		}
		set.matches = kept
	}
	return set
}
