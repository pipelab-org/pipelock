// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
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
	return hasQuotedPrintable(s) || hasCharacterCodeRun(s)
}

// hasCharacterCodeRun requires the existing minDecimalCodeRun consecutive
// NumericLiteral fields, rather than counting unrelated digits in prose.
// The existing decimal parser accepts JSON number spellings (RFC 8259
// section 6); prefixed integers use ECMA-262 section 12.9.3. Reuse those
// parsers so malformed fields break the same runs here and in the decoder.
func hasCharacterCodeRun(s string) bool {
	if !hasMinimumASCIIDigits(s, minDecimalCodeRun) {
		return false
	}
	// A run needs at least this many fields, regardless of their values.
	// Count before parsing: one large hex/base64 field cannot be a code list,
	// and strconv error reporting would otherwise copy that entire field.
	if !hasMinimumCharacterCodeFields(s) {
		return false
	}
	var counts [3]int
	for i := 0; i < len(s); {
		r, size := rune(s[i]), 1
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeRuneInString(s[i:])
		}
		if characterCodeSeparatorFast(r) {
			i += size
			continue
		}
		start := i
		i += size
		for i < len(s) {
			r, size = rune(s[i]), 1
			if r >= utf8.RuneSelf {
				r, size = utf8.DecodeRuneInString(s[i:])
			}
			if characterCodeSeparatorFast(r) {
				break
			}
			i += size
		}
		field := s[start:i]
		first := field[0]
		if (first < '0' || first > '9') && first != '+' && first != '-' && first != '.' {
			counts = [3]int{}
			continue
		}
		for kind := range counts {
			var ok bool
			switch kind {
			case 0:
				_, ok = parseDecimalCharacterCode(field)
			case 1:
				_, ok = parsePrefixedCharacterCode(field, 'o', 8)
			case 2:
				_, ok = parsePrefixedCharacterCode(field, 'b', 2)
			}
			if ok {
				counts[kind]++
				if counts[kind] >= minDecimalCodeRun {
					return true
				}
			} else {
				counts[kind] = 0
			}
		}
	}
	return false
}

func hasMinimumCharacterCodeFields(s string) bool {
	fields := 0
	for range strings.FieldsFuncSeq(s, characterCodeSeparatorFast) {
		fields++
		if fields >= minDecimalCodeRun {
			return true
		}
	}
	return false
}

type textEncodingView struct {
	decodedResult
	sourceRange encodingSourceRange
}

// appendTextEncodingViews joins textual carriers to the existing decode graph.
// Each result is at most the input size; the caller owns recursive budgets.
func appendTextEncodingViews(out []decodedResult, s string) []decodedResult {
	for _, view := range textEncodingViews(s) {
		out = append(out, view.decodedResult)
	}
	return out
}

func textEncodingViews(s string) []textEncodingView { return textEncodingViewsMode(s, true) }

// A stitched binary-fragment view retains the original whole-carrier admission.
// Damaged-carrier recovery belongs to retained source runs and real codec output.
func textEncodingViewsMode(s string, recoverQP bool) []textEncodingView {
	var out []textEncodingView

	if hasCharacterCodeRun(s) {
		if decoded, _ := decodeCharacterCodes(s, characterCodeSeparatorFast, parseDecimalCharacterCode, false); decoded != "" && decoded != s {
			out = append(out, textEncodingView{decodedResult{text: decoded, encoding: encodingDecimal}, encodingSourceRange{0, len(s)}})
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
				out = append(out, textEncodingView{decodedResult{text: decoded, encoding: encoding}, encodingSourceRange{0, len(s)}})
			}
		}
	}
	// RFC 2045 section 6.7 permits binary octets inside a valid carrier.
	// Otherwise, retain the existing printable-text admission and recover
	// embedded text runs independently of malformed or non-text padding.
	if (recoverQP && hasQuotedPrintableSourceRun(s)) || (!recoverQP && utf8.ValidString(s)) {
		if decoded, _ := decodeQuotedPrintable(s, false); decoded != s && decoded != "" {
			if utf8.ValidString(s) && (isPrintableText([]byte(decoded)) || hasQuotedPrintableCarrier(s)) {
				out = append(out, textEncodingView{decodedResult{text: decoded, encoding: encodingQuotedPrintable}, encodingSourceRange{0, len(s)}})
			} else if recoverQP {
				visitQuotedPrintableTextRuns(s, decoded, func(text string, sourceRange encodingSourceRange) bool {
					out = append(out, textEncodingView{decodedResult{text: text, encoding: encodingQuotedPrintable}, sourceRange})
					return true
				})
			}
		}
	}
	return out
}

// hasQuotedPrintableSourceRun keeps binary noise out of the decoder before
// allocating a whole-input view. Valid UTF-8 retains its existing admission;
// embedded carriers use opaqueResponseTextView's existing text-run floor.
func hasQuotedPrintableSourceRun(s string) bool {
	if utf8.ValidString(s) {
		return true
	}
	for offset := 0; offset < len(s); {
		next := strings.IndexByte(s[offset:], '=')
		if next < 0 {
			return false
		}
		i := offset + next
		offset = i + 1
		if !hasQuotedPrintable(s[i:min(len(s), i+3)]) {
			continue
		}
		// Only inspect the neighborhood of an actual escape. Walking every
		// rune of a binary body would repeat work for each recursive view.
		start := i
		for start > 0 && i-start < binaryResponseTextRunMinBytes {
			r, size := utf8.DecodeLastRuneInString(s[:start])
			if r == utf8.RuneError {
				break
			}
			start -= size
		}
		end := i
		for end < len(s) && end-start < binaryResponseTextRunMinBytes {
			r, size := utf8.DecodeRuneInString(s[end:])
			if r == utf8.RuneError {
				break
			}
			end += size
		}
		if end-start >= binaryResponseTextRunMinBytes {
			return true
		}
	}
	return false
}

// visitQuotedPrintableTextRuns uses opaqueResponseTextView's existing
// binaryResponseTextRunMinBytes floor and printable-rune classification.
// Each emitted slice has its own source coordinates. Malformed escapes and
// invalid UTF-8 end a run. Non-text edges are trimmed; interior controls retain
// the existing isPrintableText contract and normalization semantics.
func visitQuotedPrintableTextRuns(source, decoded string, yield func(string, encodingSourceRange) bool) {
	emit := func(start, end, sourceStart, sourceEnd int) bool {
		text := decoded[start:end]
		left := strings.TrimLeftFunc(text, func(r rune) bool { return !isPrintableResponseRune(r, utf8.RuneLen(r)) })
		trimStart := len(text) - len(left)
		trimmed := strings.TrimRightFunc(left, func(r rune) bool { return !isPrintableResponseRune(r, utf8.RuneLen(r)) })
		if len(trimmed) < binaryResponseTextRunMinBytes || !isPrintableText([]byte(trimmed)) {
			return true
		}
		bounds := encodingSourceRange{sourceStart, sourceEnd}
		if trimStart != 0 || len(trimmed) != len(text) {
			// A run without an escape decodes to itself with no byte map. Keep
			// the whole run span then: it still contains the trimmed text.
			_, ranges := decodeQuotedPrintable(source[sourceStart:sourceEnd], true)
			if last := trimStart + len(trimmed) - 1; last < len(ranges) {
				bounds.start += ranges[trimStart].start
				bounds.end = sourceStart + ranges[last].end
			}
		}
		if trimmed == source[bounds.start:bounds.end] {
			return true
		}
		return yield(trimmed, bounds)
	}
	start, offset, nextRune, sourceStart := 0, 0, 0, 0
	transformed := false
	for i := 0; i < len(source); {
		end := i + 1
		if source[i] == '=' {
			switch {
			case i+1 < len(source) && source[i+1] == '\n':
				// A soft break before the run's first rune belongs to the
				// previous run, like any other skipped byte.
				transformed = transformed || offset >= start
				i += 2
				continue
			case i+2 < len(source) && source[i+1:i+3] == "\r\n":
				transformed = transformed || offset >= start
				i += 3
				continue
			case i+2 < len(source):
				if _, ok := quotedPrintableByte(source[i+1], source[i+2]); ok {
					end = i + 3
				}
			}
		}
		malformed := source[i] == '=' && end == i+1
		text := true
		if offset >= nextRune {
			// Escaped multibyte characters use the same classification as
			// literal Unicode; continuation bytes belong to this rune.
			// U+FFFD also separates opaque-response fragments; it must
			// not join binary noise into an apparent text run.
			r, size := utf8.DecodeRuneInString(decoded[offset:])
			nextRune = offset + size
			text = r != utf8.RuneError
		}
		if malformed || !text {
			if transformed && offset-start >= binaryResponseTextRunMinBytes {
				if !emit(start, offset, sourceStart, i) {
					return
				}
			}
			start, transformed, sourceStart = nextRune, false, end
		} else if offset >= start {
			transformed = transformed || end-i > 1
		} else {
			sourceStart = end
		}
		i = end
		offset++
	}
	if transformed && offset-start >= binaryResponseTextRunMinBytes {
		emit(start, offset, sourceStart, len(source))
	}
}

var asciiCharacterCodeSeparators = func() [utf8.RuneSelf]bool {
	var separators [utf8.RuneSelf]bool
	for i := range separators {
		separators[i] = characterCodeSeparator(rune(i))
	}
	return separators
}()

func characterCodeSeparatorFast(r rune) bool {
	if r < utf8.RuneSelf {
		return asciiCharacterCodeSeparators[r]
	}
	return characterCodeSeparator(r)
}

// A number literal cannot contain arbitrary letters. Keeping them attached
// prevents digits inside another carrier (such as JSON \u0041 escapes) from
// manufacturing numeric-code views. The numeric parser still owns exponent
// forms. Known-value matching retains its existing liberal delimiter handling.
func characterCodeSeparator(r rune) bool {
	// NumericLiteral carriers are text. Invalid UTF-8 and non-whitespace
	// controls break a run instead of joining unrelated digits in binary.
	// Known-value numeric matching keeps its separate liberal separator rule.
	if r == utf8.RuneError || unicode.IsControl(r) && !unicode.IsSpace(r) {
		return false
	}
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
	return decodeCharacterCodes(s, characterCodeSeparatorFast, func(field string) (rune, bool) {
		return parsePrefixedCharacterCode(field, prefix, base)
	}, withRanges)
}

func parsePrefixedCharacterCode(field string, prefix byte, base int) (rune, bool) {
	if len(field) < 3 || field[0] != '0' || field[1]|0x20 != prefix {
		return 0, false
	}
	value, err := strconv.ParseUint(field[2:], base, 32)
	if err != nil {
		return 0, false
	}
	return validDecimalCharacterCode(int64(value))
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

// hasQuotedPrintableCarrier checks the '=' productions of RFC 2045 section
// 6.7: each equals sign introduces two hexadecimal digits or a soft line break.
// Lowercase hexadecimal and local LF line endings retain the decoder's existing
// tolerant handling. This is not a line-length or content-size heuristic.
func hasQuotedPrintableCarrier(s string) bool {
	for offset := 0; offset < len(s); {
		next := strings.IndexByte(s[offset:], '=')
		if next < 0 {
			return true
		}
		i := offset + next
		switch {
		case i+1 < len(s) && s[i+1] == '\n':
			offset = i + 2
		case i+2 < len(s) && s[i+1:i+3] == "\r\n":
			offset = i + 3
		case i+2 < len(s):
			if _, ok := quotedPrintableByte(s[i+1], s[i+2]); !ok {
				return false
			}
			offset = i + 3
		default:
			return false
		}
	}
	return true
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

func mapTextEncodingViewSources(set responseMatchSet, source string, view textEncodingView) responseMatchSet {
	set = mapTextEncodingSources(set, source[view.sourceRange.start:view.sourceRange.end], view.decodedResult)
	for i := range set.matches {
		if set.matches[i].hasDecodedSource {
			set.matches[i].decodedSourceStart += view.sourceRange.start
			set.matches[i].decodedSourceEnd += view.sourceRange.start
		}
	}
	return set
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
