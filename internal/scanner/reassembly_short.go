// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0
package scanner

import "unicode/utf8"

// Cue kinds specialize only the exact shipped regexes. The mfa branch keeps
// the admitted full literal; the dotted branch requires six folded characters.
func kindForLiteral(kind int, literal string) int {
	if literal == "mfa." {
		return 0
	}
	return kind
}

// The cursor reads only a candidate's bounded necessary prefix.
// Go's ASCII classes under Unicode simple folding also admit long s and Kelvin.
type assembledForwardCursor struct {
	text                string
	codec, raw, skip, n int
	bits                uint32
}

func (c *assembledForwardCursor) nextByte() (byte, bool) {
	spec := &reassemblyCodecs[c.codec]
	for c.raw < len(c.text) {
		v := spec.values[c.text[c.raw]]
		c.raw++
		if v < 0 {
			continue
		}
		width := spec.width
		if c.skip >= width {
			c.skip -= width
			continue
		}
		width -= c.skip
		c.skip = 0
		c.bits = c.bits<<uint(width) | uint32(v)&((1<<uint(width))-1)
		c.n += width
		if c.n >= 8 {
			c.n -= 8
			return byte(c.bits >> uint(c.n) & 255), true
		}
	}
	return 0, false
}

func (c *assembledForwardCursor) nextRune() (rune, bool) {
	b, ok := c.nextByte()
	if !ok {
		return 0, false
	}
	if b < utf8.RuneSelf {
		return rune(b), true
	}
	var buf [utf8.UTFMax]byte
	buf[0] = b
	n := 1
	for !utf8.FullRune(buf[:n]) && n < len(buf) {
		b, ok = c.nextByte()
		if !ok {
			return 0, false
		}
		buf[n] = b
		n++
	}
	value, size := utf8.DecodeRune(buf[:n])
	return value, size == n && value != utf8.RuneError
}

// The dotted branch is [MN][A-Za-z0-9]{23,} before its first dot, so the 23
// runes ending at that dot are class members, under the same simple folding.
// after is the decoded byte count from the dot to the cue's last complete byte.
func assembledDottedLeadingRun(text string, position assembledPosition, after int) bool {
	const leading = 23
	ref := assembledOrigin(text, position, after+leading*utf8.UTFMax)
	var data []byte
	assembledReplay(text, position.codec, ref.raw, position.end, ref.skip, func(b byte, _ int) bool {
		data = append(data, b)
		return true
	})
	if len(data) < after {
		return false
	}
	before := data[:len(data)-after]
	for range leading {
		r, size := utf8.DecodeLastRune(before)
		member := r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == 'ſ' || r == 'K'
		if size == 0 || !member {
			return false
		}
		before = before[:len(before)-size]
	}
	return true
}

func assembledShortEligible(text string, codec, phase, symbols, end int, hit reassemblyNeedle) bool {
	if hit.kind == 0 {
		return true
	}
	c := &reassemblyCodecs[codec]
	startBit := (symbols-hit.length)*c.width - hit.delta
	if startBit < phase*c.width {
		return false
	}
	literalByte := (startBit - phase*c.width) / 8
	count := (symbols - phase) * c.width / 8
	ref := assembledOrigin(text, assembledPosition{codec, phase, symbols, end}, count-literalByte)
	cursor := assembledForwardCursor{text: text, codec: codec, raw: ref.raw, skip: int(ref.skip)}
	next, ok := cursor.nextRune()
	if !ok {
		return false
	}
	if hit.kind == 1 {
		if next != '.' {
			return false
		}
		for range 6 {
			v, ok := cursor.nextRune()
			member := v >= 'A' && v <= 'Z' || v >= 'a' && v <= 'z' || v >= '0' && v <= '9' || v == '-' || v == '_' || v == '\u017f' || v == '\u212a'
			if !ok || !member {
				return false
			}
		}
		v, ok := cursor.nextRune()
		// Reject an invalid middle segment before replaying the leading run.
		return ok && v == '.' && assembledDottedLeadingRun(text, assembledPosition{codec, phase, symbols, end}, count-literalByte)
	}
	if next != 'S' && next != 's' && next != '\u017f' {
		return false
	}
	next, ok = cursor.nextRune()
	if !ok || next != 'K' && next != 'k' && next != '\u212a' {
		return false
	}
	for range 32 {
		v, ok := cursor.nextByte()
		member := v >= '0' && v <= '9' || v >= 'a' && v <= 'f' || v >= 'A' && v <= 'F'
		if !ok || !member {
			return false
		}
	}
	return true
}
