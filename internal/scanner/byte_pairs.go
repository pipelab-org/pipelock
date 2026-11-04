// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

// bytePairFilter records which adjacent byte pairs occur in one text, hashed
// into 4096 bits. A literal of two or more bytes occurs in the text only if
// every one of its adjacent pairs does, so a literal with an unrecorded pair is
// absent without searching. Recorded pairs prove nothing: hash collisions and
// pairs at other positions both leave the literal possibly present, and callers
// then run the same substring search as before. The filter can only skip a
// search whose answer is already false.
type bytePairFilter [64]uint64

func bytePairIndex(a, b byte) uint16 {
	return uint16(a&63)<<6 | uint16(b&63)
}

func (f *bytePairFilter) add(text string) {
	for i := 1; i < len(text); i++ {
		idx := bytePairIndex(text[i-1], text[i])
		f[idx>>6] |= 1 << (idx & 63)
	}
}

// mayContain reports whether every pair is recorded. An empty pair list
// (a literal shorter than two bytes) is always possibly present.
func (f *bytePairFilter) mayContain(pairs []uint16) bool {
	for _, idx := range pairs {
		if f[idx>>6]&(1<<(idx&63)) == 0 {
			return false
		}
	}
	return true
}

// literalBytePairs lists the distinct pair indexes of literal, in order of
// first occurrence.
func literalBytePairs(literal string) []uint16 {
	var pairs []uint16
	for i := 1; i < len(literal); i++ {
		idx := bytePairIndex(literal[i-1], literal[i])
		seen := false
		for _, prior := range pairs {
			if prior == idx {
				seen = true
				break
			}
		}
		if !seen {
			pairs = append(pairs, idx)
		}
	}
	return pairs
}
