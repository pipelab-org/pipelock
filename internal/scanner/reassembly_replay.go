// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

// RFC 4648 sections 4-8 pack alphabet values most-significant-bit first.
// Terminal confirmation consumes only the decoded byte and its raw end, so
// this cursor omits the composed decoder's start and tail provenance records.
// Non-alphabet bytes don't consume bits, as in the existing replay contract.
func assembledReplay(text string, codec, start, end int, skip uint8, emit func(byte, int) bool) {
	c := &reassemblyCodecs[codec]
	var bits uint32
	nbits, drop := 0, int(skip)
	for i := start; i < end; i++ {
		value := c.values[text[i]]
		if value < 0 {
			continue
		}
		if drop >= c.width {
			drop -= c.width
			continue
		}
		n := c.width - drop
		drop = 0
		bits = bits<<uint(n) | uint32(value)&uint32((1<<n)-1)
		nbits += n
		if nbits >= 8 {
			nbits -= 8
			if !emit(byte(bits>>uint(nbits)&255), i+1) {
				return
			}
		}
	}
}
