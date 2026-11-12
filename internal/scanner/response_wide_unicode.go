// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"
)

// decodeLikelyWideResponseBody recognizes UTF-32 BE and LE. Unicode Standard
// section 3.9 defines a scalar as U+0000..U+D7FF or U+E000..U+10FFFF, so a
// surrogate or a unit above U+10FFFF is not UTF-32. The prefix ff fe 00 00
// also starts valid UTF-16LE with a leading NUL, so retain its legacy UTF-16
// interpretation. Existing NUL normalization also covers ASCII UTF-32LE there.
// A BOM-less sample must be scalars and contain one ASCII unit (U+0001..U+007F).
// That ASCII unit is what separates this from an all-NUL sample and from the
// U+00FF pattern the boundary tests keep on the opaque path. The opposite
// endian of a non-zero BMP unit is above U+10FFFF, so the two orders do not
// both succeed.
func decodeLikelyWideResponseBody(ctx context.Context, data []byte) (string, bool, error) {
	var order binary.ByteOrder
	offset := 0
	if len(data) >= 4 {
		switch {
		case string(data[:4]) == "\xff\xfe\x00\x00":
			return decodeLikelyUTF16ResponseBody(ctx, data)
		case string(data[:4]) == "\x00\x00\xfe\xff":
			order = binary.BigEndian
			offset = 4
		default:
			if len(data) >= 8 && len(data)%4 == 0 {
				for _, candidate := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
					if utf32Sample(data, candidate) {
						order = candidate
						break
					}
				}
			}
		}
	}
	if order == nil {
		return decodeLikelyUTF16ResponseBody(ctx, data)
	}
	if (len(data)-offset)%4 != 0 {
		return "", false, fmt.Errorf("UTF-32 response has a truncated code unit")
	}
	var decoded strings.Builder
	decoded.Grow(len(data) - offset)
	for i := offset; i < len(data); i += 4 {
		if (i-offset)%responseBodyContextCheckBytes == 0 && ctx != nil {
			if err := ctx.Err(); err != nil {
				return "", false, err
			}
		}
		value := order.Uint32(data[i : i+4])
		r := utf8.RuneError
		if value <= utf8.MaxRune {
			r = rune(value)
			if !utf8.ValidRune(r) {
				r = utf8.RuneError
			}
		}
		decoded.WriteRune(r)
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
	}
	return decoded.String(), true, nil
}

// utf32Sample reports whether the leading units are Unicode scalars and one
// of them is ASCII. U+0000 is a scalar, so an all-NUL sample fails the ASCII
// requirement and stays off this path.
func utf32Sample(data []byte, order binary.ByteOrder) bool {
	ascii := false
	limit := min(len(data), 4096)
	for i := 0; i < limit; i += 4 {
		value := order.Uint32(data[i : i+4])
		if value > utf8.MaxRune || !utf8.ValidRune(rune(value)) {
			return false
		}
		if value >= 1 && value <= 0x7f {
			ascii = true
		}
	}
	return ascii
}
