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

// decodeLikelyWideResponseBody recognizes UTF-32BE BOMs and BOM-less ASCII
// UTF-32 code units (Unicode Standard section 3.9). The prefix ff fe 00 00
// also starts valid UTF-16LE with a leading NUL, so retain its legacy UTF-16
// interpretation. Existing NUL normalization also covers ASCII UTF-32LE there.
// BOM-less UTF-32 recognition requires ASCII scalars with three zero bytes.
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
					ascii := true
					for i := 0; i < min(len(data), 4096); i += 4 {
						v := candidate.Uint32(data[i : i+4])
						if v == 0 || v > 0x7f {
							ascii = false
							break
						}
					}
					if ascii {
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
