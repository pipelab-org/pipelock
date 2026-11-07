// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/gif"
	"testing"
)

func TestCompleteGIFValidation(t *testing.T) {
	var encoded bytes.Buffer
	if err := gif.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 1, 1)), nil); err != nil {
		t.Fatal(err)
	}
	valid := encoded.Bytes()
	// One image with a local color table and a GIF comment extension.
	local := []byte("GIF89a\x01\x00\x01\x00\x00\x00\x00\x21\xfe\x01x\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x80\x00\x00\x00\xff\xff\xff\x02\x02\x44\x01\x00\x3b")
	tests := []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"encoder", valid, true},
		{"local palette", local, true},
		{"short", valid[:6], false},
		{"signature", mutateBytes(valid, func(b []byte) { b[0] = 0 }), false},
		{"zero width", mutateBytes(valid, func(b []byte) { b[6] = 0; b[7] = 0 }), false},
		{"no image", []byte("GIF89a\x01\x00\x01\x00\x00\x00\x00\x3b"), false},
		{"missing trailer", valid[:len(valid)-1], false},
		{"trailing bytes", append(append([]byte(nil), valid...), 0), false},
		{"incomplete palette", local[:30], false},
		{"incomplete extension", local[:14], false},
		{"incomplete image descriptor", append(append([]byte(nil), local[:13]...), 0x2c), false},
		{"zero image width", mutateBytes(local, func(b []byte) { b[23] = 0 }), false},
		{"bad LZW minimum", mutateBytes(local, func(b []byte) { b[34] = 1 }), false},
		{"oversized subblock", mutateBytes(local, func(b []byte) { b[35] = 255 }), false},
		{"missing subblock end", local[:len(local)-2], false},
		{"unknown block", mutateBytes(local, func(b []byte) { b[13] = 0 }), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCompleteGIF(tt.data); got != tt.valid {
				t.Fatalf("valid=%v want %v", got, tt.valid)
			}
		})
	}
}

func TestCompleteWebPValidation(t *testing.T) {
	chunk := func(kind string, data []byte) []byte {
		out := append([]byte(kind), 0, 0, 0, 0)
		binary.LittleEndian.PutUint32(out[4:8], uint32(len(data))) //nolint:gosec // bounded fixture
		out = append(out, data...)
		if len(data)%2 != 0 {
			out = append(out, 0)
		}
		return out
	}
	riff := func(chunks ...[]byte) []byte {
		out := []byte("RIFF\x00\x00\x00\x00WEBP")
		for _, c := range chunks {
			out = append(out, c...)
		}
		binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)-8)) //nolint:gosec // bounded fixture
		return out
	}
	lossless := chunk("VP8L", []byte{0x2f, 0, 0, 0, 0, 0})
	lossy := chunk("VP8 ", []byte{0x30, 1, 0, 0x9d, 1, 0x2a, 1, 0, 1, 0, 0, 0})
	valid := riff(lossless)
	frame := chunk("ANMF", append(make([]byte, 16), lossless...))
	tests := []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"lossless", valid, true},
		{"lossy", riff(lossy), true},
		{"animation", riff(frame), true},
		{"unknown chunk", riff(lossless, chunk("JUNK", []byte{1})), true},
		{"missing padding", riff([]byte{'J', 'U', 'N', 'K', 1, 0, 0, 0, 1}), false},
		{"nonzero padding", mutateBytes(riff(lossless, chunk("JUNK", []byte{1})), func(b []byte) { b[len(b)-1] = 1 }), false},
		{"short", valid[:8], false},
		{"bad signature", mutateBytes(valid, func(b []byte) { b[0] = 0 }), false},
		{"bad size", mutateBytes(valid, func(b []byte) { b[4]++ }), false},
		{"incomplete chunk", riff([]byte("VP8L")), false},
		{"oversized chunk", riff([]byte{'V', 'P', '8', 'L', 255, 255, 255, 255}), false},
		{"no image", riff(chunk("JUNK", nil)), false},
		{"short lossless", riff(chunk("VP8L", []byte{0x2f})), false},
		{"bad lossless signature", riff(chunk("VP8L", []byte{0, 0, 0, 0, 0})), false},
		{"bad lossless version", riff(chunk("VP8L", []byte{0x2f, 0, 0, 0, 0xe0})), false},
		{"short lossy", riff(chunk("VP8 ", nil)), false},
		{"bad lossy signature", riff(chunk("VP8 ", make([]byte, 10))), false},
		{"interframe", riff(chunk("VP8 ", []byte{1, 0, 0, 0x9d, 1, 0x2a, 1, 0, 1, 0})), false},
		{"zero lossy width", riff(chunk("VP8 ", []byte{0, 0, 0, 0x9d, 1, 0x2a, 0, 0, 1, 0})), false},
		{"short frame", riff(chunk("ANMF", nil)), false},
		{"empty frame", riff(chunk("ANMF", make([]byte, 16))), false},
		{"nested frame", riff(chunk("ANMF", append(make([]byte, 16), frame...))), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCompleteWebP(tt.data); got != tt.valid {
				t.Fatalf("valid=%v want %v", got, tt.valid)
			}
		})
	}
}
