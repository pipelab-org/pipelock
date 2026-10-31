// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fileinspect

import (
	"encoding/binary"
	"strings"
	"testing"
)

// pad extends a signature prefix to n bytes so length guards are not what
// decides the case.
func pad(prefix string, n int) []byte {
	if len(prefix) >= n {
		return []byte(prefix)
	}
	return []byte(prefix + strings.Repeat("\x00", n-len(prefix)))
}

func emfHeader() []byte {
	b := make([]byte, 44)
	binary.LittleEndian.PutUint32(b, 1)
	copy(b[40:], " EMF")
	return b
}

func wmfHeader(kind, size uint16) []byte {
	b := make([]byte, 18)
	binary.LittleEndian.PutUint16(b, kind)
	binary.LittleEndian.PutUint16(b[2:], size)
	return b
}

func TestKnownBinarySignature(t *testing.T) {
	placeable := make([]byte, 4)
	binary.LittleEndian.PutUint32(placeable, 0x9AC6CDD7)
	bmpReserved := pad("BM", 14)
	bmpReserved[6] = 1

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		// Fonts.
		{"truetype", pad("\x00\x01\x00\x00", 12), true},
		{"opentype", pad("OTTO", 12), true},
		{"woff2", pad("wOF2", 12), true},
		{"font too short", []byte("OTT"), false},
		// Images.
		{"png", pad("\x89PNG\r\n\x1a\n", 16), true},
		{"png truncated", []byte("\x89PNG\r\n\x1a"), false},
		{"jpeg", pad("\xff\xd8\xff", 8), true},
		{"jpeg wrong marker", pad("\xff\xd8\x00", 8), false},
		{"gif87a", pad("GIF87a", 8), true},
		{"gif89a", pad("GIF89a", 8), true},
		{"gif other version", pad("GIF90a", 8), false},
		{"webp", pad("RIFF\x00\x00\x00\x00WEBP", 16), true},
		{"riff unknown form", pad("RIFF\x00\x00\x00\x00ABCD", 16), false},
		{"tiff little endian", pad("II*\x00", 8), true},
		{"tiff big endian", pad("MM\x00*", 8), true},
		{"bmp", pad("BM", 14), true},
		{"bmp nonzero reserved", bmpReserved, false},
		{"bmp too short", pad("BM", 13), false},
		{"emf", emfHeader(), true},
		{"emf wrong signature", func() []byte { b := emfHeader(); b[41] = 'X'; return b }(), false},
		{"emf too short", emfHeader()[:43], false},
		{"wmf placeable", placeable, true},
		{"wmf memory metafile", wmfHeader(1, 9), true},
		{"wmf disk metafile", wmfHeader(2, 9), true},
		{"wmf wrong header size", wmfHeader(1, 8), false},
		{"wmf wrong type", wmfHeader(3, 9), false},
		{"starview metafile", pad("VCLMTF", 8), true},
		// Media.
		{"wave", pad("RIFF\x00\x00\x00\x00WAVE", 16), true},
		{"avi", pad("RIFF\x00\x00\x00\x00AVI ", 16), true},
		{"aiff", pad("FORM\x00\x00\x00\x00AIFF", 16), true},
		{"form unknown", pad("FORM\x00\x00\x00\x00ABCD", 16), false},
		{"iso base media", pad("\x00\x00\x00\x18ftypmp42", 16), true},
		{"ogg", pad("OggS", 8), true},
		{"flac", pad("fLaC", 8), true},
		{"matroska", pad("\x1aE\xdf\xa3", 8), true},
		{"mp3 id3", pad("ID3", 8), true},
		{"sun audio", pad(".snd", 8), true},
		{"midi", pad("MThd", 8), true},
		// Text is never a binary member.
		{"xml text", []byte(`<?xml version="1.0"?><w:document/>`), false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := knownBinarySignature(tc.data); got != tc.want {
				t.Fatalf("knownBinarySignature(%q) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}
