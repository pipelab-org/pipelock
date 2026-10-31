// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fileinspect

import "encoding/binary"

// knownBinarySignature reports whether data begins with a published image,
// font, or media signature. A declared content type is never consulted.
// SVG is text (it is XML) and is not handled here.
func knownBinarySignature(data []byte) bool {
	return knownFontSignature(data) || knownImageSignature(data) || knownMediaSignature(data)
}

// knownFontSignature is the OpenType/TrueType and WOFF magic numbers:
// OpenType 1.9.1 OFF 'OTTO' and 'true'/'typ1'/0x00010000, WOFF 1.0 'wOFF',
// WOFF2 'wOF2'.
func knownFontSignature(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	switch string(data[:4]) {
	case "\x00\x01\x00\x00", "true", "typ1", "OTTO", "wOFF", "wOF2":
		return true
	default:
		return false
	}
}

func knownImageSignature(data []byte) bool {
	switch {
	case len(data) >= 8 && string(data[:8]) == "\x89PNG\r\n\x1a\n":
		// PNG specification, section 5.2.
		return true
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		// ISO/IEC 10918-1, start-of-image marker.
		return true
	case len(data) >= 6 && (string(data[:6]) == "GIF87a" || string(data[:6]) == "GIF89a"):
		return true
	case len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		// WebP container, RIFF fourcc.
		return true
	case len(data) >= 4 && (string(data[:4]) == "II*\x00" || string(data[:4]) == "MM\x00*"):
		// TIFF 6.0, Image File Header byte order.
		return true
	case bitmapFileHeader(data):
		return true
	case len(data) >= 44 && binary.LittleEndian.Uint32(data) == 1 && string(data[40:44]) == " EMF":
		// [MS-EMF] 2.2.9: type 0x00000001 and signature " EMF".
		return true
	case len(data) >= 4 && binary.LittleEndian.Uint32(data) == 0x9AC6CDD7:
		// [MS-WMF] 2.3.2.3 placeable header key.
		return true
	case len(data) >= 18 && wmfMetaHeader(data):
		// [MS-WMF] 2.3.2.2 META_HEADER: type 1 or 2 and header size 9 words.
		return true
	case len(data) >= 6 && string(data[:6]) == "VCLMTF":
		// StarView Metafile. Calligra libsvm SPEC: an SVM file always starts
		// with the six-byte signature "VCLMTF". LibreOffice writes chart
		// replacement images in this form.
		return true
	default:
		return false
	}
}

// bitmapFileHeader requires the published "BM" type and zero reserved fields.
// BITMAPFILEHEADER, Microsoft bitmap file format. "BM" alone is not enough.
func bitmapFileHeader(data []byte) bool {
	return len(data) >= 14 && data[0] == 'B' && data[1] == 'M' &&
		binary.LittleEndian.Uint16(data[6:]) == 0 && binary.LittleEndian.Uint16(data[8:]) == 0
}

func wmfMetaHeader(data []byte) bool {
	kind := binary.LittleEndian.Uint16(data)
	size := binary.LittleEndian.Uint16(data[2:])
	return (kind == 1 || kind == 2) && size == 9
}

func knownMediaSignature(data []byte) bool {
	switch {
	case len(data) >= 12 && string(data[:4]) == "RIFF" && (string(data[8:12]) == "WAVE" || string(data[8:12]) == "AVI "):
		return true
	case len(data) >= 12 && string(data[:4]) == "FORM" && string(data[8:12]) == "AIFF":
		return true
	case len(data) >= 8 && string(data[4:8]) == "ftyp":
		// ISO/IEC 14496-12, file-type box.
		return true
	case len(data) >= 4 && string(data[:4]) == "OggS":
		// RFC 3533.
		return true
	case len(data) >= 4 && string(data[:4]) == "fLaC":
		return true
	case len(data) >= 4 && string(data[:4]) == "\x1aE\xdf\xa3":
		// Matroska/WebM EBML header.
		return true
	case len(data) >= 3 && string(data[:3]) == "ID3":
		return true
	case len(data) >= 4 && string(data[:4]) == ".snd":
		return true
	case len(data) >= 4 && string(data[:4]) == "MThd":
		return true
	default:
		return false
	}
}
