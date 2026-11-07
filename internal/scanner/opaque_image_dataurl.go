// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/media"
)

const dataImagePrefix = "data:image/"

// exciseVerifiedImageDataURLs removes supported data:image and structured bare
// base64 image payloads whose
// base64 bytes verify as a complete image, discarding the decoded bytes.
//
// This is the injection/response-scanning variant. A structurally valid image's
// raw bytes are not text the model interprets as instructions (multimodal
// prompt injection travels through rendered pixels, which are not scannable
// here), so dropping the decoded bytes avoids the normalization false positives
// (e.g. vowel-folded "DAN") that scanning random binary produces. Surrounding
// text remains joined so a secret split around an image does not gain a
// delimiter-based bypass.
func exciseVerifiedImageDataURLs(text string) string {
	excised, _ := stripVerifiedImageDataURLs(text, false)
	return excised
}

// exciseImagesRetainingDecodedForDLP removes the base64 *text* of verified image
// payloads (the surface that false-positives: a base64 alphabet run reads as a
// secret-shaped token) but APPENDS the decoded image bytes so a secret smuggled
// inside a structurally valid image — e.g. a literal credential in a PNG tEXt
// chunk or a JPEG comment segment — is still caught by DLP. The false positives
// come from the base64 text (a large fraction of random images contain a
// secret-shaped alphabet run); the decoded image bytes do not false-positive on
// DLP secret patterns yet still expose a literal embedded secret. This is the
// DLP (outbound exfiltration) variant: dropping the decoded bytes here would
// open a "wrap the secret in a valid image" exfiltration bypass.
func exciseImagesRetainingDecodedForDLP(text string) string {
	excised, decoded := stripVerifiedImageDataURLs(text, true)
	if len(decoded) == 0 {
		return excised
	}
	var b strings.Builder
	b.Grow(len(excised) + len(decoded) + 1)
	b.WriteString(excised)
	// A newline keeps the rejoined surrounding text and the decoded image bytes
	// as separate regions so the two cannot be spliced into one spurious token.
	b.WriteByte('\n')
	b.WriteString(decoded)
	return b.String()
}

// stripVerifiedImageDataURLs removes verified data-URL and bare JSON image payloads
// from text and returns the excised text. When retainDecoded is set it also
// returns the concatenated decoded image bytes (newline-separated, one trailing
// newline per image); callers that only need the base64 text removed pass false
// to skip that allocation.
func stripVerifiedImageDataURLs(text string, retainDecoded bool) (excised, decodedConcat string) {
	excised, decodedConcat, _ = stripVerifiedImageDataURLSpans(text, retainDecoded)
	return excised, decodedConcat
}

// stripVerifiedImageDataURLSpans is stripVerifiedImageDataURLs that also
// returns the removed byte ranges of text, in order, so a position in the
// excised text can be mapped back to the original.
func stripVerifiedImageDataURLSpans(text string, retainDecoded bool) (excised, decodedConcat string, removed []textByteSpan) {
	searchFrom := 0
	copyFrom := 0
	var out strings.Builder
	var decoded strings.Builder
	type imageSpan struct {
		start, end int
		data       []byte
	}
	var images []imageSpan
	for _, span := range media.BareImagePayloadSpans(text) {
		if imageBytes, ok := decodeVerifiedImage(span.Payload, span.MediaType); ok {
			images = append(images, imageSpan{span.Start, span.End, imageBytes})
		}
	}

	for searchFrom < len(text) {
		rel := indexDataImagePrefix(text[searchFrom:])
		if rel < 0 {
			break
		}
		start := searchFrom + rel
		headerEndRel := strings.IndexByte(text[start:], ',')
		if headerEndRel < 0 {
			break
		}
		headerEnd := start + headerEndRel
		payloadStart := headerEnd + 1
		if !isPNGOrJPEGBase64DataImageHeader(text[start:headerEnd]) {
			searchFrom = payloadStart
			continue
		}

		payloadEnd := dataURLBase64PayloadEnd(text, payloadStart)
		if payloadEnd <= payloadStart {
			searchFrom = payloadStart
			continue
		}
		declared := dataURLVerificationType(strings.SplitN(strings.ToLower(text[start:headerEnd]), ";", 2)[0][len("data:"):])
		decodedImage, ok := decodeVerifiedImage(text[payloadStart:payloadEnd], declared)
		if !ok {
			searchFrom = payloadStart
			continue
		}

		images = append(images, imageSpan{start, payloadEnd, decodedImage})
		searchFrom = payloadEnd
	}
	sort.Slice(images, func(i, j int) bool { return images[i].start < images[j].start })
	for _, span := range images {
		if out.Cap() == 0 {
			out.Grow(len(text))
		}
		out.WriteString(text[copyFrom:span.start])
		removed = append(removed, textByteSpan{start: span.start, end: span.end})
		copyFrom = span.end
		if retainDecoded {
			decoded.Write(span.data)
			decoded.WriteByte('\n')
		}
	}

	if out.Cap() == 0 {
		return text, "", nil
	}
	out.WriteString(text[copyFrom:])
	return out.String(), decoded.String(), removed
}

func indexDataImagePrefix(text string) int {
	if len(text) < len(dataImagePrefix) {
		return -1
	}
	for i := 0; i <= len(text)-len(dataImagePrefix); i++ {
		if asciiEqualFold(text[i:i+len(dataImagePrefix)], dataImagePrefix) {
			return i
		}
	}
	return -1
}

func asciiEqualFold(s, target string) bool {
	if len(s) != len(target) {
		return false
	}
	for i := 0; i < len(s); i++ {
		a, b := s[i], target[i]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

func isPNGOrJPEGBase64DataImageHeader(header string) bool {
	parts := strings.Split(strings.ToLower(header), ";")
	if len(parts) < 2 {
		return false
	}
	switch parts[0] {
	case "data:image/png", "data:image/jpeg", "data:image/jpg", "data:image/gif", "data:image/webp":
	default:
		return false
	}
	for _, part := range parts[1:] {
		if strings.TrimSpace(part) == "base64" {
			return true
		}
	}
	return false
}

func dataURLBase64PayloadEnd(text string, start int) int {
	i := start
	seenPadding := false
	padding := 0
	for i < len(text) {
		c := text[i]
		if isBase64DataURLByte(c) {
			if seenPadding {
				break
			}
			i++
			continue
		}
		if c == '=' {
			if padding >= 2 {
				break
			}
			seenPadding = true
			padding++
			i++
			continue
		}
		break
	}
	return i
}

func isBase64DataURLByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '+' || c == '/' ||
		c == '-' || c == '_'
}

// decodeVerifiedPNGOrJPEG decodes the base64 payload and returns the image bytes
// only if they parse as a complete PNG or JPEG. The returned bytes are what DLP
// re-scans so a secret embedded inside a structurally valid image is not lost.
func decodeVerifiedPNGOrJPEG(payload string) ([]byte, bool) {
	return decodeVerifiedImage(payload, "")
}

func decodeVerifiedImage(payload, declared string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(payload)
		if err != nil || len(decoded) == 0 {
			continue
		}
		if completeImageMatchesType(decoded, declared) {
			return decoded, true
		}
	}
	return nil, false
}

func isCompletePNG(data []byte) bool {
	if len(data) < 8 || string(data[:8]) != "\x89PNG\r\n\x1a\n" {
		return false
	}
	pos := 8
	seenIHDR := false
	seenIDAT := false
	for {
		if len(data)-pos < 12 {
			return false
		}
		length := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		if length < 0 || length > len(data)-pos-12 {
			return false
		}
		chunkTypeStart := pos + 4
		chunkDataStart := pos + 8
		chunkDataEnd := chunkDataStart + length
		crcStart := chunkDataEnd
		crcEnd := crcStart + 4

		wantCRC := binary.BigEndian.Uint32(data[crcStart:crcEnd])
		if gotCRC := crc32.ChecksumIEEE(data[chunkTypeStart:chunkDataEnd]); gotCRC != wantCRC {
			return false
		}

		chunkType := string(data[chunkTypeStart:chunkDataStart])
		switch chunkType {
		case "IHDR":
			if seenIHDR || pos != 8 || length != 13 {
				return false
			}
			seenIHDR = true
		case "IDAT":
			if !seenIHDR {
				return false
			}
			seenIDAT = true
		case "IEND":
			return seenIHDR && seenIDAT && length == 0 && crcEnd == len(data)
		}
		pos = crcEnd
	}
}

func isCompleteJPEG(data []byte) bool {
	if len(data) < 4 || data[0] != 0xff || data[1] != 0xd8 {
		return false
	}
	pos := 2
	seenSOF := false
	var frameComponents [256]bool
	for pos < len(data) {
		if data[pos] != 0xff {
			return false
		}
		for pos < len(data) && data[pos] == 0xff {
			pos++
		}
		if pos >= len(data) {
			return false
		}
		marker := data[pos]
		pos++

		switch {
		case marker == 0xd9:
			return false
		case marker >= 0xd0 && marker <= 0xd7:
			continue
		case marker == 0x01 || marker == 0xd8:
			continue
		}

		if len(data)-pos < 2 {
			return false
		}
		segmentLength := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		if segmentLength < 2 || segmentLength > len(data)-pos {
			return false
		}
		segmentEnd := pos + segmentLength
		if segmentEnd > len(data) {
			return false
		}
		if isJPEGSOFMarker(marker) {
			if seenSOF || !parseJPEGFrameHeader(data[pos:segmentEnd], &frameComponents) {
				return false
			}
			seenSOF = true
		}
		if marker == 0xda {
			if !seenSOF || !validJPEGScanHeader(data[pos:segmentEnd], &frameComponents) {
				return false
			}
			pos = segmentEnd
			for pos < len(data) {
				if data[pos] != 0xff {
					pos++
					continue
				}
				if pos+1 >= len(data) {
					return false
				}
				next := data[pos+1]
				switch {
				case next == 0x00:
					pos += 2
				case next >= 0xd0 && next <= 0xd7:
					pos += 2
				case next == 0xd9:
					pos += 2
					return seenSOF && pos == len(data)
				default:
					return false
				}
			}
			return false
		}
		pos = segmentEnd
	}
	return false
}

func parseJPEGFrameHeader(segment []byte, components *[256]bool) bool {
	if len(segment) < 11 {
		return false
	}
	componentCount := int(segment[7])
	if componentCount == 0 || len(segment) != 8+3*componentCount {
		return false
	}
	for i := range componentCount {
		offset := 8 + 3*i
		id := segment[offset]
		sampling := segment[offset+1]
		if components[id] || sampling>>4 == 0 || sampling&0x0f == 0 {
			return false
		}
		components[id] = true
	}
	return true
}

func validJPEGScanHeader(segment []byte, components *[256]bool) bool {
	if len(segment) < 8 {
		return false
	}
	componentCount := int(segment[2])
	if componentCount == 0 || len(segment) != 6+2*componentCount {
		return false
	}
	var seen [256]bool
	for i := range componentCount {
		offset := 3 + 2*i
		id := segment[offset]
		tables := segment[offset+1]
		if !components[id] || seen[id] || tables>>4 > 3 || tables&0x0f > 3 {
			return false
		}
		seen[id] = true
	}
	return true
}

func isJPEGSOFMarker(marker byte) bool {
	switch marker {
	case 0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf:
		return true
	default:
		return false
	}
}

// dataURLVerificationType keeps the shipped data-URL contract: a png, jpeg or
// jpg label accepts either complete PNG or JPEG bytes, since clients commonly
// mislabel one as the other and the decoded bytes are retained for DLP either
// way. GIF and WebP labels, added with bare carriers, stay bound to their bytes.
func dataURLVerificationType(declared string) string {
	switch declared {
	case "image/gif", "image/webp":
		return declared
	default:
		return ""
	}
}

// completeImageMatchesType keeps the declared media type bound to its bytes.
// Empty declarations are used only by the legacy PNG/JPEG helper.
func completeImageMatchesType(data []byte, declared string) bool {
	switch declared {
	case "":
		return isCompletePNG(data) || isCompleteJPEG(data)
	case "image/png":
		return isCompletePNG(data)
	case "image/jpeg", "image/jpg":
		return isCompleteJPEG(data)
	case "image/gif":
		return isCompleteGIF(data)
	case "image/webp":
		return isCompleteWebP(data)
	default:
		return false
	}
}

// GIF89a sections 15-27 define the screen descriptor, color tables, image
// blocks, extension sub-blocks and final trailer. Walk their lengths without
// allocating pixels. https://www.w3.org/Graphics/GIF/spec-gif89a.txt
func isCompleteGIF(data []byte) bool {
	if len(data) < 14 || (string(data[:6]) != "GIF87a" && string(data[:6]) != "GIF89a") ||
		binary.LittleEndian.Uint16(data[6:8]) == 0 || binary.LittleEndian.Uint16(data[8:10]) == 0 {
		return false
	}
	pos := 13
	if data[10]&0x80 != 0 {
		pos += 3 * (1 << ((data[10] & 7) + 1))
	}
	seenImage := false
	for pos < len(data) {
		kind := data[pos]
		pos++
		switch kind {
		case 0x3b:
			return seenImage && pos == len(data)
		case 0x21:
			if pos >= len(data) {
				return false
			}
			pos++
		case 0x2c:
			if len(data)-pos < 9 || binary.LittleEndian.Uint16(data[pos+4:pos+6]) == 0 || binary.LittleEndian.Uint16(data[pos+6:pos+8]) == 0 {
				return false
			}
			packed := data[pos+8]
			pos += 9
			if packed&0x80 != 0 {
				pos += 3 * (1 << ((packed & 7) + 1))
			}
			if pos >= len(data) || data[pos] < 2 || data[pos] > 8 {
				return false
			}
			pos++
			seenImage = true
		default:
			return false
		}
		for {
			if pos >= len(data) {
				return false
			}
			size := int(data[pos])
			pos++
			if size > len(data)-pos {
				return false
			}
			pos += size
			if size == 0 {
				break
			}
		}
	}
	return false
}

// WebP uses a size-delimited RIFF file and padded chunks. Require an image
// bitstream (or an animated frame containing one) and consume the entire file.
// https://developers.google.com/speed/webp/docs/riff_container
func isCompleteWebP(data []byte) bool {
	if len(data) < 20 || string(data[:4]) != "RIFF" || string(data[8:12]) != "WEBP" ||
		uint64(binary.LittleEndian.Uint32(data[4:8]))+8 != uint64(len(data)) {
		return false
	}
	return completeWebPChunks(data[12:], false)
}

func completeWebPChunks(data []byte, frame bool) bool {
	seenImage := false
	for len(data) > 0 {
		if len(data) < 8 {
			return false
		}
		size := int(binary.LittleEndian.Uint32(data[4:8]))
		if size < 0 || size > len(data)-8 {
			return false
		}
		padded := size + (size & 1)
		if padded > len(data)-8 {
			return false
		}
		if size&1 != 0 && data[8+size] != 0 {
			return false
		}
		body := data[8 : 8+size]
		switch string(data[:4]) {
		case "VP8 ":
			if len(body) < 10 || body[0]&1 != 0 || string(body[3:6]) != "\x9d\x01\x2a" ||
				binary.LittleEndian.Uint16(body[6:8])&0x3fff == 0 || binary.LittleEndian.Uint16(body[8:10])&0x3fff == 0 {
				return false
			}
			seenImage = true
		case "VP8L":
			if len(body) < 5 || body[0] != 0x2f || body[4]>>5 != 0 {
				return false
			}
			seenImage = true
		case "ANMF":
			if frame || len(body) < 16 || !completeWebPChunks(body[16:], true) {
				return false
			}
			seenImage = true
		}
		data = data[8+padded:]
	}
	return seenImage
}
