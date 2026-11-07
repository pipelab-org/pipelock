// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package media

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"sort"
	"strings"
)

// ImagePayloadSpan identifies a bare base64 JSON string with an image media
// declaration in the same object. Start and End exclude its JSON quotes.
// Recognition only nominates a payload: callers must verify its full container
// before removing encoded text from a scan view.
type ImagePayloadSpan struct {
	Start, End int
	MediaType  string
	Payload    string
	inferred   bool
}

// BareImagePayloadSpans preserves the media declaration that scalar extraction
// otherwise loses. Anthropic image sources use media_type and MCP image blocks
// use mimeType. Both carry base64 in data; resource blobs use blob.
// https://platform.claude.com/docs/en/build-with-claude/vision
// https://modelcontextprotocol.io/specification/2025-06-18/server/tools#image-content
// OpenAI Images returns b64_json without a media declaration; its signature
// nominates the type instead (the full container still has to verify).
// https://github.com/openai/openai-python/blob/main/src/openai/types/image.py
// Invalid JSON or ambiguous declarations receive no special treatment.
func BareImagePayloadSpans(text string) []ImagePayloadSpan {
	if !strings.Contains(text, `"data"`) && !strings.Contains(text, `"blob"`) && !strings.Contains(text, `"raw"`) && !strings.Contains(text, `"b64_json"`) && !strings.Contains(text, `\`) {
		return nil
	}
	type frame struct {
		object, key bool
		name, mime  string
		declared    bool
		ambiguous   bool
		payloads    []ImagePayloadSpan
	}
	var stack []frame
	var spans []ImagePayloadSpan
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	for {
		before := int(dec.InputOffset())
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil
		}
		switch v := token.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if len(stack) > 0 && stack[len(stack)-1].object {
					f := &stack[len(stack)-1]
					if !f.key && isImageMediaField(f.name) {
						f.ambiguous = true
					}
					f.key = true
				}
				stack = append(stack, frame{object: v == '{', key: v == '{'})
			case '}', ']':
				if len(stack) == 0 {
					return nil
				}
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if !f.ambiguous {
					for _, span := range f.payloads {
						declared := f.mime
						if !f.declared && span.inferred {
							declared = imagePayloadType(span.Payload)
						}
						if imagePayloadMagicMatches(span.Payload, declared) {
							span.MediaType = declared
							spans = append(spans, span)
						}
					}
				}
			}
		case string:
			if len(stack) == 0 {
				continue
			}
			f := &stack[len(stack)-1]
			if !f.object {
				continue
			}
			if f.key {
				f.name = v
				f.key = false
				continue
			}
			switch f.name {
			case "media_type", "mimeType", "mime_type", "mediaType":
				if f.declared {
					f.ambiguous = true
				}
				f.mime = strings.ToLower(v)
				f.declared = true
			case "data", "blob", "raw", "b64_json":
				// InputOffset ends at the closing quote. Locate the opening
				// quote after the preceding colon/whitespace, retaining raw
				// coordinates even when JSON escaped some base64 bytes.
				end := int(dec.InputOffset()) - 1
				quote := strings.IndexByte(text[before:end], '"')
				if quote >= 0 {
					start := before + quote + 1
					f.payloads = append(f.payloads, ImagePayloadSpan{Start: start, End: end, Payload: v, inferred: f.name == "b64_json"})
				}
			}
			f.key = true
		default:
			if len(stack) > 0 && stack[len(stack)-1].object {
				f := &stack[len(stack)-1]
				if !f.key && isImageMediaField(f.name) {
					f.ambiguous = true
				}
				f.key = true
			}
		}
	}
	if len(stack) != 0 || !json.Valid([]byte(text)) {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
	return spans
}

func isImageMediaField(name string) bool {
	return name == "media_type" || name == "mimeType" || name == "mime_type" || name == "mediaType"
}

func imagePayloadMagicMatches(payload, declared string) bool {
	return declared != "" && imagePayloadType(payload) == declared
}

func imagePayloadType(payload string) string {
	// DetectType reads at most 16 bytes. Decode only the corresponding full
	// base64 groups here; full decoding and completeness belong to the scanner.
	if len(payload) < 24 || !imageBase64Alphabet(payload) {
		return ""
	}
	var prefix [18]byte
	n, err := base64.StdEncoding.Decode(prefix[:], []byte(payload[:24]))
	if err != nil {
		return ""
	}
	if string(prefix[:6]) == "GIF87a" || string(prefix[:6]) == "GIF89a" {
		return "image/gif"
	}
	switch detected := DetectType(prefix[:n]); detected {
	case "image/png", "image/jpeg", "image/webp":
		return detected
	default:
		return ""
	}
}

// ImageDataURLView adds declared image headers to a JSON scan copy, so existing
// verified-data-URL scanning also applies after scalar extraction. It never
// changes the delivered body or drops bytes; invalid candidates remain intact.
func ImageDataURLView(raw []byte) []byte {
	spans := BareImagePayloadSpans(string(raw))
	if len(spans) == 0 {
		return raw
	}
	var out strings.Builder
	pos := 0
	for _, span := range spans {
		out.Write(raw[pos:span.Start])
		out.WriteString("data:" + span.MediaType + ";base64,")
		out.WriteString(span.Payload)
		// Scalar joins may put another alphabet-only field immediately after
		// an unpadded image. A scan-only JSON newline bounds the data URL;
		// DLP normalization still rejoins secrets around the excised image.
		out.WriteString(`\n`)
		pos = span.End
	}
	out.Write(raw[pos:])
	return []byte(out.String())
}

// RFC 4648 section 4 permits only this alphabet and terminal padding. Validate
// the entire scalar before adding a data-URL header: otherwise punctuation
// could make the data-URL parser accept just a valid image prefix of garbage.
func imageBase64Alphabet(payload string) bool {
	n := len(payload)
	padding := 0
	for n > 0 && payload[n-1] == '=' {
		n--
		padding++
	}
	if padding > 2 || (padding > 0 && len(payload)%4 != 0) || n%4 == 1 {
		return false
	}
	for i := 0; i < n; i++ {
		c := payload[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
		default:
			return false
		}
	}
	return true
}
