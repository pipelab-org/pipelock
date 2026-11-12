// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/net/html"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

type outboundInjectionContextKey struct{}

// ScanResponseOutbound scans text the agent sends. Unlike inbound responses,
// an outbound decoding limit refuses delivery even under warn-only policy.
func (s *Scanner) ScanResponseOutbound(ctx context.Context, content string) ResponseScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	return s.ScanResponse(context.WithValue(ctx, outboundInjectionContextKey{}, true), content)
}

const injectionDecodeLimitReason = "injection inspection incomplete: decoding limit reached"

// injectionHTMLTextLabel marks the one HTML extraction on a decode lineage.
const injectionHTMLTextLabel = "html_text"

type injectionDecodeView struct {
	text, label string
	// applied lists transforms already run on this lineage. HTML extraction
	// is one tokenizer pass over a payload: running it again treats the
	// extracted text as markup and never reaches a fixed point.
	applied string
	depth   int
}

// scanAdditionalInjectionViews runs after the historical passes so their
// findings, order and coordinates remain unchanged. Only new decoded views
// are matched. A single transform of the scanned input, and one HTML
// extraction of that transform, is admitted when the view itself fits.
// Deeper copies share the retained-byte budget. Nesting uses the injection
// depth cap.
func (s *Scanner) scanAdditionalInjectionViews(ctx context.Context, content, target string, suppress []config.SuppressEntry, result ResponseScanResult) (out ResponseScanResult) {
	if ctx == nil {
		ctx = context.Background()
	}
	queue := []injectionDecodeView{{text: content}}
	seen := map[string]bool{content: true}
	used := 0
	incomplete := false
	defer func() {
		// A cancellation or other scan error already decides the result; a
		// decode limit reached before it must not replace that reason.
		if !incomplete || out.ScanError != "" {
			return
		}
		// A content finding already decides the verdict. The limit is partial
		// evidence beside it, matching text DLP and reassembly: inbound warns,
		// and outbound keeps the block instead of replacing it with a scan error.
		outbound, _ := ctx.Value(outboundInjectionContextKey{}).(bool)
		if len(out.Matches)+len(out.WarnedMatches) > 0 {
			if !outbound {
				s.EmitTextDLPWarnMatches(ctx, []TextDLPMatch{partialEncodedContentMatch()})
			}
			return
		}
		out.InspectionIncomplete = true
		if outbound {
			out.Clean = false
			out.ScanError = injectionDecodeLimitReason
		} else {
			s.EmitTextDLPWarnMatches(ctx, []TextDLPMatch{partialEncodedContentMatch()})
		}
	}()
	for head := 0; head < len(queue); head++ {
		if err := ctx.Err(); err != nil {
			result.Clean = false
			result.ScanError = err.Error()
			return result
		}
		parent := queue[head]
		if len(parent.text) > maxDecodeTotalBytes {
			// The caller already scanned this text. A larger plain payload is
			// not a decoding limit; only a transform we will not open is.
			if additionalInjectionTransformApplies(parent.text) || normalize.ContainsTags(parent.text) || hasTextEncoding(parent.text) {
				incomplete = true
			}
			continue
		}
		views, complete := additionalInjectionViews(parent.text, parent.applied)
		legacy, legacyComplete := injectionLegacyDecodeViews(parent.text)
		views = append(views, legacy...)
		complete = complete && legacyComplete
		incomplete = incomplete || !complete
		for _, view := range views {
			if view.text == "" || seen[view.text] {
				continue
			}
			// One transform of the scanned input, and HTML extraction of that
			// transform, must not push each other out of the retained-byte
			// budget. Charging them did: tag stripping was dropped on a page
			// still inside the response cap, including after entity decoding.
			htmlOfDecoded := view.label == injectionHTMLTextLabel && parent.depth == 1 && !strings.Contains(parent.applied, injectionHTMLTextLabel)
			charge := parent.depth > 0 && !htmlOfDecoded
			overBudget := len(view.text) > maxDecodeTotalBytes || (charge && len(view.text) > maxDecodeTotalBytes-used)
			if parent.depth >= responseDecodeMaxDepth || len(queue) >= maxDecodeCandidates || overBudget {
				// A leftover shorter than an encoded segment cannot hold a phrase.
				// The same floor is minSegmentDecodeLen.
				if view.label == "" && len(view.text) < minSegmentDecodeLen {
					continue
				}
				incomplete = true
				continue
			}
			seen[view.text] = true
			if charge {
				used += len(view.text)
			}
			view.depth = parent.depth + 1
			if view.label == "" {
				// A legacy payload is new text. Transforms run again; the
				// inherited label is provenance for the coordinates only.
				view.applied = ""
				view.label = parent.label
			} else {
				view.applied = spanViewLabel(view.label, parent.applied)
				view.label = spanViewLabel(view.label, parent.label)
			}
			queue = append(queue, view)
			if view.label == "" {
				continue
			}
			checked := s.scanResponseMatchesWithOptions(ctx, view.text, target, suppress, responseScanOptions{skipEncodedDecode: true}, newResponseMatchMemo(len(view.text)))
			if BlankViewAddsNoCoverage(view.text, checked) {
				continue
			}
			// Coordinates belong to a decoded view, never to the original body. A
			// strip caller must not rewrite the original using these offsets.
			for i := range checked.Matches {
				checked.Matches[i].span.ViewLabel = spanViewLabel(checked.Matches[i].span.ViewLabel, view.label)
			}
			checked.SuppressedMatches = append(result.SuppressedMatches, checked.SuppressedMatches...)
			checked.ObservedCoreMatches = append(result.ObservedCoreMatches, checked.ObservedCoreMatches...)
			checked.WarnedMatches = append(result.WarnedMatches, checked.WarnedMatches...)
			checked.StegoDetected = result.StegoDetected
			checked.StegoDensity = result.StegoDensity
			result = checked
			if !result.Clean || result.Failed() || len(result.WarnedMatches) > 0 {
				return result
			}
		}
	}
	if err := ctx.Err(); err != nil {
		result.Clean = false
		result.ScanError = err.Error()
	}
	return result
}

func hasAdditionalInjectionEncoding(text string) bool {
	return strings.ContainsAny(text, "&%<+") || strings.Contains(text, `\u`)
}

// additionalInjectionTransformApplies reports whether one of the existing
// injection decoders would change text. Punctuation alone does not: "C++",
// "a < b", "R&D" and "100%" contain the admission characters and decode to
// themselves. The checks stay on the original bytes so an oversize payload
// is not copied just to learn that.
func additionalInjectionTransformApplies(text string) bool {
	return jsonUnicodeEscapeApplies(text) || utf7ShiftApplies(text) || htmlEntityApplies(text) || percentEncodingApplies(text) || htmlMarkupApplies(text)
}

func jsonUnicodeEscapeApplies(text string) bool {
	for i := 0; i+6 <= len(text); i++ {
		if text[i] != '\\' || text[i+1] != 'u' {
			continue
		}
		if hexDigits(text[i+2:i+6]) == 4 {
			return true
		}
	}
	return false
}

func hexDigits(text string) int {
	for i := range len(text) {
		c := text[i]
		digit := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !digit {
			return i
		}
	}
	return len(text)
}

func utf7ShiftApplies(text string) bool {
	if !strings.Contains(text, "+") {
		return false
	}
	for i := 0; i < len(text); {
		if text[i] != '+' {
			next := strings.IndexByte(text[i:], '+')
			if next < 0 {
				return false
			}
			i += next
		}
		_, consumed, ok := utf7ShiftAt(text[i:])
		if ok {
			return true
		}
		if consumed < 1 {
			return false
		}
		i += consumed
	}
	return false
}

func htmlEntityApplies(text string) bool {
	start := 0
	for {
		rel := strings.IndexByte(text[start:], '&')
		if rel < 0 {
			return false
		}
		i := start + rel
		end := i + 1
		limit := min(len(text), i+64)
		for end < limit && text[end] != '&' {
			end++
			if text[end-1] == ';' {
				break
			}
		}
		decoded, _ := decodeHTMLEntitiesChecked(text[i:end])
		if decoded != text[i:end] {
			return true
		}
		start = i + 1
	}
}

func percentEncodingApplies(text string) bool {
	if !strings.Contains(text, "%") {
		return false
	}
	plus := false
	for i := 0; i < len(text); i++ {
		if text[i] == '+' {
			plus = true
		}
		if text[i] == '%' && i+2 < len(text) && hexDigits(text[i+1:i+3]) == 2 {
			return true
		}
	}
	// Form decoding maps '+' to a space only on a value that also contains '%'.
	return plus
}

func htmlMarkupApplies(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] != '<' || i+1 >= len(text) {
			continue
		}
		switch text[i+1] {
		case '/':
			if i+2 < len(text) && asciiLetter(text[i+2]) {
				return true
			}
		case '!', '?':
			return true
		default:
			if asciiLetter(text[i+1]) {
				return true
			}
		}
	}
	return false
}

func asciiLetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func additionalInjectionViews(text, applied string) ([]injectionDecodeView, bool) {
	var views []injectionDecodeView
	complete := true
	if !hasAdditionalInjectionEncoding(text) && !strings.Contains(text, "<") {
		return nil, true
	}
	if decoded := normalize.DecodeJSONUnicodeEscapes(text); decoded != text {
		views = append(views, injectionDecodeView{text: decoded, label: "json_unicode_decoded"})
	}
	if decoded := injectionUTF7View(text); decoded != text {
		views = append(views, injectionDecodeView{text: decoded, label: "utf7_shifted_decoded"})
	}
	if strings.Contains(text, "&") {
		decoded, converged := decodeHTMLEntitiesChecked(text)
		complete = complete && converged
		if decoded != text {
			views = append(views, injectionDecodeView{text: decoded, label: "html_entity_decoded"})
		}
	}
	if strings.Contains(text, "%") {
		form, percent := urlComponentDecodes(text)
		if form != "" {
			views = append(views, injectionDecodeView{text: form, label: "url_decoded"})
			complete = complete && normalize.QueryUnescapePartial(form) == form
		}
		if percent != "" {
			views = append(views, injectionDecodeView{text: percent, label: "percent_decoded"})
			complete = complete && normalize.PercentUnescapePartial(percent) == percent
		}
	}
	// One extraction per lineage. A second pass parses the extracted text as
	// markup, so ordinary "<" and "+" keep producing new views until the depth cap.
	if strings.Contains(text, "<") && !strings.Contains(applied, injectionHTMLTextLabel) {
		decoded := injectionHTMLText(text)
		if decoded != text {
			views = append(views, injectionDecodeView{text: decoded, label: injectionHTMLTextLabel})
		}
	}
	return views, complete
}

// injectionHTMLText uses the same HTML parser's text-node semantics as fetch
// extraction: tags and comments disappear, adjacent text nodes concatenate,
// and character references decode. script, style and noscript text is omitted,
// matching the element names fetch conceals. template and textarea stay.
// The raw view is always scanned first.
func injectionHTMLText(text string) string {
	z := html.NewTokenizer(strings.NewReader(text))
	var out strings.Builder
	raw := ""
	for {
		switch z.Next() {
		case html.TextToken:
			if raw == "" {
				out.Write(z.Text())
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			if raw != "" {
				continue
			}
			name, _ := z.TagName()
			if injectionHTMLConcealedElement(name) {
				// The tokenizer keeps a raw element open until its end tag,
				// including when the start tag was marked self-closing.
				raw = string(name)
			}
		case html.EndTagToken:
			if raw == "" {
				continue
			}
			name, _ := z.TagName()
			if string(name) == raw {
				raw = ""
			}
		case html.ErrorToken:
			if !errors.Is(z.Err(), io.EOF) {
				return text
			}
			return out.String()
		}
	}
}

func injectionHTMLConcealedElement(name []byte) bool {
	switch string(name) {
	case "script", "style", "noscript":
		return true
	default:
		return false
	}
}

func injectionLegacyDecodeViews(text string) ([]injectionDecodeView, bool) {
	complete := true
	used := 0
	seen := map[string]bool{text: true}
	var views []injectionDecodeView
	add := func(text string) {
		if text == "" || seen[text] {
			return
		}
		if len(views) >= maxDecodeCandidates || len(text) > maxDecodeTotalBytes-used {
			complete = false
			return
		}
		seen[text] = true
		used += len(text)
		views = append(views, injectionDecodeView{text: text})
	}
	decode := func(source string, printableOnly bool) {
		stripped, _ := stripDecodeWhitespace(source, 0)
		stripped = canonicalMixedBase64(stripped)
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			if decoded, err := enc.DecodeString(stripped); err == nil && len(decoded) > 0 && (!printableOnly || isPrintableText(decoded)) {
				add(string(decoded))
			}
		}
		if decoded, err := hex.DecodeString(stripped); err == nil && len(decoded) > 0 && (!printableOnly || isPrintableText(decoded)) {
			add(string(decoded))
		}
	}
	decode(text, false)
	visitEncodedRunSpans(text, minSegmentDecodeLen, func(segment encodedRunSpan) bool {
		decode(segment.text, true)
		return complete
	})
	for _, view := range textEncodingViewsMode(text, true) {
		add(view.text)
	}
	if decoded := normalize.DecodeTags(text); decoded != text {
		add(decoded)
	}
	return views, complete
}

// injectionUTF7View reuses DLP's RFC 4648 decoder for the RFC 2152 shifted
// sequence. The existing UTF-16 body decoder receives an explicit big-endian BOM so it
// cannot infer little-endian ASCII from non-ASCII UTF-7 code units.
func injectionUTF7View(text string) string {
	if !strings.Contains(text, "+") {
		return text
	}
	var out strings.Builder
	changed := false
	for i := 0; i < len(text); {
		if text[i] != '+' {
			next := strings.IndexByte(text[i:], '+')
			if next < 0 {
				out.WriteString(text[i:])
				break
			}
			out.WriteString(text[i : i+next])
			i += next
		}
		decoded, consumed, ok := utf7ShiftAt(text[i:])
		if ok {
			out.WriteString(decoded)
			changed = true
		} else {
			out.WriteString(text[i : i+consumed])
		}
		i += consumed
	}
	if !changed {
		return text
	}
	return out.String()
}

// utf7ShiftAt parses one RFC 2152 shifted sequence at the start of rest.
// rest must begin with '+'. A shift that does not decode to UTF-16 reports
// the bytes consumed and ok false, so the caller keeps them literal.
func utf7ShiftAt(rest string) (decoded string, consumed int, ok bool) {
	// RFC 2152 ends a shifted sequence at a non-base64 byte or EOF.
	// Only an explicit '-' terminator is consumed; other bytes stay literal.
	end := 1
	for end < len(rest) {
		c := rest[end]
		base64Byte := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/'
		if !base64Byte {
			break
		}
		end++
	}
	consumed = end
	if end < len(rest) && rest[end] == '-' {
		consumed++
	}
	encoded := rest[1:end]
	if encoded == "" {
		return "", consumed, false
	}
	buffer := make([]byte, base64.RawStdEncoding.DecodedLen(len(encoded)))
	parts := decodeBase64PaddingVariants(encoded, base64.StdEncoding, base64.RawStdEncoding, buffer, 0)
	value := parts[0]
	if value == "" {
		value = parts[1]
	}
	if value == "" || len(value)%2 != 0 {
		return "", consumed, false
	}
	// The existing UTF-16 body decoder receives an explicit big-endian BOM so it
	// cannot infer little-endian ASCII from non-ASCII UTF-7 code units.
	utf16, decodedOK, _ := decodeLikelyUTF16ResponseBody(context.Background(), append([]byte{0xfe, 0xff}, []byte(value)...))
	if !decodedOK {
		return "", consumed, false
	}
	return utf16, consumed, true
}
