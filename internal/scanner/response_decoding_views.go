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

type injectionDecodeView struct {
	text, label string
	depth       int
}

// scanAdditionalInjectionViews runs after the historical passes so their
// findings, order and coordinates remain unchanged. Only new decoded views
// are matched. Every retained view is charged against the DLP byte/candidate
// budgets, including first-layer copies; nesting uses the injection depth cap.
func (s *Scanner) scanAdditionalInjectionViews(ctx context.Context, content, target string, suppress []config.SuppressEntry, result ResponseScanResult) (out ResponseScanResult) {
	if ctx == nil {
		ctx = context.Background()
	}
	queue := []injectionDecodeView{{text: content}}
	seen := map[string]bool{content: true}
	used := 0
	incomplete := false
	defer func() {
		if incomplete {
			out.InspectionIncomplete = true
			outbound, _ := ctx.Value(outboundInjectionContextKey{}).(bool)
			if outbound {
				out.Clean = false
				out.ScanError = injectionDecodeLimitReason
			} else {
				s.EmitTextDLPWarnMatches(ctx, []TextDLPMatch{partialEncodedContentMatch()})
			}
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
			incomplete = true
			continue
		}
		views, complete := additionalInjectionViews(parent.text)
		legacy, legacyComplete := injectionLegacyDecodeViews(parent.text)
		views = append(views, legacy...)
		complete = complete && legacyComplete
		incomplete = incomplete || !complete
		for _, view := range views {
			if view.text == "" || seen[view.text] {
				continue
			}
			if parent.depth >= responseDecodeMaxDepth || len(queue) >= maxDecodeCandidates || len(view.text) > maxDecodeTotalBytes-used {
				incomplete = true
				continue
			}
			seen[view.text] = true
			used += len(view.text)
			view.depth = parent.depth + 1
			if view.label == "" {
				view.label = parent.label
			} else {
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

func additionalInjectionViews(text string) ([]injectionDecodeView, bool) {
	var views []injectionDecodeView
	complete := true
	if !hasAdditionalInjectionEncoding(text) {
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
	if strings.Contains(text, "<") {
		decoded := injectionHTMLText(text)
		if decoded != text {
			views = append(views, injectionDecodeView{text: decoded, label: "html_text"})
		}
	}
	return views, complete
}

// injectionHTMLText uses the same HTML parser's text-node semantics as fetch
// extraction: tags and comments disappear, adjacent text nodes concatenate,
// and character references decode. The raw view is always scanned first.
func injectionHTMLText(text string) string {
	z := html.NewTokenizer(strings.NewReader(text))
	var out strings.Builder
	for {
		switch z.Next() {
		case html.TextToken:
			out.Write(z.Text())
		case html.ErrorToken:
			if !errors.Is(z.Err(), io.EOF) {
				return text
			}
			return out.String()
		}
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
	for rest := text; ; {
		start := strings.IndexByte(rest, '+')
		if start < 0 {
			out.WriteString(rest)
			break
		}
		out.WriteString(rest[:start])
		rest = rest[start:]
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
		consumed := end
		if end < len(rest) && rest[end] == '-' {
			consumed++
		}
		encoded := rest[1:end]
		if encoded == "" {
			out.WriteString(rest[:consumed])
		} else {
			buffer := make([]byte, base64.RawStdEncoding.DecodedLen(len(encoded)))
			decoded := decodeBase64PaddingVariants(encoded, base64.StdEncoding, base64.RawStdEncoding, buffer, 0)
			value := decoded[0]
			if value == "" {
				value = decoded[1]
			}
			if value == "" || len(value)%2 != 0 {
				out.WriteString(rest[:consumed])
			} else {
				decoded, ok, _ := decodeLikelyUTF16ResponseBody(context.Background(), append([]byte{0xfe, 0xff}, []byte(value)...))
				if ok {
					out.WriteString(decoded)
					changed = true
				} else {
					out.WriteString(rest[:consumed])
				}
			}
		}
		rest = rest[consumed:]
	}
	if !changed {
		return text
	}
	return out.String()
}
