// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

type responseDecodeKey struct {
	content  string
	encoding *base64.Encoding
}

type responseCarrierDecoder struct {
	scratch []byte
	// The depth-first scanner reuses successful and failed codec attempts.
	// A nil memo keeps only the scratch for the current expansion step.
	memo map[responseDecodeKey]string
}

type responseCarrierTextGate struct {
	bytes func([]byte) bool
	text  func(string) bool
}

var printableResponseCarrierText = responseCarrierTextGate{
	bytes: isPrintableText,
	text:  func(text string) bool { return isPrintableText([]byte(text)) },
}

func (d *responseCarrierDecoder) decode(content string, encoding *base64.Encoding, accept responseCarrierTextGate) (string, bool) {
	key := responseDecodeKey{content, encoding}
	if d.memo != nil {
		if text, ok := d.memo[key]; ok {
			if text != "" && accept.text != nil && !accept.text(text) {
				return "", true
			}
			return text, text != "" || content == ""
		}
	}
	length := hex.DecodedLen(len(content))
	if encoding != nil {
		length = encoding.DecodedLen(len(content))
	}
	d.scratch = slices.Grow(d.scratch[:0], length)[:length]
	var n int
	var err error
	if encoding == nil {
		n, err = hex.Decode(d.scratch, []byte(content))
	} else {
		n, err = encoding.Decode(d.scratch, []byte(content))
	}
	var text string
	if err == nil && (d.memo != nil || accept.bytes == nil || accept.bytes(d.scratch[:n])) {
		text = string(d.scratch[:n])
	}
	if d.memo != nil {
		d.memo[key] = text
		if text != "" && accept.bytes != nil && !accept.bytes(d.scratch[:n]) {
			return "", true
		}
	}
	return text, err == nil
}

type responseDecodedCarrier struct {
	text   string
	source encodedRunSpan
	hex    bool
}

// visitBase64HexCarriers visits whole-content decodes first, then the admitted
// runs in source order. The text gate applies only to runs. afterSegment lets
// the bounded collector finish the current carrier before stopping the walk.
func (d *responseCarrierDecoder) visitBase64HexCarriers(content string, segmentText responseCarrierTextGate, afterSegment func() bool, yield func(responseDecodedCarrier) bool) (malformed bool) {
	if wholeResponseCarrierPossible(content) {
		whole := encodedRunSpan{text: content, end: len(content)}
		stripped := stripResponseDecodeWhitespace(content)
		keepGoing, rejected := d.visitCarrierCodecs(whole, stripped, responseCarrierTextGate{}, yield)
		malformed = rejected
		if !keepGoing {
			return malformed
		}
	}
	visitEncodedRunSpans(content, minSegmentDecodeLen, func(segment encodedRunSpan) bool {
		keepGoing, rejected := d.visitCarrierCodecs(segment, segment.text, segmentText, yield)
		malformed = malformed || rejected
		return keepGoing && (afterSegment == nil || afterSegment())
	})
	return malformed
}

func wholeResponseCarrierPossible(content string) bool {
	for i := range len(content) {
		b := content[i]
		if !isBase64DataByte(b) && !strings.ContainsRune("= \t\r\n", rune(b)) {
			return false
		}
	}
	return true
}

func (d *responseCarrierDecoder) visitCarrierCodecs(source encodedRunSpan, stripped string, accept responseCarrierTextGate, yield func(responseDecodedCarrier) bool) (keepGoing, malformed bool) {
	base64Text := canonicalMixedBase64(stripped)
	if d.memo == nil {
		// Reserve the largest codec destination once for this carrier.
		d.scratch = slices.Grow(d.scratch[:0], base64.RawStdEncoding.DecodedLen(len(base64Text)))
	}
	valid := false
	for _, encoding := range [...]*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding, nil} {
		input := base64Text
		if encoding == nil {
			input = stripped
		}
		decoded, ok := d.decode(input, encoding, accept)
		valid = valid || ok
		if decoded != "" && !yield(responseDecodedCarrier{text: decoded, source: source, hex: encoding == nil}) {
			return false, false
		}
	}
	return true, stripped != "" && !valid
}

func stripResponseDecodeWhitespace(content string) string {
	if !strings.ContainsAny(content, " \n\r\t") {
		return content
	}
	var stripped strings.Builder
	stripped.Grow(len(content))
	for i := 0; i < len(content); i++ {
		switch content[i] {
		case ' ', '\n', '\r', '\t':
			continue
		default:
			stripped.WriteByte(content[i])
		}
	}
	return stripped.String()
}

func responseDecodeTagView(text string) (string, bool) {
	decoded := normalize.DecodeTags(text)
	return decoded, decoded != text
}

func responseDecodeSpacedView(text, normalized string) (string, bool) {
	spaced := normalize.ForMatchingSpaced(text)
	return spaced, spaced != normalized
}

func responseDecodeQuotedPrintableSource(text string) (string, bool) {
	stripped := normalize.StripZeroWidth(text)
	return stripped, hasQuotedPrintable(stripped)
}

type responseDecodeStepOptions struct {
	applied                string
	additionalInjection    bool
	includeMatchingUnicode bool
	recoverQP              bool
}

type responseDecodeStepOutcome struct {
	Truncated bool
	// Malformed reports a nonempty carrier rejected by every codec. A
	// successfully decoded binary segment may fail the text gate separately.
	Malformed bool
	Canceled  error
}

// expandResponseDecodeStep collects one breadth-first expansion. Additional
// labeled views precede legacy views and have independent admission limits.
// The depth-first scanner visits the same primitives in its own scan order.
func expandResponseDecodeStep(ctx context.Context, text string, options responseDecodeStepOptions) ([]injectionDecodeView, responseDecodeStepOutcome) {
	if err := ctx.Err(); err != nil {
		return nil, responseDecodeStepOutcome{Canceled: err}
	}
	var views []injectionDecodeView
	var outcome responseDecodeStepOutcome
	if options.additionalInjection {
		var complete bool
		views, complete = additionalInjectionViews(text, options.applied)
		outcome.Truncated = !complete
	}
	firstLegacy := len(views)
	legacyTruncated := false
	used := 0
	seen := map[string]struct{}{text: {}}
	add := func(decoded string) {
		if _, exists := seen[decoded]; decoded == "" || exists {
			return
		}
		if len(views)-firstLegacy >= maxDecodeCandidates || len(decoded) > maxDecodeTotalBytes-used {
			legacyTruncated = true
			return
		}
		seen[decoded] = struct{}{}
		used += len(decoded)
		views = append(views, injectionDecodeView{text: decoded})
	}
	var decoder responseCarrierDecoder
	outcome.Malformed = decoder.visitBase64HexCarriers(text, printableResponseCarrierText, func() bool { return !legacyTruncated }, func(carrier responseDecodedCarrier) bool {
		add(carrier.text)
		return true
	})
	for _, view := range textEncodingViewsMode(text, options.recoverQP) {
		add(view.text)
	}
	if decoded, ok := responseDecodeTagView(text); ok {
		add(decoded)
	}
	if options.includeMatchingUnicode {
		normalized := normalize.ForMatching(text)
		if normalized != text {
			views = append(views, injectionDecodeView{text: normalized, label: ViewForMatching})
		}
		if spaced, ok := responseDecodeSpacedView(text, normalized); ok {
			views = append(views, injectionDecodeView{text: spaced, label: ViewInvisibleSpaced})
		}
		if normalize.ContainsTags(text) {
			if stripped, ok := responseDecodeQuotedPrintableSource(text); ok && stripped != text {
				views = append(views, injectionDecodeView{text: stripped})
			}
		}
	}
	outcome.Truncated = outcome.Truncated || legacyTruncated
	outcome.Canceled = ctx.Err()
	return views, outcome
}
