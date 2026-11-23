// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Keep the existing legacy-limit test pointed at the shared collector.
func injectionLegacyDecodeViews(text string) ([]injectionDecodeView, bool) {
	views, outcome := expandResponseDecodeStep(context.Background(), text, responseDecodeStepOptions{recoverQP: true})
	return views, !outcome.Truncated
}

// The expected carrier visits preserve the depth-first scanner's codec order
// and offsets. The breadth-first expansion keeps only distinct legacy texts
// and places its labeled views first.
func TestResponseDecodeStepLegacyEquivalence(t *testing.T) {
	const segmentText = "the sky is blue"
	segment := base64.StdEncoding.EncodeToString([]byte(segmentText))
	for _, tt := range []struct {
		name       string
		input      string
		carrier    string
		offset     int
		base64Text string
		base64Runs int
		hexText    string
		want       []injectionDecodeView
	}{
		{name: "prose", input: "ordinary prose."},
		{
			name: "whole base64", input: "YWJj", carrier: "YWJj", base64Text: "abc", base64Runs: 4,
			want: []injectionDecodeView{{text: "abc"}},
		},
		{
			name: "ASCII whitespace", input: "Y W\r\nJ\tj", carrier: "Y W\r\nJ\tj", base64Text: "abc", base64Runs: 4,
			want: []injectionDecodeView{{text: "abc"}},
		},
		{
			name: "whole hex also decodes as base64", input: "4869", carrier: "4869", base64Text: "\xe3\xce\xbd", base64Runs: 4, hexText: "Hi",
			want: []injectionDecodeView{{text: "\xe3\xce\xbd"}, {text: "Hi"}},
		},
		{
			name: "mixed alphabets", input: "-///", carrier: "-///", base64Text: "\xfb\xff\xff", base64Runs: 2,
			want: []injectionDecodeView{{text: "\xfb\xff\xff"}},
		},
		{
			name: "segment", input: "prefix:" + segment + "!", carrier: segment, offset: len("prefix:"), base64Text: segmentText, base64Runs: 4,
			want: []injectionDecodeView{{text: segmentText}},
		},
		{name: "binary segment", input: "data:AAAAAAAAAAAAAAAA!"},
		{name: "quoted printable", input: "=63=61=74", want: []injectionDecodeView{{text: "cat"}}},
		{name: "Unicode tags", input: "c\U000e0061t", want: []injectionDecodeView{{text: "cat"}}},
		{name: "HTML transforms", input: "<b>caf&#233;</b>", want: []injectionDecodeView{
			{text: "<b>café</b>", label: "html_entity_decoded"},
			{text: "café", label: injectionHTMLTextLabel},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var wantCarriers []responseDecodedCarrier
			span := encodedRunSpan{text: tt.carrier, start: tt.offset, end: tt.offset + len(tt.carrier)}
			for range tt.base64Runs {
				wantCarriers = append(wantCarriers, responseDecodedCarrier{text: tt.base64Text, source: span})
			}
			if tt.hexText != "" {
				wantCarriers = append(wantCarriers, responseDecodedCarrier{text: tt.hexText, source: span, hex: true})
			}
			for _, memoized := range []bool{false, true} {
				var decoder responseCarrierDecoder
				if memoized {
					decoder.memo = make(map[responseDecodeKey]string)
				}
				var got []responseDecodedCarrier
				decoder.visitBase64HexCarriers(tt.input, printableResponseCarrierText, nil, func(view responseDecodedCarrier) bool {
					got = append(got, view)
					return true
				})
				if !slices.Equal(got, wantCarriers) {
					t.Fatalf("codec views (memoized=%t) = %+v, want %+v", memoized, got, wantCarriers)
				}
			}
			views, outcome := expandResponseDecodeStep(t.Context(), tt.input, responseDecodeStepOptions{additionalInjection: true, recoverQP: true})
			if len(views) != len(tt.want) || outcome.Truncated || outcome.Canceled != nil {
				t.Fatalf("breadth-first views = %+v, outcome = %+v, want %+v", views, outcome, tt.want)
			}
			for i, want := range tt.want {
				if views[i].text != want.text || views[i].label != want.label {
					t.Fatalf("breadth-first view %d = (%q, %q), want (%q, %q)", i, views[i].text, views[i].label, want.text, want.label)
				}
			}
		})
	}
}

func TestResponseDecodeStepUnicodeViews(t *testing.T) {
	views, _ := expandResponseDecodeStep(t.Context(), "hello\u200bworld", responseDecodeStepOptions{includeMatchingUnicode: true})
	if len(views) != 2 || views[0].text != "helloworld" || views[0].label != ViewForMatching ||
		views[1].text != "hello world" || views[1].label != ViewInvisibleSpaced {
		t.Fatalf("Unicode matching views = %+v", views)
	}
	const stripped = "=63=61=74"
	if got, ok := responseDecodeQuotedPrintableSource("=6\U000e00013=61=74"); !ok || got != stripped {
		t.Fatalf("quoted-printable source = %q, %t, want %q", got, ok, stripped)
	}
}

func TestResponseDecodeStepOutcomes(t *testing.T) {
	if _, outcome := expandResponseDecodeStep(t.Context(), "A=", responseDecodeStepOptions{}); !outcome.Malformed || outcome.Truncated || outcome.Canceled != nil {
		t.Fatalf("malformed carrier outcome = %+v", outcome)
	}
	var text strings.Builder
	for i := range maxDecodeCandidates + 2 {
		text.WriteByte('!')
		text.WriteString(base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "row %03d ready now", i)))
	}
	views, outcome := expandResponseDecodeStep(t.Context(), text.String(), responseDecodeStepOptions{})
	if !outcome.Truncated || outcome.Canceled != nil || len(views) != maxDecodeCandidates {
		t.Fatalf("bounded step collected %d views, outcome = %+v", len(views), outcome)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	views, outcome = expandResponseDecodeStep(ctx, "YWJj", responseDecodeStepOptions{})
	if len(views) != 0 || !errors.Is(outcome.Canceled, context.Canceled) {
		t.Fatalf("canceled step produced %+v, outcome = %+v", views, outcome)
	}
}

// A carrier that overflows the byte budget ends the walk once that carrier is
// finished, as the earlier collector did. A later carrier that would still fit
// is not admitted, so the truncation always covers the remaining carriers.
func TestResponseDecodeStepStopsAfterOverflowingCarrier(t *testing.T) {
	carrier := func(word string, decodedBytes int) (encoded, decoded string) {
		decoded = strings.Repeat(word+" ", decodedBytes/(len(word)+1))
		return base64.StdEncoding.EncodeToString([]byte(decoded)), decoded
	}
	// Two carriers exceed the budget together; the third would fit alone.
	first, firstText := carrier("alpha", maxDecodeTotalBytes*5/8)
	second, _ := carrier("bravo", maxDecodeTotalBytes*5/8)
	third, _ := carrier("charlie", 64)
	views, outcome := expandResponseDecodeStep(t.Context(), "!"+first+"!"+second+"!"+third, responseDecodeStepOptions{})
	if !outcome.Truncated || len(views) != 1 || views[0].text != firstText {
		t.Fatalf("collected %d views, outcome = %+v, want only the first carrier", len(views), outcome)
	}
}
