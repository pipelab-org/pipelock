// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestExtractResponseBodyViews(t *testing.T) {
	const prose = "ordinary response text"
	const firstPart = "morning"
	const secondPart = "afternoon"
	const proseEncodedChain = "o\nr\nd\ni\nn\na\nr\ny\nr\ne\ns\np\no\nn\ns\ne\nt\ne\nx\nt"
	utf32 := []byte{0, 0, 0xfe, 0xff}
	for i := range len(prose) {
		utf32 = binary.BigEndian.AppendUint32(utf32, uint32(prose[i]))
	}
	unverified := []byte("\xff\xd8" + prose)
	first := base64.StdEncoding.EncodeToString([]byte(firstPart))
	second := base64.StdEncoding.EncodeToString([]byte(secondPart))
	longFirst := base64.StdEncoding.EncodeToString([]byte(prose))
	longSecond := base64.StdEncoding.EncodeToString([]byte("another readable line"))

	for _, tt := range []struct {
		name string
		body []byte
		want []bodyInjectionView
	}{
		{name: "empty text", want: []bodyInjectionView{{Kind: bodyViewText, CanTransform: true}}},
		{name: "text", body: []byte(prose), want: []bodyInjectionView{{Kind: bodyViewText, Text: prose, CanTransform: true}}},
		{name: "invalid separators", body: []byte("ordinary\xff\xfe response text"), want: []bodyInjectionView{
			{Kind: bodyViewText, Text: "ordinary\xff\xfe response text", CanTransform: true},
			{Kind: bodyViewTextSeparators, Text: "ordinary  response text"},
		}},
		{name: "verified PNG without metadata", body: pngWithIsolatedDANPixels(t)},
		{name: "verified JPEG without metadata", body: jpegWithIsolatedDANTable(t)},
		{name: "verified PNG metadata", body: pngWithMetadata(t, "tEXt", []byte("Comment\x00"+prose)), want: []bodyInjectionView{
			{Kind: bodyViewImageMetadata, Text: "Comment\x00" + prose},
		}},
		{name: "verified JPEG metadata", body: jpegWithComment(t, []byte(prose)), want: []bodyInjectionView{{Kind: bodyViewImageMetadata, Text: prose}}},
		{name: "unverified image", body: unverified, want: []bodyInjectionView{{Kind: bodyViewUnverifiedImage, Text: string(unverified)}}},
		{name: "UTF-16 with raw suffix", body: append(encodeUTF16ResponseBody(prose, true, true), prose...), want: []bodyInjectionView{
			{Kind: bodyViewWideUnicode, Text: prose + "牯楤慮祲爠獥潰獮\u2065整瑸"},
			{Kind: bodyViewRetained, Text: prose},
			{Kind: bodyViewEncoded, Text: proseEncodedChain, DecodeOnly: true, RequireFragmentBoundary: true},
		}},
		{name: "UTF-32", body: utf32, want: []bodyInjectionView{
			{Kind: bodyViewWideUnicode, Text: prose},
			{Kind: bodyViewEncoded, Text: proseEncodedChain, DecodeOnly: true, RequireFragmentBoundary: true},
		}},
		{name: "opaque without views", body: []byte{0, 0xff, 0x80}},
		{name: "opaque with prose", body: opaqueBodyViewFixture(prose, "another readable line"), want: []bodyInjectionView{
			{Kind: bodyViewRetained, Text: prose + "\n\ufffd\nanother readable line"},
			{Kind: bodyViewFragmented, Text: prose + "\nanother readable line", RequireFragmentBoundary: true},
		}},
		{name: "opaque with encoded and decoded chains", body: opaqueBodyViewFixture(first, second), want: []bodyInjectionView{
			{Kind: bodyViewEncoded, Text: first + "\n" + second, DecodeOnly: true, RequireFragmentBoundary: true},
			{Kind: bodyViewDecoded, Text: firstPart + "\n" + secondPart, RequireFragmentBoundary: true},
		}},
		{name: "opaque with duplicate reconstructed chain", body: opaqueBodyViewFixture(longFirst, longSecond), want: []bodyInjectionView{
			{Kind: bodyViewRetained, Text: longFirst + "\n\ufffd\n" + longSecond},
			{Kind: bodyViewFragmented, Text: longFirst + "\n" + longSecond, RequireFragmentBoundary: true},
			{Kind: bodyViewDecoded, Text: prose + "\nanother readable line", RequireFragmentBoundary: true},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractResponseBodyViews(t.Context(), tt.body)
			if err != nil || !slices.Equal(got, tt.want) {
				t.Fatalf("body views = %+v, %v, want %+v", got, err, tt.want)
			}
		})
	}
}

func TestExtractResponseBodyViewsErrors(t *testing.T) {
	for _, tt := range []struct {
		name      string
		body      []byte
		errorText string
	}{
		{name: "compressed metadata", body: pngWithMetadata(t, "zTXt", []byte("Comment\x00\x00invalid")), errorText: "image metadata inspection failed"},
		{name: "truncated UTF-32", body: []byte{0, 0, 0xfe, 0xff, 0}, errorText: "UTF-32 response has a truncated code unit"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			views, err := extractResponseBodyViews(t.Context(), tt.body)
			if len(views) != 0 || err == nil || !strings.Contains(err.Error(), tt.errorText) {
				t.Fatalf("body views = %+v, %v, want %q", views, err, tt.errorText)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	views, err := extractResponseBodyViews(ctx, []byte("some text"))
	if len(views) != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled body extraction = %+v, %v", views, err)
	}
}

func opaqueBodyViewFixture(parts ...string) []byte {
	body := bytes.Repeat([]byte{0, 0, 0xff, 0x80}, 32)
	for _, part := range parts {
		body = append(body, part...)
		body = append(body, 0xff)
	}
	return body
}
