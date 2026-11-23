// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"fmt"
	"unicode/utf8"
)

type bodyInjectionViewKind uint8

const (
	bodyViewNone bodyInjectionViewKind = iota
	bodyViewText
	bodyViewTextSeparators
	bodyViewImageMetadata
	bodyViewUnverifiedImage
	bodyViewWideUnicode
	bodyViewOpaque
	bodyViewRetained
	bodyViewFragmented
	bodyViewEncoded
	bodyViewDecoded
)

type bodyInjectionView struct {
	Kind                    bodyInjectionViewKind
	Text                    string
	DecodeOnly              bool
	RequireFragmentBoundary bool
	CanTransform            bool
}

// extractResponseBodyViews collects the views in scan order. The scanner uses
// the same stages lazily so an early finding can stop before the next stage.
func extractResponseBodyViews(ctx context.Context, body []byte) ([]bodyInjectionView, error) {
	first, err := firstResponseBodyView(ctx, body)
	if err != nil {
		return nil, err
	}
	var views []bodyInjectionView
	if first.Kind != bodyViewNone && first.Kind != bodyViewOpaque {
		views = append(views, first)
	}
	switch first.Kind {
	case bodyViewText:
		if separator := responseBodySeparatorView(body, first.Text); separator.Kind != bodyViewNone {
			views = append(views, separator)
		}
	case bodyViewWideUnicode, bodyViewOpaque:
		opaque, err := extractOpaqueResponseBodyViews(ctx, body)
		if err != nil {
			return nil, err
		}
		for _, view := range opaque {
			if view.Kind != bodyViewNone {
				views = append(views, view)
			}
		}
	}
	return views, nil
}

func firstResponseBodyView(ctx context.Context, body []byte) (bodyInjectionView, error) {
	metadata, image, err := responseImageMetadata(body)
	if image {
		if err != nil {
			return bodyInjectionView{}, fmt.Errorf("image metadata inspection failed: %w", err)
		}
		if len(metadata) == 0 {
			return bodyInjectionView{}, nil
		}
		return bodyInjectionView{Kind: bodyViewImageMetadata, Text: string(metadata)}, nil
	}
	if hasResponseImageSignature(body) {
		return bodyInjectionView{Kind: bodyViewUnverifiedImage, Text: string(body)}, nil
	}
	textual, err := isTextualResponseBody(ctx, body)
	if err != nil {
		return bodyInjectionView{}, err
	}
	if textual {
		return bodyInjectionView{Kind: bodyViewText, Text: string(body), CanTransform: true}, nil
	}
	decoded, wide, err := decodeLikelyWideResponseBody(ctx, body)
	if err != nil {
		return bodyInjectionView{}, err
	}
	if wide {
		return bodyInjectionView{Kind: bodyViewWideUnicode, Text: decoded}, nil
	}
	return bodyInjectionView{Kind: bodyViewOpaque}, nil
}

func responseBodySeparatorView(body []byte, raw string) bodyInjectionView {
	if utf8.ValidString(raw) {
		return bodyInjectionView{}
	}
	return bodyInjectionView{Kind: bodyViewTextSeparators, Text: string(bytes.ToValidUTF8(body, []byte(" ")))}
}

func extractOpaqueResponseBodyViews(ctx context.Context, body []byte) (out [4]bodyInjectionView, err error) {
	views, err := opaqueResponseTextView(ctx, body)
	if err != nil {
		return out, err
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return out, err
		}
	}
	if views.retained != "" {
		out[0] = bodyInjectionView{Kind: bodyViewRetained, Text: views.retained}
	}
	if views.fragmented != "" {
		out[1] = bodyInjectionView{Kind: bodyViewFragmented, Text: views.fragmented, RequireFragmentBoundary: true}
	}
	if views.encoded != "" && views.encoded != views.fragmented {
		out[2] = bodyInjectionView{Kind: bodyViewEncoded, Text: views.encoded, DecodeOnly: true, RequireFragmentBoundary: true}
	}
	if views.decoded != "" && views.decoded != views.fragmented && views.decoded != views.encoded {
		out[3] = bodyInjectionView{Kind: bodyViewDecoded, Text: views.decoded, RequireFragmentBoundary: true}
	}
	return out, nil
}
