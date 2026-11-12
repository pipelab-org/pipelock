// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"errors"
	"io"
	"strings"

	"golang.org/x/net/html"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

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
			out.Clean = false
			out.ScanError = injectionDecodeLimitReason
		}
	}()
	for head := 0; head < len(queue); head++ {
		if ctx != nil && ctx.Err() != nil {
			return ResponseScanResult{Clean: false, ScanError: ctx.Err().Error()}
		}
		parent := queue[head]
		if !hasAdditionalInjectionEncoding(parent.text) {
			continue
		}
		if len(parent.text) > maxDecodeTotalBytes {
			incomplete = true
			continue
		}
		views, complete := additionalInjectionViews(parent.text)
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
			checked := s.scanResponseMatches(ctx, view.text, target, suppress, false, newResponseMatchMemo(len(view.text)))
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
	return result
}

func hasAdditionalInjectionEncoding(text string) bool {
	return strings.ContainsAny(text, "&%<")
}

func additionalInjectionViews(text string) ([]injectionDecodeView, bool) {
	var views []injectionDecodeView
	complete := true
	if !hasAdditionalInjectionEncoding(text) {
		return nil, true
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
