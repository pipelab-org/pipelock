// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

type checkerTextBuilder struct {
	ctx              context.Context
	parts            []checker.Part
	submitted, limit int64
	reason           checker.Reason
}

func (s *Scanner) newCheckerTextBuilder(ctx context.Context, surface string) checkerTextBuilder {
	set := s.InjectionCheckers()
	decider, _ := set.Decider(surface)
	watcher, _ := set.Watcher(surface)
	return checkerTextBuilder{ctx: ctx, limit: max(decider.Policy.MaxRequestBytes, watcher.Policy.MaxRequestBytes)}
}

// BuildInjectionTextParts extracts ordered views for a selected checker.
func (s *Scanner) BuildInjectionTextParts(ctx context.Context, surface string, texts ...string) ([]checker.Part, *checker.Completeness) {
	builder := s.newCheckerTextBuilder(ctx, surface)
	builder.addTexts(texts)
	return builder.parts, builder.completeness(nil)
}

// InjectionTextParts builds text parts without a configured checker budget.
func InjectionTextParts(texts ...string) []checker.Part {
	builder := checkerTextBuilder{ctx: context.Background(), limit: math.MaxInt64}
	builder.addTexts(texts)
	return builder.parts
}

func (b *checkerTextBuilder) addTexts(texts []string) {
	for _, text := range texts {
		if !b.add(bodyInjectionView{Kind: bodyViewText, Text: text}) {
			break
		}
	}
}

func (b *checkerTextBuilder) completeness(existing *checker.Completeness) *checker.Completeness {
	if b.reason != "" {
		return &checker.Completeness{Status: checker.Partial, Reason: b.reason}
	}
	if existing != nil {
		return existing
	}
	return &checker.Completeness{Status: checker.Complete}
}

func (b *checkerTextBuilder) add(view bodyInjectionView) bool {
	// Fragment reconstructions preserve the producer's synthetic newlines.
	// Keep each reconstruction in its own part; a checker must not concatenate
	// independent parts. Encoded-only sources supply decoded parts only.
	text := strings.ToValidUTF8(exciseVerifiedImageDataURLs(view.Text), " ")
	if text == "" {
		return true
	}
	seen := make(map[string]struct{})
	appendPart := func(text, representation string) bool {
		if text == "" {
			return true
		}
		if _, exists := seen[text]; exists {
			return true
		}
		if int64(len(text)) > b.limit-b.submitted {
			b.reason = checker.ReasonOverBudget
			return false
		}
		seen[text] = struct{}{}
		role := "decoded_view"
		if representation == "original" {
			role = "content"
		}
		if view.RequireFragmentBoundary && representation != "response_fragments/v1" {
			representation = "response_fragment_decoded/v1"
		}
		b.parts = append(b.parts, checker.Part{ID: "text-" + strconv.Itoa(len(b.parts)), Role: role, Representation: representation, Text: text})
		b.submitted += int64(len(text))
		return true
	}

	addMatching := func(text string, printableOnly bool) bool {
		add := func(value, representation string) bool {
			return (printableOnly && !isPrintableText([]byte(value))) || appendPart(value, representation)
		}
		tags := normalize.DecodeTags(text)
		return (tags == text || add(tags, "unicode_tags/v1")) &&
			add(normalize.ForMatching(text), "for_matching/v1") &&
			add(normalize.ForMatchingSpaced(text), "for_matching_spaced/v1") &&
			(tags == text || add(normalize.ForMatching(tags), "for_matching/v1"))
	}
	representation := "original"
	if view.RequireFragmentBoundary {
		representation = "response_fragments/v1"
	}
	if !view.DecodeOnly && (!appendPart(text, representation) || !addMatching(text, false)) {
		return false
	}
	// The scanner opens a whole-content decode without a text gate, so wording
	// buried in binary reaches its rules. A decode that is not text as a whole
	// still contributes its readable runs, the same floor the opaque body view
	// applies. Short coincidental decodes of ordinary words stay below it.
	addReadableRuns := func(text string) bool {
		views, err := opaqueResponseTextView(b.ctx, []byte(text))
		if err != nil {
			b.reason = checker.ReasonCanceled
			return false
		}
		runs := strings.ToValidUTF8(exciseVerifiedImageDataURLs(views.retained), " ")
		return appendPart(runs, "response_decoded_runs/v1") && addMatching(runs, true)
	}
	addDecoded := func(raw string) bool {
		if !utf8.ValidString(raw) {
			textual, err := isTextualResponseBody(b.ctx, []byte(raw))
			if err != nil {
				b.reason = checker.ReasonCanceled
				return false
			}
			if !textual {
				return addReadableRuns(raw)
			}
		}
		text := strings.ToValidUTF8(exciseVerifiedImageDataURLs(raw), " ")
		if !isPrintableText([]byte(text)) {
			return addReadableRuns(raw) && addMatching(text, true)
		}
		return appendPart(text, "response_decoded/v1") && addMatching(text, true)
	}

	// The historical depth-first pass starts from normalized text, with
	// separate tag and quoted-printable roots where matching preserves them.
	// Reuse its codec order and recursion without running any wording rules.
	normalized := normalize.ForMatching(text)
	legacyRoot := normalized
	if !view.DecodeOnly && normalize.ContainsTags(text) {
		legacyRoot = text
	}
	if view.DecodeOnly || view.RequireFragmentBoundary || hasEncodedRun(normalized) ||
		hasTextEncoding(normalized) || hasQuotedPrintable(text) || normalize.ContainsTags(text) {
		used, candidates := 0, 0
		legacy := newResponseDecodeMemo(nil, false, nil)
		legacy.visitDecoded = func(decoded, _ string) bool {
			if b.ctx.Err() != nil {
				b.reason = checker.ReasonCanceled
				return false
			}
			if candidates >= maxDecodeCandidates || len(decoded) > maxDecodeTotalBytes-used {
				b.reason = checker.ReasonTruncated
				return false
			}
			candidates++
			used += len(decoded)
			return addDecoded(decoded)
		}
		if len(legacyRoot) <= maxDecodeTotalBytes {
			legacy.recursiveMode(legacyRoot, 0, !view.RequireFragmentBoundary)
			if !legacy.stopVisiting && !view.DecodeOnly && legacyRoot != text && hasQuotedPrintable(text) {
				legacy.recursiveMode(text, 0, !view.RequireFragmentBoundary)
			}
		} else {
			b.reason = checker.ReasonTruncated
		}
		if b.reason == checker.ReasonOverBudget || b.reason == checker.ReasonCanceled {
			return false
		}
	}

	root := text
	if view.DecodeOnly {
		root = normalized
	}
	incomplete, err := visitAdditionalInjectionViews(b.ctx, root, injectionWalkOptions{outboundWorkLimit: outboundInjectionDecodeWorkBytes},
		func(_ int, _ injectionDecodeView, decoded injectionDecodeView, _ injectionDecodeAlignment, _ bool, _ *responseDeltaProof) bool {
			// Unlabeled values only extend the queue; Engine 1 owns their
			// direct match views.
			if decoded.label == "" {
				return true
			}
			return addDecoded(decoded.text)
		})
	if b.reason == checker.ReasonOverBudget || b.reason == checker.ReasonCanceled {
		return false
	}
	if err != nil {
		b.reason = checker.ReasonCanceled
		return false
	}
	if incomplete {
		b.reason = checker.ReasonTruncated
	}
	return true
}
