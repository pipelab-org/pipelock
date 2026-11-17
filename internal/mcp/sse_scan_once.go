// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// sseViewStatsKey carries a test counter for scanner calls. Production contexts
// leave it unset.
type (
	sseViewStatsKey struct{}
	sseViewStats    struct {
		onDLP func(text string, reused bool)
		onInj func(text string, reused bool)
	}
)

func withSSEViewStats(ctx context.Context, stats *sseViewStats) context.Context {
	return context.WithValue(ctx, sseViewStatsKey{}, stats)
}

// sseScanOnce reuses completed, finding-free DLP scans among an event's fixed
// rolling and payload views, and explicitly benign basic injection assessments.
// Variable-sized field-tail loops scan directly so their field count cannot
// grow this cache. Every new event starts empty.
// Findings, partial scans and warnings run again to preserve their hooks and
// evidence. Other checkers never reuse an assessment here.
type sseScanOnce struct {
	ctx   context.Context
	sc    *scanner.Scanner
	opts  GenericSSEScanOptions
	stats *sseViewStats
	reuse bool
	dlp   []sseDLPSeen
	inj   []sseInjectionSeen
}
type sseInjectionSeen struct {
	text   string
	result scanner.ResponseScanResult
}
type sseDLPSeen struct {
	text, card string
	typed      bool
	result     scanner.TextDLPResult
}

func newSSEScanOnce(ctx context.Context, sc *scanner.Scanner, opts GenericSSEScanOptions, stats *sseViewStats) sseScanOnce {
	return sseScanOnce{ctx: ctx, sc: sc, opts: opts, stats: stats, reuse: true}
}

func (o *sseScanOnce) noteDLP(text string, reused bool) {
	if o.stats != nil && o.stats.onDLP != nil {
		o.stats.onDLP(text, reused)
	}
}

func (o *sseScanOnce) textDLP(text, card string, typed bool) (scanner.TextDLPResult, []scanner.TextDLPMatch) {
	if o.ctx.Err() != nil {
		return scanner.TextDLPResult{Incomplete: true}, nil
	}
	for i := range o.dlp {
		seen := &o.dlp[i]
		if seen.typed == typed && seen.text == text && seen.card == card {
			o.noteDLP(text, true)
			return seen.result, nil
		}
	}
	o.noteDLP(text, false)
	var result scanner.TextDLPResult
	if typed {
		result = o.sc.ScanTextForDLPWithTypedCardView(o.ctx, text, card)
	} else {
		result = o.sc.ScanTextForDLPWithCardView(o.ctx, text, card)
	}
	// Decide reuse before suppressions: a suppressed finding still has evidence
	// and hook semantics, even when delivery becomes clean after filtering.
	if o.reuse && result.Clean && !result.Incomplete && len(result.Matches) == 0 && len(result.InformationalMatches) == 0 {
		// A caller may append findings when it merges a result. Empty slices with
		// zero capacity cannot let that append mutate a cached slice's backing array.
		result.Matches = result.Matches[:0:0]
		result.InformationalMatches = result.InformationalMatches[:0:0]
		o.dlp = append(o.dlp, sseDLPSeen{text: text, card: card, typed: typed, result: result})
	}
	return keepUnsuppressedDLP(result, o.opts.Target, o.opts.Suppress)
}

func (o *sseScanOnce) response(text string) scanner.ResponseScanResult {
	if o.ctx.Err() == nil {
		for i := range o.inj {
			if seen := &o.inj[i]; seen.text == text {
				if o.stats != nil && o.stats.onInj != nil {
					o.stats.onInj(text, true)
				}
				return seen.result
			}
		}
	}
	if o.stats != nil && o.stats.onInj != nil {
		o.stats.onInj(text, false)
	}
	result := o.sc.ScanResponseWithSuppress(o.ctx, text, o.opts.Target, o.opts.Suppress)
	if o.reuse && reusableSSEInjection(result) {
		result.Matches = result.Matches[:0:0]
		result.WarnedMatches = result.WarnedMatches[:0:0]
		result.SuppressedMatches = result.SuppressedMatches[:0:0]
		result.ObservedCoreMatches = result.ObservedCoreMatches[:0:0]
		o.inj = append(o.inj, sseInjectionSeen{text: text, result: result})
	}
	return result
}

func reusableSSEInjection(result scanner.ResponseScanResult) bool {
	return result.Clean && !result.Failed() && !result.InspectionIncomplete &&
		result.Assessment.Checker == scanner.InjectionCheckerBasic && result.Assessment.IsBenign() &&
		len(result.Matches)+len(result.WarnedMatches)+len(result.SuppressedMatches)+len(result.ObservedCoreMatches) == 0 &&
		result.TransformedContent == "" && !result.StegoDetected && result.StegoDensity == 0
}
