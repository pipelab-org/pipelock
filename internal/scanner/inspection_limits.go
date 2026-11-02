// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// Decoder bounds exist to cap scan cost. Reaching one with decodable content
// left means some views were never scanned. Returning the views that were
// produced as if they were all of them turns every bound into a length or
// depth past which detection quietly stops, so the URL and outbound text
// paths refuse instead. The bounds themselves are unchanged: receipt replay
// pins the same numbers, and a refusal leaves those profiles intact.

// urlInspectionLimitReason names the URL refusal. It is a core-floor result
// (ScannerCoreDLP), so it holds in audit mode and against warn actions the
// same way an incomplete body inspection does.
const urlInspectionLimitReason = "core DLP inspection limit: URL encoding could not be fully decoded"

func urlInspectionLimitResult() Result {
	return Result{
		Allowed: false,
		Reason:  urlInspectionLimitReason,
		Scanner: ScannerCoreDLP,
		Score:   1.0,
	}
}

// IsURLInspectionLimitResult reports a URL refused because a decoder bound
// was reached, rather than for a content match.
func IsURLInspectionLimitResult(r Result) bool {
	return !r.Allowed && r.Scanner == ScannerCoreDLP && r.Reason == urlInspectionLimitReason
}

// urlPercentDecodeConverges reports whether every percent-encoded URL
// component reaches a fixed point within maxDecodeRounds under both the form
// (query) and RFC 3986 (path, fragment, userinfo) unescapers. The URL
// detectors decode components with those same functions and stop at that
// ceiling; a component still changing there was never seen in the form a
// receiver that decodes to a fixed point recovers.
//
// Reassembled values and views recovered from other encodings are checked
// separately by the fixpoint decoder: joining can create a percent escape
// across a delimiter that was present in the original component.
func urlPercentDecodeConverges(parsed *url.URL) bool {
	components := []string{parsed.RawQuery, parsed.EscapedPath(), parsed.EscapedFragment()}
	if parsed.User != nil {
		components = append(components, parsed.User.String())
	}
	for _, component := range components {
		if !percentDecodeConverges(component, normalize.QueryUnescapePartial) ||
			!percentDecodeConverges(component, normalize.PercentUnescapePartial) {
			return false
		}
	}
	return true
}

func percentDecodeConverges(s string, unescape func(string) string) bool {
	for range maxDecodeRounds {
		decoded := unescape(s)
		if decoded == s {
			return true
		}
		s = decoded
	}
	return unescape(s) == s
}

type inboundScanCtxKey struct{}

// WithInboundDirection marks text scans under ctx as scanning content the
// agent receives. Some response paths (generic SSE events, A2A responses)
// use the outbound text-DLP entry points for their pattern and secret
// checks; the marker keeps them from refusing a response at a decode bound,
// which is an outbound-only refusal.
func WithInboundDirection(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, inboundScanCtxKey{}, true)
}

func inboundDirection(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	inbound, _ := ctx.Value(inboundScanCtxKey{}).(bool)
	return inbound
}
