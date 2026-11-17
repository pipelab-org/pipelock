// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// CheckerPatternPrefix labels a proxy-owned external checker finding.
const CheckerPatternPrefix = "checker:"

// BufferedInjectionScan describes one existing buffered wording scan. Body
// retains the response body decoder; Outbound retains outbound decode limits.
// Neither changes DLP or other deterministic controls in the caller.
type BufferedInjectionScan struct {
	// Completeness defaults to complete; extracted-only callers retain partial coverage.
	Completeness  *checker.Completeness
	OriginalBytes int64
	// Texts, when present, are ordered extracted parts of the same content unit.
	Texts     []string
	Surface   string
	Transport string
	Direction string
	Content   string
	Body      []byte
	UseBody   bool
	Outbound  bool
	Target    string
	Suppress  []config.SuppressEntry
}

// ScanBufferedInjection joins a buffered consumer to the existing selection.
// The legacy scan runs unchanged without an explicit selection. External
// ownership suppresses all built-in wording, including on off and failure;
// there is no fallback. Callers retain partial semantic coverage in Completeness.
func (s *Scanner) ScanBufferedInjection(ctx context.Context, o BufferedInjectionScan) ResponseScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = WithInjectionSurface(ctx, o.Surface)
	var result ResponseScanResult
	switch {
	case o.UseBody:
		result = s.ScanResponseBodyWithSuppress(ctx, o.Body, o.Target, o.Suppress)
	case o.Outbound:
		result = s.ScanResponseOutbound(ctx, o.Content)
	default:
		result = s.ScanResponseWithSuppress(ctx, o.Content, o.Target, o.Suppress)
	}
	return s.ComposeBufferedInjection(ctx, o, result)
}

// ComposeBufferedInjection applies the deciding checker after the existing
// consumer has scanned all its views under WithInjectionSurface. It shares
// the result/failure composition with single-view buffered consumers.
func (s *Scanner) ComposeBufferedInjection(ctx context.Context, o BufferedInjectionScan, result ResponseScanResult) ResponseScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if result.Failed() || (!s.ExternalInjectionSurface(o.Surface) && !s.InjectionCheckers().Watches(o.Surface)) {
		return result
	}
	originalBytes := int64(len(o.Content))
	texts := o.Texts
	if o.UseBody {
		originalBytes = int64(len(o.Body))
		var err error
		texts, err = bufferedBodyInjectionTexts(ctx, o.Body)
		if err != nil {
			result.Clean = false
			result.ScanError = err.Error()
			result.TransformedContent = ""
			return result
		}
	} else if texts == nil {
		texts = []string{o.Content}
	}
	if o.OriginalBytes > 0 {
		originalBytes = o.OriginalBytes
	}
	parts := InjectionTextParts(texts...)
	if len(parts) == 0 {
		return result
	}
	transport := o.Transport
	if transport == "" {
		transport = DLPWarnContextFromCtx(ctx).Transport
	}
	if transport == "" {
		transport = o.Surface
	}
	direction := o.Direction
	if direction == "" {
		direction = "response"
	}
	var submitted int64
	for _, p := range parts {
		submitted += int64(len(p.Text))
	}
	completeness := o.Completeness
	if completeness == nil {
		completeness = &checker.Completeness{Status: checker.Complete}
	}
	item := checker.Item{
		ID: "buffered-" + o.Surface, Kind: checker.KindText, Surface: o.Surface,
		Transport: transport, Direction: direction, ExtractionVersion: "buffered-text/v1",
		Parts: parts, OriginalBytes: originalBytes, SubmittedBytes: submitted,
		Completeness: completeness,
	}
	ext, ok := s.AssessInjection(ctx, o.Surface, item)
	if !ok {
		return result
	}
	result.Assessment = ext.Recovery()
	switch {
	case ext.Block() && ext.Finding():
		result.Clean = false
		result.Matches = append(result.Matches, ResponseMatch{PatternName: CheckerPatternPrefix + ext.Checker, externalCheckerBlock: true})
		result.TransformedContent = ""
	case ext.Block():
		result.Clean = false
		result.ScanError = fmt.Sprintf("injection checker %s did not assess content (%s)", ext.Checker, ext.Reason())
		result.TransformedContent = ""
	case ext.Finding():
		result.WarnedMatches = append(result.WarnedMatches, ResponseMatch{PatternName: CheckerPatternPrefix + ext.Checker})
	}
	return result
}

// InjectionTextParts preserves valid source text and labels Unicode views,
// matching the MCP checker seam. Invalid byte runs become spaces, as in the
// response body view, before any checker parts or normalized views are built.
// It never adds base64 or hex decoded checker views.
func InjectionTextParts(texts ...string) []checker.Part {
	var parts []checker.Part
	for i, text := range texts {
		text = strings.ToValidUTF8(text, " ")
		if text == "" {
			continue
		}
		id := "text-" + strconv.Itoa(i)
		parts = append(parts, checker.Part{ID: id, Role: "content", Representation: "original", Text: text})
		tags := normalize.DecodeTags(text)
		if tags != text {
			parts = append(parts, checker.Part{ID: id + ":tags", Role: "decoded_view", Representation: "unicode_tags/v1", Text: tags})
		}
		if m := normalize.ForMatching(tags); m != text && m != tags {
			parts = append(parts, checker.Part{ID: id + ":normalized", Role: "decoded_view", Representation: "for_matching/v1", Text: m})
		}
	}
	return parts
}

// CheckerBlocked reports a deciding external finding. A transport's legacy
// wording action must never lower this explicit block decision.
func (r ResponseScanResult) CheckerBlocked() bool { return HasCheckerFinding(r.Matches) }

// HasCheckerFinding identifies external block findings in composed verdicts.
// Warn assessments deliberately do not enter enforcing match slices.
func HasCheckerFinding(matches []ResponseMatch) bool {
	for _, m := range matches {
		if m.externalCheckerBlock {
			return true
		}
	}
	return false
}

// EnforcementAction preserves the legacy action except for an external block.
func (r ResponseScanResult) EnforcementAction(action string) string {
	if r.CheckerBlocked() {
		return config.ActionBlock
	}
	return action
}

// ScanHookInjection is shared by hook implementations. Input and result text
// have distinct operator selections; hook extraction and DLP stay with callers.
func (s *Scanner) ScanHookInjection(ctx context.Context, text, transport string, inbound bool) ResponseScanResult {
	surface, direction := config.InjectionSurfaceHookToolInput, "request"
	if inbound {
		surface, direction = config.InjectionSurfaceHookToolResult, "response"
	}
	result := s.ScanBufferedInjection(ctx, BufferedInjectionScan{Surface: surface, Transport: transport, Direction: direction, Content: text})
	sp := s.InjectionPolicy().For(surface)
	if sp.External() && sp.Mode == config.InjectionModeWarn && result.Assessment.Status != AssessmentBenign {
		s.ReportInjectionWarnings(ctx, []string{CheckerPatternPrefix + sp.Checker + " (" + string(result.Assessment.Status) + ")"})
	}
	return result
}

// bufferedBodyInjectionTexts follows the response body's established prose
// boundary. Opaque bytes and image pixels are never checker content. Encoded
// chain and decoded base64/hex views remain outside buffered checker routing.
func bufferedBodyInjectionTexts(ctx context.Context, body []byte) ([]string, error) {
	metadata, image, err := responseImageMetadata(body)
	if image {
		if err != nil {
			return nil, fmt.Errorf("image metadata inspection failed: %w", err)
		}
		if len(metadata) == 0 {
			return nil, nil
		}
		// Metadata combines formats with different encodings. Preserve valid
		// UTF-8 and ASCII wording, separating invalid byte runs as in the
		// non-image body view rather than sending invalid protocol text.
		return []string{string(bytes.ToValidUTF8(metadata, []byte(" ")))}, nil
	}
	textual, err := isTextualResponseBody(ctx, body)
	if err != nil {
		return nil, err
	}
	if textual || hasResponseImageSignature(body) {
		return []string{string(bytes.ToValidUTF8(body, []byte(" ")))}, nil
	}
	decoded, wide, err := decodeLikelyWideResponseBody(ctx, body)
	if err != nil {
		return nil, err
	}
	views, err := opaqueResponseTextView(ctx, body)
	if err != nil {
		return nil, err
	}
	texts := []string{views.retained, views.fragmented}
	if wide {
		texts = append([]string{decoded}, texts...)
	}
	return texts, nil
}
