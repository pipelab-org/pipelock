// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"strconv"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// checkerExtractionVersion labels how MCP text is turned into checker parts.
const checkerExtractionVersion = "mcp-text/v1"

// CheckerPatternPrefix prefixes the pattern name of an external checker
// finding, followed by the checker name.
const CheckerPatternPrefix = "checker:"

// checkerTextParts turns ordered texts into checker parts. Each text keeps its
// original form, and a normalized or decoded view is added as a labelled
// extra part when it differs, so a checker sees what the built-in matcher
// would have seen. Empty texts are skipped.
func checkerTextParts(prefix string, texts ...string) []checker.Part {
	var parts []checker.Part
	for i, text := range texts {
		if text == "" {
			continue
		}
		id := prefix + strconv.Itoa(i)
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

func checkerItem(surface, transport string, originalBytes int, parts []checker.Part) checker.Item {
	if transport == "" {
		transport = "mcp"
	}
	var submitted int64
	for _, p := range parts {
		submitted += int64(len(p.Text))
	}
	return checker.Item{
		ID: "mcp-" + surface, Kind: checker.KindText, Surface: surface, Transport: transport,
		Direction: "response", ExtractionVersion: checkerExtractionVersion, Parts: parts,
		OriginalBytes: int64(originalBytes), SubmittedBytes: submitted,
		Completeness: &checker.Completeness{Status: checker.Complete},
	}
}

// applyResponseChecker lets the external checker that owns the MCP result
// surface decide on texts, after the built-in pipeline produced verdict
// (which ran DLP but no wording rules for that surface). A block-mode
// finding blocks; any other block-mode result that is not a complete benign
// assessment withholds the response as an assessment failure; warn mode
// never changes delivery. The response is never handed back to the
// built-in wording rules.
func applyResponseChecker(ctx context.Context, sc *scanner.Scanner, opts ResponseScanOptions, originalBytes int, verdict jsonrpc.ScanVerdict, texts ...string) jsonrpc.ScanVerdict {
	if !sc.ExternalInjectionSurface(config.InjectionSurfaceMCPToolResult) && !sc.InjectionCheckers().Watches(config.InjectionSurfaceMCPToolResult) {
		return verdict
	}
	if verdict.Error != "" && verdict.Action == config.ActionBlock {
		return verdict
	}
	parts := checkerTextParts("text-", texts...)
	if len(parts) == 0 {
		return verdict
	}
	ext, ok := sc.AssessInjection(ctx, config.InjectionSurfaceMCPToolResult, checkerItem(config.InjectionSurfaceMCPToolResult, opts.checkerTransport(), originalBytes, parts))
	if !ok {
		return verdict
	}
	switch {
	case ext.Block() && ext.Finding():
		verdict.Clean = false
		verdict.Action = config.ActionBlock
		verdict.Matches = append(verdict.Matches, scanner.ResponseMatch{PatternName: CheckerPatternPrefix + ext.Checker})
		verdict.Assessment = ext.Recovery()
	case ext.Block():
		return jsonrpc.ScanVerdict{
			ID: verdict.ID, Action: config.ActionBlock,
			Error: fmt.Sprintf("injection checker %s did not assess the response (%s)", ext.Checker, ext.Reason()),
		}
	default:
		verdict.Assessment = ext.Recovery()
	}
	return verdict
}

func (o ResponseScanOptions) checkerTransport() string {
	if wc := scanner.DLPWarnContextFromCtx(o.scanContext()); wc.Transport != "" {
		return wc.Transport
	}
	return "mcp"
}
