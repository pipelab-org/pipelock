// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// checkerExtractionVersion labels how MCP text is turned into checker parts.
const checkerExtractionVersion = "mcp-text/v1"

// CheckerPatternPrefix prefixes the pattern name of an external checker
// finding, followed by the checker name.
const CheckerPatternPrefix = "checker:"

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
	parts, completeness := sc.BuildInjectionTextParts(ctx, config.InjectionSurfaceMCPToolResult, texts...)
	if len(parts) == 0 && completeness.Status == checker.Complete {
		return verdict
	}
	item := checkerItem(config.InjectionSurfaceMCPToolResult, opts.checkerTransport(), originalBytes, parts)
	item.Completeness = completeness
	ext, ok := sc.AssessInjection(ctx, config.InjectionSurfaceMCPToolResult, item)
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
			ID: verdict.ID, Action: config.ActionBlock, Assessment: ext.Recovery(),
			Error: fmt.Sprintf("injection checker %s did not assess the response (%s)", ext.Checker, ext.Reason()),
		}
	default:
		verdict.Assessment = ext.Recovery()
	}
	return verdict
}

func (o ResponseScanOptions) checkerTransport() string {
	return mcpCheckerTransport(o.scanContext())
}
