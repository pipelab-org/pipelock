// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// watchMCPHeaders reuses the existing header contract while independently
// checking the credential floor after any earlier configurable finding.
func watchMCPHeaders(ctx context.Context, headers http.Header, target string, opts MCPProxyOpts) bool {
	sc := opts.scanner()
	if sc == nil {
		opts.recordWatch("mcp_headers", "scanner unavailable", config.ActionBlock, 0, true)
		return true
	}
	if result := scanMCPListenerHeadersForTarget(ctx, headers, sc, opts.requestBodyCfg(), target); result != nil {
		reason, pattern := listenerHeaderBlockClassification(result)
		opts.recordWatch("mcp_headers", string(reason)+": "+pattern, config.ActionBlock, 0, false)
	}
	var joined []string
	core := false
	add := func(value string) {
		joined = append(joined, value)
		verdict := sc.ScanTextForDLP(ctx, value)
		core = core || verdict.Err() != nil
		matches := verdict.Matches
		core = core || watchCoreMatches(matches)
		if scanner.HasInspectionLimit(matches) {
			opts.recordWatch("mcp_headers", "header inspection limit", "uninspected", int64(len(value)), false)
		}
	}
	for name, values := range mcpListenerHeadersToScan(headers, opts.requestBodyCfg()) {
		if mcpListenerShouldScanHeaderNames(opts.requestBodyCfg()) {
			add(name)
		}
		for _, value := range values {
			if http.CanonicalHeaderKey(name) == listenerAuthorization && len(values) == 1 {
				value = scanner.ScrubSigV4AuthorizationForTarget(value, target)
			}
			add(value)
			if mcpListenerShouldScanHeaderNames(opts.requestBodyCfg()) {
				add(name + value)
			}
			if strings.HasPrefix(strings.ToLower(name), mcpParamHeaderPrefix) {
				if decoded, ok := decodeMCPHeaderValue(value); ok {
					add(decoded)
				}
			}
		}
	}
	sort.Strings(joined)
	core = core || watchCoreMatches(sc.ScanTextForDLP(ctx, strings.Join(joined, "\n")).Matches)
	if cfg := opts.a2aCfg(); cfg != nil && cfg.Enabled {
		result := ScanA2AHeaders(ctx, headers, sc, cfg)
		if !result.Clean {
			opts.recordWatch("a2a_headers", result.Reason, result.Action, 0, false)
		}
		core = core || watchCoreMatches(result.DLPFindings)
		for _, finding := range result.URLFindings {
			core = core || scanner.IsCoreCriticalResult(finding) || scanner.IsHostnameExfilResult(finding)
		}
		if result.InspectionIncomplete || result.ScanError != "" || result.BudgetExceeded {
			core = true
			opts.recordWatch("a2a_headers", "header inspection incomplete", config.ActionBlock, 0, true)
		}
	}
	if core {
		opts.recordWatch("dlp", "core credential floor in request headers", config.ActionBlock, 0, true)
	}
	return core
}
