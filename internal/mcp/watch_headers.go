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
		opts.recordWatch("mcp_headers", "scanner unavailable", "uninspected", int64(watchHeaderBytes(headers)), false)
		return false
	}
	if result := scanMCPListenerHeadersForTarget(ctx, headers, sc, opts.requestBodyCfg(), target); result != nil {
		reason, pattern := listenerHeaderBlockClassification(result)
		opts.recordWatch("mcp_headers", string(reason)+": "+pattern, config.ActionBlock, 0, false)
	}
	var joined []string
	core := false
	add := func(value string) {
		joined = append(joined, value)
		matches := sc.ScanTextForDLP(ctx, value).Matches
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
			core = core || scanner.IsCoreCredentialResult(finding)
		}
		if result.InspectionIncomplete || result.ScanError != "" || result.BudgetExceeded {
			opts.recordWatch("a2a_headers", "header inspection incomplete", "uninspected", int64(watchHeaderBytes(headers)), false)
		}
	}
	if core {
		opts.recordWatch("dlp", "core credential floor in request headers", config.ActionBlock, 0, true)
	}
	return core
}

func watchHeaderBytes(headers http.Header) int {
	n := 0
	for name, values := range headers {
		n += len(name)
		for _, value := range values {
			n += len(value)
		}
	}
	return n
}
