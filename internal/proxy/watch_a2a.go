// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// watchA2AResult carries the audit-mode security floor. Core includes
// incomplete inspections that audit mode refuses; Uninspected describes the
// inspection gap without claiming that refused bytes were forwarded.
type watchA2AResult struct {
	Core        bool
	Uninspected string
}

func watchA2AHeaders(r *http.Request, o watchHTTPOptions) bool {
	if !o.Config.A2AScanning.Enabled || !mcp.IsA2ARequest(r.URL.Path, r.Header.Get("Content-Type")) {
		return false
	}
	result := mcp.ScanA2AHeaders(r.Context(), r.Header, o.Scanner, &o.Config.A2AScanning)
	outcome := observeWatchA2A(result, "a2a_header", o.Config.A2AScanning.Action, o.observe)
	if outcome.Uninspected != "" && !outcome.Core {
		// Header/URL counters describe the admitted representation; body
		// counters instead follow reads of the forwarded replay stream.
		var count int64
		for _, value := range r.Header.Values("A2A-Extensions") {
			count += int64(len(value))
		}
		o.observe("a2a_header", outcome.Uninspected, "uninspected", count, false)
	}
	return outcome.Core
}

func watchA2ARequest(ctx context.Context, r *http.Request, body []byte, o watchRequestOptions) watchA2AResult {
	if !o.Config.A2AScanning.Enabled || !mcp.IsA2ARequest(r.URL.Path, r.Header.Get("Content-Type")) {
		return watchA2AResult{}
	}
	result := mcp.ScanA2ARequestBody(ctx, body, o.Scanner, &o.Config.A2AScanning, a2aContentEntropyOptions(r.URL.Hostname(), o.Config))
	return observeWatchA2A(result, scannerLabelA2A, o.Config.A2AScanning.Action, func(layer, reason, action string, count int64, enforced bool) {
		watchObservation(o.Logger, o.Metrics, o.Transport, layer, reason, action, count, enforced)
	})
}

func watchA2AResponse(ctx context.Context, resp *http.Response, body []byte, o watchResponseOptions, baseline *mcp.CardBaseline) watchA2AResult {
	if !o.Config.A2AScanning.Enabled || resp.Request == nil || resp.Request.URL == nil {
		return watchA2AResult{}
	}
	req := resp.Request
	if !mcp.IsA2ARequest(req.URL.Path, req.Header.Get("Content-Type")) {
		return watchA2AResult{}
	}
	if !mcp.IsAgentCardPath(req.URL.Path) {
		result := mcp.ScanA2AResponseBody(ctx, body, o.Scanner, &o.Config.A2AScanning)
		return observeWatchA2A(result, "a2a_response", o.Config.A2AScanning.Action, o.record)
	}
	card := mcp.ScanAgentCardWithOptions(ctx, body, o.Scanner, mcp.A2AResponseOpts{
		Cfg: &o.Config.A2AScanning, Baseline: baseline,
		CardKey: mcp.CardCacheKeyFromRequest(req.URL.String(), req.Header.Get("Authorization")),
	})
	result := observeWatchA2A(card.Findings, "a2a_response", o.Config.A2AScanning.Action, o.record)
	if !card.Clean && !card.Findings.InspectionIncomplete && card.Findings.ScanError == "" {
		action := card.Action
		if action == "" {
			action = o.Config.A2AScanning.Action
		}
		o.record("a2a_card", card.Reason, action, 0, false)
	}
	if card.BaselineCapacityExceeded {
		result.Uninspected = "Agent Card baseline capacity exhausted"
		o.record(scannerLabelA2ACardDrift, result.Uninspected, "uninspected", 0, false)
	}
	if card.DriftAdopted {
		o.record(scannerLabelA2ACardDrift, "Agent Card descriptive drift adopted", config.ActionAllow, 0, false)
	}
	if card.SignatureVerified {
		o.record(scannerLabelA2ACardSignature, "Agent Card signature verified", config.ActionAllow, 0, false)
	}
	return result
}

// observeWatchA2A retains the existing scanner classifications and resolved
// actions. It never calls a blocked-event writer or modifies payload bytes.
func observeWatchA2A(result mcp.A2AScanResult, layer, fallbackAction string, observe func(string, string, string, int64, bool)) watchA2AResult {
	outcome := watchA2AResult{Core: containsCoreFloorMatch(result.DLPFindings) || scanner.HasInspectionLimit(result.DLPFindings)}
	action := result.Action
	if action == "" {
		action = fallbackAction
	}
	if action == "" {
		action = config.ActionBlock
	}
	for _, finding := range result.URLFindings {
		core := scanner.IsCoreCriticalResult(finding)
		outcome.Core = outcome.Core || core
		findingAction := action
		if core {
			findingAction = config.ActionBlock
		}
		observe(layer, finding.Scanner+": "+finding.Reason, findingAction, 0, core)
	}
	for _, finding := range result.DLPFindings {
		core := (!finding.Warn && scanner.IsCoreCriticalMatch(finding)) || scanner.HasInspectionLimit([]scanner.TextDLPMatch{finding})
		findingAction := action
		if core {
			findingAction = config.ActionBlock
		}
		observe(layer, finding.PatternName, findingAction, 0, core)
	}
	for _, finding := range result.InjectFindings {
		observe(layer, finding.PatternName, action, 0, false)
	}
	if result.EntropyFinding != nil {
		observe(layer, "A2A content entropy finding", action, 0, false)
	}
	if result.InspectionIncomplete || result.ScanError != "" {
		outcome.Uninspected = "A2A structured inspection incomplete"
		if result.ScanError != "" {
			outcome.Uninspected = "A2A scanner could not complete inspection"
		}
		outcome.Core = true
		observe(layer, outcome.Uninspected, config.ActionBlock, 0, true)
	} else if !result.Clean && len(result.URLFindings) == 0 && len(result.DLPFindings) == 0 && len(result.InjectFindings) == 0 && result.EntropyFinding == nil && result.Reason != "" {
		observe(layer, result.Reason, action, 0, false)
	}
	return outcome
}
