// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// auditObservedAction turns a configured block or ask into warn while audit
// mode is observing that contributor. Redirect, defer, and every other action
// pass through. Callers pass only a contributor they have already classified
// as liftable.
func auditObservedAction(audit bool, action string) string {
	if audit && (action == config.ActionBlock || action == config.ActionAsk) {
		return config.ActionWarn
	}
	return action
}

// chainAuditAction observes a matched pattern's action. A call the matcher
// could not track is a resource limit and keeps its block.
func chainAuditAction(audit bool, verdict chains.Verdict) string {
	if verdict.ResourceLimit {
		return verdict.Action
	}
	return auditObservedAction(audit, verdict.Action)
}

// fragmentHasCoreMatch reports whether a reassembled cross-request match is a
// core credential, which audit mode never releases.
func fragmentHasCoreMatch(matches []scanner.DLPMatch) bool {
	for _, match := range matches {
		if config.IsCoreDLPPatternName(match.PatternName) {
			return true
		}
	}
	return false
}

// auditContentAction is the content contributor's action after the audit
// lift. A verdict is lifted only when every finding in it is configured
// policy; one floor finding keeps the effective action.
func auditContentAction(audit bool, sc *scanner.Scanner, verdict InputVerdict, configuredAction string, msg []byte) string {
	action := inputVerdictEffectiveAction(verdict, configuredAction)
	if !audit {
		return action
	}
	urls, urlsOK := mcpResourceScanURLs(msg)
	if !contentVerdictLiftable(sc, verdict, urls, urlsOK) {
		return action
	}
	return auditObservedAction(true, action)
}

// contentVerdictLiftable reports whether every finding in verdict is
// configured policy. URL findings lift only for the named scanners, and only
// after the core credential floor is re-run on the submitted resource URL and
// its HTTP view. A URL finding whose raw URL cannot be read is not liftable.
// A high-entropy subdomain is also a hostname-exfiltration text match, so
// that floor keeps the whole message refused.
func contentVerdictLiftable(sc *scanner.Scanner, verdict InputVerdict, rawURLs []string, urlsOK bool) bool {
	if verdict.Error != "" {
		return false
	}
	if scanner.ContainsCoreCriticalMatch(verdict.Matches) ||
		scanner.ContainsHostnameExfilMatch(verdict.Matches) ||
		scanner.HasInspectionLimit(verdict.Matches) {
		return false
	}
	for _, match := range verdict.Matches {
		if match.PatternName == uninspectableSplitSecretFieldsReason {
			return false
		}
	}
	if len(verdict.URLFindings) > 0 {
		for _, finding := range verdict.URLFindings {
			if !urlFindingPolicyOnly(finding) {
				return false
			}
		}
		if sc == nil || !urlsOK || len(rawURLs) == 0 {
			return false
		}
		for _, rawURL := range rawURLs {
			if !sc.ScanURLCoreFloor(rawURL).Allowed {
				return false
			}
		}
	}
	return len(verdict.Matches) > 0 || len(verdict.Inject) > 0 || len(verdict.AddressFindings) > 0 || len(verdict.URLFindings) > 0
}

// urlFindingPolicyOnly is the explicit scanner allow-list for a resource URL
// finding that audit mode may observe. Unknown labels stay refused.
func urlFindingPolicyOnly(finding scanner.Result) bool {
	if finding.Allowed || scanner.IsCoreCriticalResult(finding) || scanner.IsHostnameExfilResult(finding) {
		return false
	}
	switch finding.Scanner {
	case scanner.ScannerAllowlist, scanner.ScannerBlocklist, scanner.ScannerDLP, scanner.ScannerEntropy, scanner.ScannerSubdomainEntropy:
		return true
	default:
		return false
	}
}

// mcpResourceScanURLs returns the submitted resources/read URI and, when it
// differs, the HTTP view the scanner actually checked. ok is false when a
// resources/read URI cannot be read back from msg.
func mcpResourceScanURLs(msg []byte) (urls []string, ok bool) {
	frame := ParseMCPFrame(msg)
	if frame.Method != methodResourcesRead {
		return nil, true
	}
	if frame.ParseErr != nil {
		return nil, false
	}
	var envelope struct {
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(msg), &envelope); err != nil {
		return nil, false
	}
	trimmed := bytes.TrimSpace(envelope.Params)
	if len(trimmed) == 0 || string(trimmed) == jsonrpc.Null {
		return nil, false
	}
	var req struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return nil, false
	}
	uri := strings.TrimSpace(req.URI)
	if uri == "" {
		return nil, false
	}
	view, viewOK, err := httpResourceURLView(uri)
	if !viewOK || err != nil {
		return nil, false
	}
	urls = []string{uri}
	if view != uri {
		urls = append(urls, view)
	}
	return urls, true
}

// a2aAuditAction observes a completed A2A content block. Inspection, config,
// budget, infrastructure, and core findings stay blocked. Ask is unchanged.
func a2aAuditAction(audit bool, result A2AScanResult, action string) string {
	if !audit || action != config.ActionBlock || !a2aContentLiftable(result) {
		return action
	}
	return config.ActionWarn
}

func a2aContentLiftable(result A2AScanResult) bool {
	if result.InspectionIncomplete || result.ScanError != "" || result.IsConfigMismatch() {
		return false
	}
	if result.BudgetExceeded && len(result.DLPFindings) == 0 && len(result.InjectFindings) == 0 && len(result.URLFindings) == 0 && result.EntropyFinding == nil {
		return false
	}
	if mcpA2AOperationalURLFindingsOnly(result) {
		return false
	}
	if scanner.ContainsCoreCriticalMatch(result.DLPFindings) ||
		scanner.ContainsHostnameExfilMatch(result.DLPFindings) ||
		scanner.HasInspectionLimit(result.DLPFindings) {
		return false
	}
	for _, match := range result.DLPFindings {
		if match.PatternName == uninspectableSplitSecretFieldsReason {
			return false
		}
	}
	for _, finding := range result.URLFindings {
		if !urlFindingPolicyOnly(finding) {
			return false
		}
		switch finding.Class {
		case scanner.ClassInfrastructureError, scanner.ClassProtective, scanner.ClassConfigMismatch:
			return false
		}
	}
	return len(result.DLPFindings) > 0 || len(result.InjectFindings) > 0 || len(result.URLFindings) > 0 || result.EntropyFinding != nil
}

// observeBaselineAudit lifts a checker deviation. Fail-closed decisions never
// reach it: those returns happen before the checker result is normalized.
func observeBaselineAudit(opts MCPProxyOpts, decision session.BaselineDecision) session.BaselineDecision {
	lifted := auditObservedAction(opts.auditMode(), decision.Action)
	if lifted == decision.Action {
		return decision
	}
	decision.Action = lifted
	decision.Blocked = false
	return decision
}
