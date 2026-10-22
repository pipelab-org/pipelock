// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	dowSubjectKeyDefault   = "_default"
	dowSubjectTrustDefault = "default"
	dowAuditFallbackTarget = "invalid-mcp-resource"
)

func mustMCPAuditContext(logger *audit.Logger, method, resource string) audit.LogContext {
	ctx, err := audit.NewMCPLogContext(method, resource, "")
	if err != nil {
		if logger != nil {
			logger.LogError(audit.NewMethodLogContext(method), err)
		}
		return audit.NewMethodLogContext(method)
	}
	return ctx
}

// logMCPInputBlock uses only scanner-owned labels and configured pattern names.
// Input verdict reasons can contain request bytes (notably URL and parse errors).
func logMCPInputBlock(logger *audit.Logger, verdict InputVerdict) {
	if logger == nil {
		return
	}
	scannerName := scanner.ScannerParser
	reason := string(mcpScannerBlockReason(verdict, policy.Verdict{}, false))
	switch {
	case len(verdict.Matches) > 0:
		scannerName = scanner.ScannerDLP
		reason = verdict.Matches[0].PatternName
	case len(verdict.Inject) > 0:
		scannerName = scanner.AuditResponseScan
		reason = verdict.Inject[0].PatternName
	case len(verdict.URLFindings) > 0:
		scannerName = verdict.URLFindings[0].Scanner
	case len(verdict.AddressFindings) > 0:
		scannerName = scanner.AuditAddressProtection
		reason = "address protection blocked"
	}
	logger.LogBlocked(mustMCPAuditContext(logger, "MCP", "mcp_input"), scannerName, reason)
}

// inputBlockedByContent reports whether the content scan is what blocked an
// input request: it blocks on its own, or no other control (tool policy,
// session binding, chain detection, behavioral baseline) enforced anything, so
// the block is the content verdict after any adaptive upgrade. A request
// blocked by another control must not be attributed to a scanner pattern: the
// event's remediation hint would send the operator to a suppression that the
// blocking control never consults.
func inputBlockedByContent(verdict InputVerdict, contentAction string, otherActions ...string) bool {
	if verdict.Clean {
		return false
	}
	if inputVerdictEffectiveAction(verdict, contentAction) == config.ActionBlock {
		return true
	}
	for _, other := range otherActions {
		if other != "" && other != config.ActionWarn && other != config.ActionAllow {
			return false
		}
	}
	return true
}

// matchedPolicyAction is the tool policy action, or "" when no rule matched.
func matchedPolicyAction(verdict policy.Verdict) string {
	if !verdict.Matched {
		return ""
	}
	return verdict.Action
}

// logMCPListenerHeaderBlock records a listener header DLP, injection or
// encoding block. The header name and value are request bytes (an Mcp-Param-
// suffix is client-chosen), so only the pattern name or a fixed label is used.
func logMCPListenerHeaderBlock(logger *audit.Logger, result *mcpListenerHeaderDLPResult) {
	if logger == nil || result == nil {
		return
	}
	_, pattern := listenerHeaderBlockClassification(result)
	scannerName := scanner.ScannerParser
	detail := audit.BlockDetail{}
	switch {
	case len(result.matches) > 0:
		scannerName = scanner.ScannerDLP
	case result.reason == blockreason.PromptInjection:
		scannerName = scanner.AuditResponseScan
	case result.reason == blockreason.ParseError:
		// The decoded header could not be scanned; it is not evidence of
		// an attack pattern or a malformed client header.
		scannerName = scanner.AuditResponseScan
		pattern = "response scan parse error in MCP parameter header"
		detail.Class = audit.BlockClassInfrastructureError
	}
	logger.LogBlockedDetail(mustMCPAuditContext(logger, "MCP", "mcp_listener_header"), scannerName, pattern, detail)
}

// logMCPListenerReplyBlock records an upstream HTTP error reply withheld by
// response scanning. finding is a pattern name or a fixed scan-failure label,
// never reply bytes (see upstreamClientErrorFinding).
func logMCPListenerReplyBlock(logger *audit.Logger, finding string) {
	if logger == nil {
		return
	}
	detail := audit.BlockDetail{}
	switch finding {
	case "response scanner unavailable", "uninspectable reply":
		// These are scan-integrity refusals, not observed prompt injection.
		// Route to scan-integrity guidance and omit MITRE.
		finding = "response scan cannot be scanned: " + finding
		detail.Class = audit.BlockClassInfrastructureError
	case "response scan finding":
		finding = "response scan returned an incomplete verdict"
		detail.Class = audit.BlockClassInfrastructureError
	}
	logger.LogBlockedDetail(mustMCPAuditContext(logger, "MCP", "upstream_error_reply"), scanner.AuditResponseScan, finding, detail)
}

func resolvedDoWAttribution(opts MCPProxyOpts) (string, DoWAttribution) {
	agent := identitykey.CEESafeAgent(opts.DoWSubjectAgent, opts.DoWSubjectAgentAuth)
	if agent == "" {
		agent = metrics.DoWAgentDefault
	}
	attribution := opts.DoWAttribution
	if attribution.SubjectKey == "" {
		attribution.SubjectKey = dowSubjectKeyDefault
	}
	attribution.Trust = resolvedDoWTrust(attribution.Trust)
	return agent, attribution
}

func resolvedDoWTrust(trust string) string {
	switch trust {
	case config.DoWTrustNetwork.String(), config.DoWTrustAgent.String(), config.DoWTrustPrincipal.String():
		return trust
	default:
		return dowSubjectTrustDefault
	}
}

func mustMCPDoWAuditContext(logger *audit.Logger, resource string, opts MCPProxyOpts) audit.LogContext {
	return mcpDoWAuditContext(logger, resource, opts, audit.NewMCPLogContext)
}

func mcpDoWAuditContext(
	logger *audit.Logger,
	resource string,
	opts MCPProxyOpts,
	newContext func(method, resource, agent string) (audit.LogContext, error),
) audit.LogContext {
	agent, attribution := resolvedDoWAttribution(opts)
	ctx, err := newContext("MCP", resource, agent)
	if err != nil {
		if logger != nil {
			logger.LogError(audit.NewMethodLogContext("MCP"), err)
		}
		ctx, _ = audit.NewMCPLogContext("MCP", dowAuditFallbackTarget, agent)
	}
	return ctx.WithDoWAttribution(attribution.SubjectKey, attribution.Trust)
}

func recordDoWMetric(m *metrics.Metrics, action string, opts MCPProxyOpts) {
	if m == nil {
		return
	}
	agent, attribution := resolvedDoWAttribution(opts)
	m.RecordDenialOfWalletEvent(action, agent, attribution.Trust)
}
