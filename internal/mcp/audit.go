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
	dowSubjectKeyDefault     = "_default"
	dowSubjectTrustDefault   = "default"
	dowAuditFallbackTarget   = "invalid-mcp-resource"
	mcpReceiptEmissionReason = "MCP receipt emission failed"
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

// logMCPInputBlock uses finding-kind labels and configured pattern names.
// Input verdict reasons can contain request bytes (notably URL and parse errors).
func logMCPInputBlock(logger *audit.Logger, verdict InputVerdict) {
	if logger == nil {
		return
	}
	scannerName := scanner.AuditMCPInputInspection
	reason := string(mcpScannerBlockReason(verdict, policy.Verdict{}, false))
	detail := audit.BlockDetail{Class: audit.BlockClassInfrastructureError}
	switch {
	case verdict.Error != "":
		// A failed inspection is the enforcing gate even if a raw fallback
		// found content. No attacker-controlled parse diagnostic enters audit.
	case len(verdict.Matches) > 0:
		scannerName = scanner.AuditMCPInputDLP
		reason = verdict.Matches[0].PatternName
		detail.Class = audit.BlockClassThreat
	case len(verdict.Inject) > 0:
		scannerName = scanner.AuditMCPInputInjection
		reason = verdict.Inject[0].PatternName
		detail.Class = audit.BlockClassThreat
	case len(verdict.URLFindings) > 0:
		scannerName = verdict.URLFindings[0].Scanner
		detail.Class = audit.BlockClassThreat
	case len(verdict.AddressFindings) > 0:
		scannerName = scanner.AuditAddressProtection
		reason = "address protection blocked"
		detail.Class = audit.BlockClassThreat
	}
	logger.LogBlockedDetail(mustMCPAuditContext(logger, "MCP", "mcp_input"), scannerName, reason, detail)
}

// logMCPInputDecisionBlock records exactly one final denial. Content wins when
// its own action blocks; otherwise the first enforcing control in this fixed
// precedence supplies the label. Reasons are fixed or policy-owned strings.
func logMCPInputDecisionBlock(logger *audit.Logger, verdict InputVerdict, contentBlock bool, policyVerdict policy.Verdict, bindingAction, chainAction, chainPattern, baselineAction string) {
	if logger == nil {
		return
	}
	if contentBlock {
		logMCPInputBlock(logger, verdict)
		return
	}
	// MCP input has no human approval, so a control that asks is enforced as
	// a block (behavioral_baseline.deviation_action: ask). That control, not
	// adaptive enforcement, made the denial.
	enforces := func(action string) bool {
		return action == config.ActionBlock || action == config.ActionAsk
	}
	label, reason := scanner.AuditAdaptiveEnforcement, "MCP input action upgraded to block"
	switch {
	case policyVerdict.Matched && enforces(policyVerdict.Action):
		label, reason = scanner.AuditMCPToolPolicy, "MCP tool policy blocked"
	case enforces(bindingAction):
		label, reason = scanner.AuditMCPSessionBinding, "MCP session binding blocked"
	case enforces(chainAction):
		label, reason = scanner.AuditChainDetection, chainPattern
	case enforces(baselineAction):
		label, reason = scanner.AuditSessionAnomaly, "baseline_deviation"
	}
	// If no control independently blocked, adaptive enforcement made the
	// warning into a denial. Its session guidance is the narrowest remedy.
	logger.LogBlocked(mustMCPAuditContext(logger, "MCP", "mcp_input"), label, reason)
}

func logMCPChainBlock(logger *audit.Logger, pattern string) {
	if logger != nil {
		logger.LogBlocked(mustMCPAuditContext(logger, "MCP", "mcp_input"), scanner.AuditChainDetection, pattern)
	}
}

func logMCPBaselineBlock(logger *audit.Logger) {
	if logger != nil {
		logger.LogBlocked(mustMCPAuditContext(logger, "MCP", "mcp_input"), scanner.AuditSessionAnomaly, "baseline_deviation")
	}
}

func logMCPCleanAdaptiveBlock(logger *audit.Logger) {
	if logger != nil {
		logger.LogBlocked(mustMCPAuditContext(logger, "MCP", "mcp_input"), scanner.AuditAdaptiveEnforcement, "MCP clean input action upgraded to block")
	}
}

// inputBlockedByContent is true only when the content verdict independently
// blocks. An adaptive upgrade of a warning uses the adaptive label instead.
func inputBlockedByContent(verdict InputVerdict, contentAction string) bool {
	return !verdict.Clean && inputVerdictEffectiveAction(verdict, contentAction) == config.ActionBlock
}

// logMCPListenerHeaderBlock records a listener header DLP, injection or
// encoding block. The header name and value are request bytes (an Mcp-Param-
// suffix is client-chosen), so only the pattern name or a fixed label is used.
func logMCPListenerHeaderBlock(logger *audit.Logger, result *mcpListenerHeaderDLPResult) {
	if logger == nil || result == nil {
		return
	}
	_, pattern := listenerHeaderBlockClassification(result)
	scannerName := scanner.AuditMCPHeaderInspection
	detail := audit.BlockDetail{Class: audit.BlockClassInfrastructureError}
	switch {
	case len(result.matches) > 0:
		scannerName = scanner.AuditMCPHeaderDLP
		detail.Class = audit.BlockClassThreat
	case result.reason == blockreason.PromptInjection:
		scannerName = scanner.AuditMCPHeaderInjection
		detail.Class = audit.BlockClassThreat
	case result.reason == blockreason.ParseError:
		// The decoded header could not be scanned; it is not evidence of
		// an attack pattern or a malformed client header.
		scannerName = scanner.AuditMCPHeaderInspection
		pattern = "response scan parse error in MCP parameter header"
		detail.Class = audit.BlockClassInfrastructureError
	}
	logger.LogBlockedDetail(mustMCPAuditContext(logger, "MCP", "mcp_listener_header"), scannerName, pattern, detail)
}

// logMCPResponseInspectionBlock classifies a failed response inspection as
// operational. detail and response bytes must never enter the event.
func logMCPResponseInspectionBlock(logger *audit.Logger, reason string) {
	logMCPOperationalBlock(logger, scanner.AuditMCPResponseInspection, "mcp_response", reason)
}

func logMCPOperationalBlock(logger *audit.Logger, label, resource, reason string) {
	if logger == nil {
		return
	}
	logger.LogBlockedDetail(mustMCPAuditContext(logger, "MCP", resource), label, reason,
		audit.BlockDetail{Class: audit.BlockClassInfrastructureError})
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
