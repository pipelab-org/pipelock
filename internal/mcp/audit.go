// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	dowSubjectKeyDefault             = "_default"
	dowSubjectTrustDefault           = "default"
	dowAuditFallbackTarget           = "invalid-mcp-resource"
	mcpReceiptEmissionReason         = "MCP receipt emission failed"
	mcpKillSwitchReason              = "MCP kill switch active"
	mcpBatchReason                   = "MCP batch requests are unsupported"
	mcpRedactionReason               = "MCP redaction blocked the request"
	mcpA2ABudgetReason               = "A2A input inspection budget exceeded"
	mcpA2AURLReason                  = "A2A input URL check refused"
	mcpA2AContentReason              = "A2A input content finding"
	mcpA2AInspectionReason           = "A2A input could not be inspected"
	mcpA2AConfigReason               = "A2A input configuration mismatch"
	mcpContractEvalReason            = "MCP contract evaluation failed"
	mcpContractDenyAuditReason       = "MCP live-lock contract blocked the request"
	mcpEnvelopeReason                = "MCP mediation envelope injection failed"
	mcpRedirectBatchReason           = "MCP batch redirect is unsupported"
	mcpRedirectProfileReason         = "MCP redirect profile is unavailable"
	mcpRedirectHandlerReason         = "MCP redirect handler failed"
	mcpDeferUnsupportedReason        = "MCP defer is unsupported on this transport"
	mcpDeferDisabledReason           = "MCP defer is disabled"
	mcpRedirectOutputDLPReason       = "MCP redirect output DLP finding"
	mcpRedirectOutputInjectionReason = "MCP redirect output injection finding"
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

// mcpAuditDescriptor resolves only registered MCP label/class/resource variants.
// Diagnostic errors and client-controlled resource names never enter the catalog.
func mcpAuditDescriptor(label, resource, reason, class string) mcpDenialAudit {
	if class == "" {
		class = audit.BlockClassThreat
	}
	for _, spec := range mcpDenialCatalog {
		if spec.label == label && spec.resource == resource && spec.class == class && (spec.reason == "" || spec.reason == reason) {
			return mcpDenialAudit{kind: spec.kind, pattern: reason}
		}
	}
	return mcpDenialAudit{}
}

func mcpInputBlockAudit(verdict InputVerdict) mcpDenialAudit {
	label := scanner.AuditMCPInputInspection
	reason := string(mcpScannerBlockReason(verdict, policy.Verdict{}, false))
	class := audit.BlockClassInfrastructureError
	switch {
	case verdict.Error != "":
	case len(verdict.Matches) > 0:
		label, reason, class = scanner.AuditMCPInputDLP, verdict.Matches[0].PatternName, audit.BlockClassThreat
	case len(verdict.Inject) > 0:
		label, reason, class = scanner.AuditMCPInputInjection, verdict.Inject[0].PatternName, audit.BlockClassThreat
	case len(verdict.URLFindings) > 0:
		finding := verdict.URLFindings[0]
		label, class = finding.Scanner, audit.BlockClassThreat
		switch finding.Class {
		case scanner.ClassProtective:
			class = audit.BlockClassProtective
		case scanner.ClassInfrastructureError:
			class = audit.BlockClassInfrastructureError
		case scanner.ClassConfigMismatch:
			class = audit.BlockClassConfigMismatch
		}
	case len(verdict.AddressFindings) > 0:
		label, reason, class = scanner.AuditAddressProtection, "address protection blocked", audit.BlockClassThreat
	}
	return mcpAuditDescriptor(label, "mcp_input", reason, class)
}

func mcpInputDecisionBlockAudit(verdict InputVerdict, contentBlock bool, policyVerdict policy.Verdict, bindingAction, chainAction, chainPattern, baselineAction string) mcpDenialAudit {
	if contentBlock {
		return mcpInputBlockAudit(verdict)
	}
	enforces := func(action string) bool { return action == config.ActionBlock || action == config.ActionAsk }
	switch {
	case policyVerdict.Matched && enforces(policyVerdict.Action):
		return mcpDenialAudit{kind: "policy"}
	case enforces(bindingAction):
		return mcpDenialAudit{kind: "binding"}
	case enforces(chainAction):
		return mcpChainBlockAudit(chainPattern)
	case enforces(baselineAction):
		return mcpBaselineBlockAudit()
	default:
		return mcpDenialAudit{kind: "adaptive"}
	}
}

func mcpChainBlockAudit(pattern string) mcpDenialAudit {
	return mcpDenialAudit{kind: "chain", pattern: pattern}
}
func mcpBaselineBlockAudit() mcpDenialAudit      { return mcpDenialAudit{kind: "baseline"} }
func mcpCleanAdaptiveBlockAudit() mcpDenialAudit { return mcpDenialAudit{kind: "adaptive_clean"} }

func inputBlockedByContent(verdict InputVerdict, contentAction string) bool {
	return !verdict.Clean && inputVerdictEffectiveAction(verdict, contentAction) == config.ActionBlock
}

func mcpListenerHeaderBlockAudit(result *mcpListenerHeaderDLPResult) mcpDenialAudit {
	if result == nil {
		return mcpDenialAudit{}
	}
	_, pattern := listenerHeaderBlockClassification(result)
	label, class := scanner.AuditMCPHeaderInspection, audit.BlockClassInfrastructureError
	switch {
	case len(result.matches) > 0:
		label, class = scanner.AuditMCPHeaderDLP, audit.BlockClassThreat
	case result.reason == blockreason.PromptInjection:
		label, class = scanner.AuditMCPHeaderInjection, audit.BlockClassThreat
	case result.reason == blockreason.ParseError:
		pattern = "response scan parse error in MCP parameter header"
	}
	return mcpAuditDescriptor(label, "mcp_listener_header", pattern, class)
}

func mcpResponseInspectionBlockAudit(reason string) mcpDenialAudit {
	return mcpDenialAudit{kind: "response_inspection", pattern: reason}
}

func mcpOperationalBlockAudit(label, resource, reason string) mcpDenialAudit {
	return mcpAuditDescriptor(label, resource, reason, audit.BlockClassInfrastructureError)
}

func mcpInputGateBlockAudit(label, reason, class string) mcpDenialAudit {
	return mcpAuditDescriptor(label, "mcp_input", reason, class)
}

func mcpRedirectOutputBlockAudit(label, reason string) mcpDenialAudit {
	return mcpAuditDescriptor(label, "mcp_redirect_output", reason, audit.BlockClassThreat)
}

func mcpRedactionBlockClass(err error) string {
	var blockErr *redact.BlockError
	if !errors.As(err, &blockErr) || blockErr.Reason == redact.ReasonInternalError || blockErr.Reason == redact.ReasonRemarshalFailed {
		return audit.BlockClassInfrastructureError
	}
	return audit.BlockClassProtective
}

func mcpA2AGateAudit(r A2AScanResult) (class, reason string) {
	switch {
	case r.ScanError != "" || r.InspectionIncomplete:
		return audit.BlockClassInfrastructureError, mcpA2AInspectionReason
	case r.IsConfigMismatch():
		return audit.BlockClassConfigMismatch, mcpA2AConfigReason
	case mcpA2AOperationalURLFindingsOnly(r):
		for _, f := range r.URLFindings {
			if f.Class == scanner.ClassInfrastructureError {
				return audit.BlockClassInfrastructureError, mcpA2AURLReason
			}
		}
		return audit.BlockClassProtective, mcpA2AURLReason
	case r.BudgetExceeded && len(r.DLPFindings) == 0 && len(r.InjectFindings) == 0 && len(r.URLFindings) == 0 && r.EntropyFinding == nil:
		return audit.BlockClassProtective, mcpA2ABudgetReason
	default:
		return audit.BlockClassThreat, mcpA2AContentReason
	}
}

func mcpA2AOperationalURLFindingsOnly(r A2AScanResult) bool {
	if len(r.URLFindings) == 0 || len(r.DLPFindings) > 0 || len(r.InjectFindings) > 0 || r.EntropyFinding != nil {
		return false
	}
	for _, f := range r.URLFindings {
		switch f.Class {
		case scanner.ClassInfrastructureError, scanner.ClassProtective, scanner.ClassConfigMismatch:
		default:
			return false
		}
	}
	return true
}

func mcpListenerReplyBlockAudit(finding string) mcpDenialAudit {
	class := audit.BlockClassThreat
	switch finding {
	case "response scanner unavailable", "uninspectable reply":
		finding, class = "response scan cannot be scanned: "+finding, audit.BlockClassInfrastructureError
	case "response scan finding":
		finding, class = "response scan returned an incomplete verdict", audit.BlockClassInfrastructureError
	}
	return mcpAuditDescriptor(scanner.AuditResponseScan, "upstream_error_reply", finding, class)
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

func mcpDoWDenialAudit(opts MCPProxyOpts, target, reason string) mcpDenialAudit {
	ctx := mustMCPDoWAuditContext(opts.AuditLogger, target, opts)
	return mcpDenialAudit{kind: "dow", pattern: reason, context: &ctx}
}

func mcpDeferredDenialAudit(res deferred.Resolution) mcpDenialAudit {
	if res.Reason == deferred.ReasonReceiptNotWritten {
		return mcpDenialAudit{kind: "receipt_mcp_input"}
	}
	switch res.ResolutionSource {
	case deferred.SourceKillSwitch:
		return mcpDenialAudit{kind: "kill_mcp_input"}
	case deferred.SourceAuthority:
		return mcpDenialAudit{kind: "authority"}
	default:
		return mcpDenialAudit{kind: "defer_terminal"}
	}
}

func mcpListenerBlockAudit(dec mcpListenerBlockDecision) mcpDenialAudit {
	switch dec.reason {
	case blockreason.KillSwitchActive:
		return mcpDenialAudit{kind: "kill_mcp_input"}
	case blockreason.ReceiptEmissionFailed:
		return mcpDenialAudit{kind: "receipt_mcp_input"}
	case blockreason.SSRFMetadata:
		return mcpDenialAudit{kind: "listener_metadata"}
	}
	switch dec.layer {
	case "session_capacity":
		switch dec.pattern {
		case errMCPListenerRegistryCapacity.Error():
			return mcpDenialAudit{kind: "listener_registry_capacity"}
		case session.ErrCapacity.Error():
			return mcpDenialAudit{kind: "listener_session_capacity"}
		default:
			return mcpDenialAudit{kind: "listener_capacity"}
		}
	case "mcp_listener_session":
		// One receipt layer covers three refusals; its fixed receipt pattern
		// names which one. Only the principal-state cap is a capacity refusal.
		switch dec.pattern {
		case "listener_principal_state_capacity":
			return mcpDenialAudit{kind: "listener_capacity"}
		case "legacy_listener_token_on_current_protocol":
			return mcpDenialAudit{kind: "listener_protocol"}
		default:
			return mcpDenialAudit{kind: "listener_admission"}
		}
	case mcpContractReceiptLayer:
		return mcpDenialAudit{kind: "listener_contract"}
	case mcpReceiptLayerA2A:
		return mcpDenialAudit{kind: "listener_a2a"}
	default:
		return mcpDenialAudit{kind: "listener_admission"}
	}
}

func mcpUpstreamGateDenialAudit(gate mcpContractGateOutput) mcpDenialAudit {
	if gate.upstreamDenial.kind != "" {
		return gate.upstreamDenial
	}
	if mcpContractBlockReason(gate) == blockreason.KillSwitchActive {
		return mcpDenialAudit{kind: "kill_mcp_input"}
	}
	return mcpDenialAudit{kind: "listener_contract"}
}

func mcpA2AHeaderDenialAudit(result A2AScanResult) mcpDenialAudit {
	class, reason := mcpA2AGateAudit(result)
	return mcpInputGateBlockAudit(scanner.AuditA2AScan, reason, class)
}

func mcpMediaDenialAudit(result mcpMediaPolicyResult) mcpDenialAudit { return result.denialAudit }

// The reason values are fixed outcomes of upstreamClientError.writeIfActive
// and the listener relay gates, never diagnostic error text.
func mcpListenerWithholdAudit(reason string) mcpDenialAudit {
	switch reason {
	case "kill switch blocks responses":
		return mcpDenialAudit{kind: "kill_mcp_response"}
	case "upstream identity changed":
		return mcpDenialAudit{kind: "identity_mcp_response"}
	case "session escalation blocks responses":
		return mcpDenialAudit{kind: "adaptive_response"}
	case "listener state revoked":
		// Same refusal as a revoked state on the JSON and SSE reply paths.
		return mcpListenerAdmissionDenialAudit()
	default:
		return mcpDenialAudit{kind: "listener_inspection"}
	}
}

func mcpAdaptiveResponseDenialAudit() mcpDenialAudit {
	return mcpDenialAudit{kind: "adaptive_response"}
}

func mcpAirlockDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "airlock"} }

func mcpAuthorityDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "authority"} }

func mcpBatchResponseDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "batch_response"} }

func mcpCeeCapacityDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "cee_capacity"} }

func mcpCeeEntropyDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "cee_entropy"} }

func mcpCeeFragmentLimitDenialAudit() mcpDenialAudit {
	return mcpDenialAudit{kind: "cee_fragment_limit"}
}

func mcpCeeOwnerDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "cee_owner"} }

func mcpCorrelationResponseDenialAudit() mcpDenialAudit {
	return mcpDenialAudit{kind: "correlation_response"}
}

func mcpDeferDisabledDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "defer_disabled"} }

func mcpDeferHoldDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "defer_hold"} }

// Preserve the released frozen-tool resource: it is the refused tool name,
// unlike content-bearing resources that the audit logger redacts.
func mcpFrozenDenialAudit(opts MCPProxyOpts, toolName string) mcpDenialAudit {
	ctx := mustMCPAuditContext(opts.AuditLogger, "MCP", firstNonEmpty(toolName, dowAuditFallbackTarget))
	return mcpDenialAudit{kind: "frozen", context: &ctx}
}

func mcpIdentityMcpResponseDenialAudit() mcpDenialAudit {
	return mcpDenialAudit{kind: "identity_mcp_response"}
}

func mcpKillMcpInputDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "kill_mcp_input"} }

func mcpKillMcpResponseDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "kill_mcp_response"} }

func mcpListenerAdmissionDenialAudit() mcpDenialAudit {
	return mcpDenialAudit{kind: "listener_admission"}
}

func mcpListenerCapacityDenialAudit() mcpDenialAudit {
	return mcpDenialAudit{kind: "listener_capacity"}
}

func mcpListenerContractEvalDenialAudit() mcpDenialAudit {
	return mcpDenialAudit{kind: "listener_contract_eval"}
}

func mcpListenerInspectionDenialAudit() mcpDenialAudit {
	return mcpDenialAudit{kind: "listener_inspection"}
}

func mcpListenerProtocolDenialAudit() mcpDenialAudit {
	return mcpDenialAudit{kind: "listener_protocol"}
}

func mcpMediaInspectionDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "media_inspection"} }

func mcpMediaPolicyDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "media_policy"} }

func mcpProvenanceDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "provenance"} }

func mcpReceiptMcpInputDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "receipt_mcp_input"} }

func mcpTaintDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "taint"} }

func mcpToolCapacityDenialAudit() mcpDenialAudit { return mcpDenialAudit{kind: "tool_capacity"} }

func mcpResponseContentDenialAudit(pattern string) mcpDenialAudit {
	return mcpDenialAudit{kind: "response_content", pattern: firstNonEmpty(pattern, "response scanning blocked")}
}

func mcpToolResultDenialAudit(resourceLimit, reason string) mcpDenialAudit {
	if resourceLimit != "" {
		return mcpDenialAudit{kind: "tool_inspection", pattern: reason}
	}
	return mcpDenialAudit{kind: "tool_finding", pattern: reason}
}

func mcpCEEFragmentDenialAudit(pattern string) mcpDenialAudit {
	return mcpDenialAudit{kind: "cee_fragment", pattern: pattern}
}

func mcpStartupDenialAudit(descriptor mcpDenialAudit) mcpDenialAudit {
	switch descriptor.kind {
	case "listener_contract":
		return mcpDenialAudit{kind: "startup_contract"}
	case "listener_contract_eval":
		return mcpDenialAudit{kind: "startup_contract_eval"}
	case "listener_capacity":
		return mcpDenialAudit{kind: "startup_capacity"}
	case "listener_metadata":
		return mcpDenialAudit{kind: "startup_metadata"}
	case "kill_mcp_input":
		return mcpDenialAudit{kind: "kill_mcp_startup"}
	default:
		return descriptor
	}
}
