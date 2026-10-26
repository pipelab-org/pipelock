// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	mcpResourceInput    = "mcp_input"
	mcpResourceResponse = "mcp_response"
	mcpResourceListener = "mcp_listener"
	mcpResourceStartup  = "mcp_startup"
)

type mcpDenialKind string

// mcpDenialSpec is the MCP applicability catalog. Labels come from scanner's
// published audit vocabulary; classes come from audit.BlockClass*. Empty reason
// entries accept only typed pattern projections in audit.go, never diagnostics.
type mcpDenialSpec struct {
	kind     mcpDenialKind
	label    string
	class    string
	resource string
	reason   string
}

var mcpDenialCatalog = [...]mcpDenialSpec{
	{"unclassified", scanner.AuditScannerUnavailable, audit.BlockClassInfrastructureError, mcpResourceInput, "MCP denial classification unavailable"},
	{"startup_contract", scanner.AuditContract, audit.BlockClassProtective, mcpResourceStartup, "MCP upstream URL blocked by live-lock contract"},
	{"startup_contract_eval", scanner.AuditContract, audit.BlockClassInfrastructureError, mcpResourceStartup, "MCP contract upstream evaluation failed"},
	{"startup_capacity", scanner.AuditMCPProtocol, audit.BlockClassProtective, mcpResourceStartup, session.ErrCapacity.Error()},
	{"startup_metadata", scanner.ScannerSSRFMetadata, audit.BlockClassThreat, mcpResourceStartup, "MCP upstream resolves to a cloud metadata endpoint"},

	{"input_dlp", scanner.AuditMCPInputDLP, audit.BlockClassThreat, mcpResourceInput, ""},
	{"input_injection", scanner.AuditMCPInputInjection, audit.BlockClassThreat, mcpResourceInput, ""},
	{"input_inspection", scanner.AuditMCPInputInspection, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"address", scanner.AuditAddressProtection, audit.BlockClassThreat, mcpResourceInput, "address protection blocked"},
	{"policy", scanner.AuditMCPToolPolicy, audit.BlockClassProtective, mcpResourceInput, "MCP tool policy blocked"},
	{"binding", scanner.AuditMCPSessionBinding, audit.BlockClassProtective, mcpResourceInput, "MCP session binding blocked"},
	{"chain", scanner.AuditChainDetection, audit.BlockClassThreat, mcpResourceInput, ""},
	{"baseline", scanner.AuditSessionAnomaly, audit.BlockClassThreat, mcpResourceInput, "baseline_deviation"},
	{"adaptive", scanner.AuditAdaptiveEnforcement, audit.BlockClassProtective, mcpResourceInput, "MCP input action upgraded to block"},
	{"adaptive_clean", scanner.AuditAdaptiveEnforcement, audit.BlockClassProtective, mcpResourceInput, "MCP clean input action upgraded to block"},
	{"header_dlp", scanner.AuditMCPHeaderDLP, audit.BlockClassThreat, "mcp_listener_header", ""},
	{"header_injection", scanner.AuditMCPHeaderInjection, audit.BlockClassThreat, "mcp_listener_header", ""},
	{"header_inspection", scanner.AuditMCPHeaderInspection, audit.BlockClassInfrastructureError, "mcp_listener_header", ""},
	{"response_inspection", scanner.AuditMCPResponseInspection, audit.BlockClassInfrastructureError, mcpResourceResponse, ""},
	{"response_content", scanner.AuditResponseScan, audit.BlockClassThreat, "server_response", ""},
	{"reply_content", scanner.AuditResponseScan, audit.BlockClassThreat, "upstream_error_reply", ""},
	{"reply_inspection", scanner.AuditResponseScan, audit.BlockClassInfrastructureError, "upstream_error_reply", ""},
	{"a2a_content", scanner.AuditA2AScan, audit.BlockClassThreat, mcpResourceInput, "A2A input content finding"},
	{"a2a_inspection", scanner.AuditA2AScan, audit.BlockClassInfrastructureError, mcpResourceInput, "A2A input could not be inspected"},
	{"a2a_config", scanner.AuditA2AScan, audit.BlockClassConfigMismatch, mcpResourceInput, "A2A input configuration mismatch"},
	{"a2a_limit", scanner.AuditA2AScan, audit.BlockClassProtective, mcpResourceInput, "A2A input inspection budget exceeded"},
	{"a2a_url_infrastructure", scanner.AuditA2AScan, audit.BlockClassInfrastructureError, mcpResourceInput, "A2A input URL check refused"},
	{"a2a_url_protective", scanner.AuditA2AScan, audit.BlockClassProtective, mcpResourceInput, "A2A input URL check refused"},
	{"batch", scanner.AuditMCPProtocol, audit.BlockClassProtective, mcpResourceInput, "MCP batch requests are unsupported"},
	{"redaction_error", scanner.AuditRedaction, audit.BlockClassInfrastructureError, mcpResourceInput, "MCP redaction blocked the request"},
	{"redaction_limit", scanner.AuditRedaction, audit.BlockClassProtective, mcpResourceInput, "MCP redaction blocked the request"},
	{"contract_eval", scanner.AuditContract, audit.BlockClassInfrastructureError, mcpResourceInput, "MCP contract evaluation failed"},
	{"contract_deny", scanner.AuditContract, audit.BlockClassProtective, mcpResourceInput, "MCP live-lock contract blocked the request"},
	{"envelope", scanner.AuditMediationEnvelope, audit.BlockClassInfrastructureError, mcpResourceInput, "MCP mediation envelope injection failed"},
	{"redirect_batch", scanner.AuditMCPRedirect, audit.BlockClassProtective, mcpResourceInput, "MCP batch redirect is unsupported"},
	{"redirect_profile", scanner.AuditMCPRedirect, audit.BlockClassConfigMismatch, mcpResourceInput, "MCP redirect profile is unavailable"},
	{"redirect_handler", scanner.AuditMCPRedirect, audit.BlockClassInfrastructureError, mcpResourceInput, "MCP redirect handler failed"},
	{"redirect_dlp", scanner.AuditMCPRedirectOutputDLP, audit.BlockClassThreat, "mcp_redirect_output", "MCP redirect output DLP finding"},
	{"redirect_injection", scanner.AuditMCPRedirectOutputInjection, audit.BlockClassThreat, "mcp_redirect_output", "MCP redirect output injection finding"},
	{"defer_unsupported", scanner.AuditMCPDefer, audit.BlockClassConfigMismatch, mcpResourceInput, "MCP defer is unsupported on this transport"},
	{"defer_disabled", scanner.AuditMCPDefer, audit.BlockClassConfigMismatch, mcpResourceInput, "MCP defer is disabled"},
	{"defer_hold", scanner.AuditMCPDefer, audit.BlockClassProtective, mcpResourceInput, "MCP deferred hold failed"},
	{"defer_terminal", scanner.AuditMCPDefer, audit.BlockClassProtective, mcpResourceInput, "MCP deferred action denied"},
	{"airlock", scanner.AuditAirlock, audit.BlockClassProtective, mcpResourceInput, "MCP session airlock refused the request"},
	{"taint", scanner.AuditTaintPolicy, audit.BlockClassProtective, mcpResourceInput, "MCP taint policy blocked the request"},
	{"authority", scanner.AuditRequestPolicy, audit.BlockClassProtective, mcpResourceInput, "MCP action authority denied the request"},
	{"frozen", scanner.AuditFrozenTool, audit.BlockClassProtective, mcpResourceInput, "tool not in frozen inventory"},
	{"dow", scanner.ScannerDenialOfWallet, audit.BlockClassProtective, mcpResourceInput, ""},
	// Preserve the released label and its content-redaction mode.
	{"tool_finding", scanner.AuditToolScanning, audit.BlockClassThreat, "tools/list", ""},
	{"tool_capacity", scanner.AuditToolScanning, audit.BlockClassInfrastructureError, "tools/list", "tools/list cannot be safely inspected: tool_inventory_capacity"},
	{"tool_inspection", scanner.AuditToolScanning, audit.BlockClassInfrastructureError, "tools/list", ""},
	{"provenance", scanner.AuditProvenance, audit.BlockClassThreat, "tools/list", "MCP tool provenance verification failed"},
	{"media_finding", scanner.AuditMediaPolicy, audit.BlockClassThreat, "server_response", "MCP response media policy refused content"},
	{"media_inspection", scanner.AuditMediaPolicy, audit.BlockClassInfrastructureError, "server_response", "MCP response media could not be inspected"},
	{"cee_entropy", scanner.AuditCrossRequestEntropy, audit.BlockClassProtective, "mcp-input", "cross-request entropy budget exceeded"},
	{"cee_fragment", scanner.AuditCrossRequestFragment, audit.BlockClassThreat, "mcp-input", ""},
	{"cee_fragment_limit", scanner.AuditCrossRequestFragment, audit.BlockClassProtective, "mcp-input", "cross-request fragment inspection limit exceeded"},
	{"cee_owner", scanner.AuditCrossRequestFragmentOwnerMismatch, audit.BlockClassProtective, "mcp-input", "cross-request fragment stream belongs to another identity; request cannot be safely inspected"},
	{"cee_capacity", scanner.AuditCrossRequestFragmentCapacity, audit.BlockClassInfrastructureError, "mcp-input", "cross-request fragment session capacity exhausted; request cannot be safely inspected; increase cross_request_detection.fragment_reassembly.max_sessions or reduce active sessions"},
	{"kill_mcp_input", scanner.AuditKillSwitch, audit.BlockClassProtective, mcpResourceInput, "MCP kill switch active"},
	{"receipt_mcp_input", scanner.AuditReceiptEmission, audit.BlockClassInfrastructureError, mcpResourceInput, "MCP receipt emission failed"},
	{"identity_mcp_input", scanner.AuditAgentIdentity, audit.BlockClassProtective, mcpResourceInput, "MCP server identity is no longer authorized"},
	{"scanner_mcp_input", scanner.AuditScannerUnavailable, audit.BlockClassInfrastructureError, mcpResourceInput, "MCP scanner unavailable"},
	{"kill_mcp_response", scanner.AuditKillSwitch, audit.BlockClassProtective, mcpResourceResponse, "MCP kill switch active"},
	{"receipt_mcp_response", scanner.AuditReceiptEmission, audit.BlockClassInfrastructureError, mcpResourceResponse, "MCP receipt emission failed"},
	{"identity_mcp_response", scanner.AuditAgentIdentity, audit.BlockClassProtective, mcpResourceResponse, "MCP server identity is no longer authorized"},
	{"scanner_mcp_response", scanner.AuditScannerUnavailable, audit.BlockClassInfrastructureError, mcpResourceResponse, "MCP scanner unavailable"},
	{"kill_mcp_listener", scanner.AuditKillSwitch, audit.BlockClassProtective, mcpResourceListener, "MCP kill switch active"},
	{"receipt_mcp_listener", scanner.AuditReceiptEmission, audit.BlockClassInfrastructureError, mcpResourceListener, "MCP receipt emission failed"},
	{"identity_mcp_listener", scanner.AuditAgentIdentity, audit.BlockClassProtective, mcpResourceListener, "MCP server identity is no longer authorized"},
	{"scanner_mcp_listener", scanner.AuditScannerUnavailable, audit.BlockClassInfrastructureError, mcpResourceListener, "MCP scanner unavailable"},
	{"kill_mcp_startup", scanner.AuditKillSwitch, audit.BlockClassProtective, mcpResourceStartup, "MCP kill switch active"},
	{"receipt_mcp_startup", scanner.AuditReceiptEmission, audit.BlockClassInfrastructureError, mcpResourceStartup, "MCP receipt emission failed"},
	{"identity_mcp_startup", scanner.AuditAgentIdentity, audit.BlockClassProtective, mcpResourceStartup, "MCP server identity is no longer authorized"},
	{"scanner_mcp_startup", scanner.AuditScannerUnavailable, audit.BlockClassInfrastructureError, mcpResourceStartup, "MCP scanner unavailable"},
	{"listener_admission", scanner.AuditMCPProtocol, audit.BlockClassProtective, mcpResourceListener, "MCP listener admission refused"},
	{"listener_protocol", scanner.AuditMCPProtocol, audit.BlockClassProtective, mcpResourceListener, "MCP listener protocol refused"},
	{"listener_capacity", scanner.AuditMCPProtocol, audit.BlockClassProtective, mcpResourceListener, "MCP listener state capacity exhausted"},
	{"listener_inspection", scanner.AuditMCPResponseInspection, audit.BlockClassInfrastructureError, mcpResourceListener, "MCP upstream reply withheld"},
	{"listener_metadata", scanner.ScannerSSRFMetadata, audit.BlockClassThreat, mcpResourceListener, "MCP upstream resolves to a cloud metadata endpoint"},
	{"listener_contract", scanner.AuditContract, audit.BlockClassProtective, mcpResourceListener, "MCP upstream URL blocked by live-lock contract"},
	{"listener_contract_eval", scanner.AuditContract, audit.BlockClassInfrastructureError, mcpResourceListener, "MCP contract upstream evaluation failed"},
	{"listener_a2a", scanner.AuditA2AScan, audit.BlockClassProtective, mcpResourceListener, "MCP listener A2A headers refused"},
	{"url_parser_threat", scanner.ScannerParser, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_parser_protective", scanner.ScannerParser, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_parser_infrastructure", scanner.ScannerParser, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_parser_config", scanner.ScannerParser, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_scheme_threat", scanner.ScannerScheme, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_scheme_protective", scanner.ScannerScheme, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_scheme_infrastructure", scanner.ScannerScheme, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_scheme_config", scanner.ScannerScheme, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_length_threat", scanner.ScannerLength, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_length_protective", scanner.ScannerLength, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_length_infrastructure", scanner.ScannerLength, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_length_config", scanner.ScannerLength, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_ssrf_threat", scanner.ScannerSSRF, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_ssrf_protective", scanner.ScannerSSRF, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_ssrf_infrastructure", scanner.ScannerSSRF, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_ssrf_config", scanner.ScannerSSRF, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_ssrf_metadata_threat", scanner.ScannerSSRFMetadata, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_ssrf_metadata_protective", scanner.ScannerSSRFMetadata, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_ssrf_metadata_infrastructure", scanner.ScannerSSRFMetadata, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_ssrf_metadata_config", scanner.ScannerSSRFMetadata, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_core_ssrf_threat", scanner.ScannerCoreSSRF, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_core_ssrf_protective", scanner.ScannerCoreSSRF, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_core_ssrf_infrastructure", scanner.ScannerCoreSSRF, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_core_ssrf_config", scanner.ScannerCoreSSRF, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_allowlist_threat", scanner.ScannerAllowlist, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_allowlist_protective", scanner.ScannerAllowlist, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_allowlist_infrastructure", scanner.ScannerAllowlist, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_allowlist_config", scanner.ScannerAllowlist, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_blocklist_threat", scanner.ScannerBlocklist, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_blocklist_protective", scanner.ScannerBlocklist, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_blocklist_infrastructure", scanner.ScannerBlocklist, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_blocklist_config", scanner.ScannerBlocklist, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_ratelimit_threat", scanner.ScannerRateLimit, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_ratelimit_protective", scanner.ScannerRateLimit, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_ratelimit_infrastructure", scanner.ScannerRateLimit, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_ratelimit_config", scanner.ScannerRateLimit, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_dlp_threat", scanner.ScannerDLP, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_dlp_protective", scanner.ScannerDLP, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_dlp_infrastructure", scanner.ScannerDLP, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_dlp_config", scanner.ScannerDLP, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_entropy_threat", scanner.ScannerEntropy, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_entropy_protective", scanner.ScannerEntropy, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_entropy_infrastructure", scanner.ScannerEntropy, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_entropy_config", scanner.ScannerEntropy, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_subdomain_entropy_threat", scanner.ScannerSubdomainEntropy, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_subdomain_entropy_protective", scanner.ScannerSubdomainEntropy, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_subdomain_entropy_infrastructure", scanner.ScannerSubdomainEntropy, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_subdomain_entropy_config", scanner.ScannerSubdomainEntropy, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_databudget_threat", scanner.ScannerDataBudget, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_databudget_protective", scanner.ScannerDataBudget, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_databudget_infrastructure", scanner.ScannerDataBudget, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_databudget_config", scanner.ScannerDataBudget, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_path_traversal_threat", scanner.ScannerPathTraversal, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_path_traversal_protective", scanner.ScannerPathTraversal, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_path_traversal_infrastructure", scanner.ScannerPathTraversal, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_path_traversal_config", scanner.ScannerPathTraversal, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_crlf_injection_threat", scanner.ScannerCRLF, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_crlf_injection_protective", scanner.ScannerCRLF, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_crlf_injection_infrastructure", scanner.ScannerCRLF, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_crlf_injection_config", scanner.ScannerCRLF, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_context_threat", scanner.ScannerContext, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_context_protective", scanner.ScannerContext, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_context_infrastructure", scanner.ScannerContext, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_context_config", scanner.ScannerContext, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"url_core_dlp_threat", scanner.ScannerCoreDLP, audit.BlockClassThreat, mcpResourceInput, ""},
	{"url_core_dlp_protective", scanner.ScannerCoreDLP, audit.BlockClassProtective, mcpResourceInput, ""},
	{"url_core_dlp_infrastructure", scanner.ScannerCoreDLP, audit.BlockClassInfrastructureError, mcpResourceInput, ""},
	{"url_core_dlp_config", scanner.ScannerCoreDLP, audit.BlockClassConfigMismatch, mcpResourceInput, ""},
	{"adaptive_response", scanner.AuditAdaptiveEnforcement, audit.BlockClassProtective, mcpResourceResponse, "MCP session escalation blocks responses"},
	{"batch_response", scanner.AuditMCPProtocol, audit.BlockClassProtective, mcpResourceResponse, "MCP batch responses are unsupported"},
	{"correlation_response", scanner.AuditMCPResponseInspection, audit.BlockClassProtective, mcpResourceResponse, "MCP response correlation refused"},
	{"media_policy", scanner.AuditMediaPolicy, audit.BlockClassProtective, "server_response", "MCP response media policy refused content"},
}

// MCPDenialLabels returns the registered label vocabulary for documentation
// checks. The returned slice is a copy and cannot mutate the runtime catalog.
func MCPDenialLabels() []string {
	seen := make(map[string]bool)
	var labels []string
	for _, spec := range mcpDenialCatalog {
		if !seen[spec.label] {
			labels = append(labels, spec.label)
			seen[spec.label] = true
		}
	}
	return labels
}

func denialSpec(kind mcpDenialKind) (mcpDenialSpec, bool) {
	for _, spec := range mcpDenialCatalog {
		if spec.kind == kind {
			return spec, true
		}
	}
	return mcpDenialCatalog[0], false
}
