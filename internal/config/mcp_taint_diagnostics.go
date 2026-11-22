// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

// MCPTaintRecoveryGuidance describes only remedies the MCP runtime can use.
const MCPTaintRecoveryGuidance = "MCP stdio uses stdin for JSON-RPC: inline terminal approval is unavailable and ask fails closed. Every MCP session (stdio, HTTP/WS bridges, and listener principal, token and legacy partitions) is invocation-scoped, so admin task boundaries and runtime trust grants are rejected for all of them. A verified invocation can receive an exact task permission on the operator task route; that permission lasts until expiry or process exit because task rotation stays rejected. An action-scoped taint.trust_overrides entry without source_match (MCP sources record no origin URL) does not satisfy the task check. pipelock run applies it on reload; standalone pipelock mcp proxy reads taint config only at startup, and the restart that applies an override also discards that invocation's in-memory history. Source trust classifies future observations, including wording-only findings. Existing hostile history remains in effect. Inline approval cannot override a hostile block."

// MCPTaintDiagnostics describes configuration prerequisites, not live coverage.
// Recorder allocation is owned by the runtime entry points. Listener identity and
// recorder admission must also succeed before history can protect later calls.
func (c *Config) MCPTaintDiagnostics() []Warning {
	if c == nil {
		return nil
	}
	recorder := "taint is disabled; cross-request taint protection is inactive"
	if c.Taint.Enabled {
		recorder = "taint is enabled. Standalone MCP stdio and HTTP/WS bridges, including --sandbox, configure an invocation-scoped recorder. At startup, the pipelock run HTTP proxy and its MCP listener share a session store. Anomaly detection, adaptive enforcement, airlock, behavioral baselines, and the session admin API still require session profiling"
	}
	listener := "HTTP listener: authenticated principal state and anonymous legacy Mcp-Session-Id state can retain taint only with an admitted taint recorder; legacy headers are compatibility partitions, not verified caller identity"
	if c.MCPSessionBinding.ListenerRequireStateToken != nil && *c.MCPSessionBinding.ListenerRequireStateToken {
		listener += "; listener_require_state_token requires verified caller identity for current-protocol calls (legacy callers may use a Pipelock-issued token)"
	}
	return []Warning{
		{Field: "taint.mcp_recorder", Message: recorder + "; config-only assessment, not proof of a running recorder"},
		{Field: "taint.mcp_listener", Message: listener + "; anonymous 2026-07-28 stateless calls are request-local only: cross-request taint protection is NOT active; use verified caller identity and an admitted cross-request recorder, not a session header on the current protocol; a shared listener bearer shares one principal"},
		{Field: "taint.mcp_origin", Message: "stdio subprocess content origin is undeclared: responses default to internal_generated, which is not verified provenance; the embedding TaintExternalSource option declares external content, but mcp proxy has no corresponding CLI flag; HTTP/WS upstreams declare external content unless taint.trusted_mcp_servers trusts the resolved server; source classification applies to wording-only findings too. Also, " + c.mcpPromptHitTaintNote()},
		{Field: "taint.mcp_recovery", Message: MCPTaintRecoveryGuidance},
		{Field: "taint.mcp_finding_kinds", Message: "Session history records finding_kinds independently of source trust. Wording alone is a warning and does not make the session hostile. Independent findings such as DLP and tool poisoning still make the session hostile when recorded. Legacy or aggregate evidence reports cause not recorded (older state or aggregate finding). This config-only check has no live session history."},
	}
}

// mcpPromptHitTaintNote describes wording detection under the configured mode.
func (c *Config) mcpPromptHitTaintNote() string {
	switch c.PromptInjectionMode() {
	case ActionAllow:
		return "prompt_injection_detection is off, so wording matches raise no hostile taint"
	case ActionWarn:
		return "prompt_injection_detection is warn-only, so wording matches are logged but raise no hostile taint"
	default:
		return "wording alone does not make the session hostile; response delivery follows the configured scan action"
	}
}
