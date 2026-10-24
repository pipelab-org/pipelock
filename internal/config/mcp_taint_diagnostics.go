// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

// MCPTaintRecoveryGuidance describes only remedies the MCP runtime can use.
const MCPTaintRecoveryGuidance = "MCP stdio uses stdin for JSON-RPC: inline terminal approval is unavailable and ask fails closed. Every MCP session (stdio, HTTP/WS bridges, and listener principal, token and legacy partitions) is invocation-scoped, so admin task boundaries and runtime trust grants are rejected for all of them. The only configured override for existing hostile history is an action-scoped taint.trust_overrides entry without source_match (MCP sources record no origin URL), optionally expiring. pipelock run applies it on reload; standalone pipelock mcp proxy reads taint config only at startup, and the restart that applies an override also discards that invocation's in-memory history. Source trust affects only future clean observations; it does not clear hostile history. Inline approval cannot override a hostile block."

// MCPTaintDiagnostics describes configuration prerequisites, not live coverage.
// Recorder allocation is owned by the MCP entry points; listener identity and
// recorder admission must also succeed before history can protect later calls.
func (c *Config) MCPTaintDiagnostics() []Warning {
	if c == nil {
		return nil
	}
	recorder := "taint is disabled; cross-request taint protection is inactive"
	if c.Taint.Enabled {
		recorder = "taint is enabled but session_profiling.enabled=false: no session taint recorder exists for MCP stdio/HTTP/WS bridges, the MCP listener, or the HTTP proxy; enable session_profiling and restart"
		if c.SessionProfiling.Enabled {
			recorder = "standalone MCP stdio subprocess and stdio-to-HTTP/WS upstream: session_profiling.enabled=true provisions an invocation-scoped recorder; live allocation and RiskState support must be verified"
		}
	}
	listener := "HTTP listener: authenticated principal state and anonymous legacy Mcp-Session-Id state can retain taint only with an admitted taint recorder; legacy headers are compatibility partitions, not verified caller identity"
	if c.MCPSessionBinding.ListenerRequireStateToken != nil && *c.MCPSessionBinding.ListenerRequireStateToken {
		listener += "; listener_require_state_token requires verified caller identity for current-protocol calls (legacy callers may use a Pipelock-issued token)"
	}
	return []Warning{
		{Field: "taint.mcp_recorder", Message: recorder + "; config-only assessment, not proof of a running recorder"},
		{Field: "taint.mcp_listener", Message: listener + "; anonymous 2026-07-28 stateless calls are request-local only: cross-request taint protection is NOT active; use verified caller identity and an admitted cross-request recorder, not a session header on the current protocol; a shared listener bearer shares one principal"},
		{Field: "taint.mcp_origin", Message: "stdio subprocess content origin is undeclared: clean responses default to internal_generated, which is not verified provenance; the embedding TaintExternalSource option declares external content, but mcp proxy has no corresponding CLI flag; HTTP/WS upstreams declare external content unless taint.trusted_mcp_servers trusts the resolved server; that trust affects future clean observations only, and prompt hits can still raise hostile taint"},
		{Field: "taint.mcp_recovery", Message: MCPTaintRecoveryGuidance},
	}
}
