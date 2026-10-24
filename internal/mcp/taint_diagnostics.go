// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// reportMCPTaint reports the recorder actually allocated by the entry point,
// rather than inferring protection from configuration or Store != nil.
// The binding vocabulary describes the existing state registry, not identity
// obtained from an untrusted header. No caller identifiers enter this output.
func reportMCPTaint(w io.Writer, opts MCPProxyOpts, rec session.Recorder, binding string) {
	status := "inactive"
	policy := "unspecified"
	cfg := opts.taintCfg()
	if cfg != nil {
		policy = cfg.Policy
	}
	_, recordsRisk := rec.(session.RiskState)
	if cfg == nil || !cfg.Enabled {
		status = "disabled"
	} else if recordsRisk && binding != "listener_stateless" {
		status = "active"
	}
	opts.Metrics.RecordMCPTaintContext(binding, status)
	if w == nil {
		return
	}
	_, _ = fmt.Fprintf(w, "pipelock: MCP taint binding=%s recorder_risk_state=%t cross_request_recording=%s taint_policy=%s (in-memory scope; not restart persistence or proof of enforcement)\n", binding, recordsRisk, status, policy)
	if binding == "listener_stateless" {
		_, _ = fmt.Fprintln(w, "pipelock: anonymous stateless MCP caller: request-local only; cross-request taint protection is NOT active; use verified caller identity and an admitted persistent taint recorder")
	} else if !recordsRisk && cfg != nil && cfg.Enabled {
		_, _ = fmt.Fprintln(w, "pipelock: no taint recorder is active; standalone MCP needs session_profiling.enabled and successful recorder admission")
	}
	origin := "undeclared (clean responses default to internal_generated; not verified provenance)"
	if opts.TaintExternalSource {
		origin = "external_untrusted"
		if !opts.mcpResponseTaintExternal() {
			origin = "operator-trusted (future clean responses only; prompt hits can still raise hostile taint)"
		}
	}
	action := opts.responseActionOverride()
	if action == "" {
		if sc := opts.scanner(); sc != nil {
			action = sc.ResponseAction()
		}
	}
	if action == "" {
		action = "unspecified"
	}
	approval := opts.Approver != nil && opts.Approver.IsTerminal()
	effective := action
	if action == config.ActionAsk && !approval {
		effective = config.ActionBlock
	}
	_, _ = fmt.Fprintf(w, "pipelock: MCP taint origin=%s response_action=%s effective_response_action=%s terminal_approval=%t (finding-specific core/DLP rules still apply)\n", origin, action, effective, approval)
}

func mcpTaintRefusalMessage(decision taintDecision) string {
	return "pipelock: " + decision.Result.Reason + "; taint recovery: an operator may accept risk with scoped taint.trust_overrides (action/source, optional expiry); source_match requires a recorded origin URL and cannot match URL-less MCP sources. Runtime task boundaries/grants apply only to mutable identity sessions; admin invocation grants are rejected. Source trust changes only future clean observations; it does not clear hostile history. Inline approval cannot override a hostile block; ask fails closed without a terminal."
}
