// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"io"
	"strings"

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
		_, _ = fmt.Fprintln(w, "pipelock: anonymous stateless MCP caller: request-local only; cross-request taint protection is NOT active; use verified caller identity and an admitted cross-request taint recorder")
	}
	if !recordsRisk && cfg != nil && cfg.Enabled {
		if strings.HasPrefix(binding, "listener_") {
			_, _ = fmt.Fprintln(w, "pipelock: no cross-request taint recorder is active; restart the listener with session_profiling.enabled; also check listener state capacity and recorder admission")
		} else {
			_, _ = fmt.Fprintln(w, "pipelock: no session taint recorder is active; enable session_profiling.enabled and restart; verify recorder admission")
		}
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

// mcpTaintBlockMessage follows adaptive diagnostics: detail to the operator,
// the original stable reason to the JSON-RPC client.
func mcpTaintBlockMessage(decision taintDecision, logW io.Writer) string {
	if logW != nil {
		_, _ = fmt.Fprintf(logW, "pipelock: taint refusal (%s); recovery: %s\n", decision.Result.Reason, config.MCPTaintRecoveryGuidance)
	}
	return "pipelock: " + decision.Result.Reason
}

// reportTaint reuses the listener's bounded aggregation contract. Metrics still
// count each context even when this listener-wide log interval is suppressed.
func (s *mcpListenerClientStates) reportTaint(w io.Writer, opts MCPProxyOpts, rec session.Recorder, binding string) bool {
	count, emit := s.taintReporter.observe()
	if !emit {
		w = nil
	} else if count > 1 && w != nil {
		_, _ = fmt.Fprintf(w, "pipelock: MCP taint listener contexts since last report=%d (see pipelock_mcp_taint_contexts_total)\n", count)
	}
	reportMCPTaint(w, opts, rec, binding)
	return emit
}
