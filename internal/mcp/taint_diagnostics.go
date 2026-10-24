// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/diaglog"
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

// reportMCPTaintStartup counts and renders once, then gives healthy sinks the
// existing bounded startup flush. The entry point supplies its shared writer.
func reportMCPTaintStartup(w *diaglog.Writer, opts MCPProxyOpts, rec session.Recorder, binding string) {
	var b strings.Builder
	reportMCPTaint(&b, opts, rec, binding)
	if done := emitMCPTaintReport(w, opts, b.String()); done != nil {
		select {
		case <-done:
		case <-time.After(logFlushGrace):
		}
	}
}

// mcpTaintBlockMessage follows adaptive diagnostics: detail to the operator,
// the original stable reason to the JSON-RPC client.
func mcpTaintBlockMessage(decision taintDecision, logW io.Writer, opts MCPProxyOpts) string {
	if logW != nil {
		emitMCPTaintReport(diaglog.New(logW), opts, fmt.Sprintf("pipelock: taint refusal (%s); recovery: %s\n", decision.Result.Reason, config.MCPTaintRecoveryGuidance))
	}
	return "pipelock: " + decision.Result.Reason
}

// reportTaint reuses the listener's bounded aggregation contract. Metrics still
// count each context even when this listener-wide log interval is suppressed.
func (s *mcpListenerClientStates) reportTaint(w io.Writer, opts MCPProxyOpts, rec session.Recorder, binding string) bool {
	// Count every context independently of whether an optional report is admitted.
	reportMCPTaint(nil, opts, rec, binding)
	return s.taintReporter.observeIf(func(count uint64) bool {
		if w == nil {
			return false
		}
		var b strings.Builder
		if count > 1 {
			_, _ = fmt.Fprintf(&b, "pipelock: MCP taint listener contexts since last report=%d (see pipelock_mcp_taint_contexts_total)\n", count)
		}
		renderOpts := opts
		renderOpts.Metrics = nil // Rendering must not count the same context twice.
		reportMCPTaint(&b, renderOpts, rec, binding)
		return emitMCPTaintReport(diaglog.New(w), opts, b.String()) != nil
	})
}

// Admission never waits for I/O. Nil sinks disable output; busy sinks count a
// skipped report, without treating context metrics as delivery acknowledgements.
func emitMCPTaintReport(w *diaglog.Writer, opts MCPProxyOpts, message string) <-chan struct{} {
	if w == nil || message == "" {
		return nil
	}
	done := w.TryWrite(message)
	if done == nil {
		opts.Metrics.RecordMCPTaintReportSkipped()
	}
	return done
}
