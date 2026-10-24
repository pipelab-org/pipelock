// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtimeconfig

import (
	"fmt"
	"io"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/diaglog"
)

// ResponseScanningMCPDisabledWarning is the single operator-facing notice for
// the temporary MCP-mode fail-safe that overrides response_scanning.enabled=false.
const ResponseScanningMCPDisabledWarning = "warning: response_scanning.enabled=false is ignored in MCP mode (this control is required); running with default response scanning. This will become a startup error in a future release - remove the disable to silence."

// ResolveAndReportConfig applies runtime-mode config resolution and immediately
// emits any operator-facing notices for fallbacks or auto-enabled MCP controls.
func ResolveAndReportConfig(cfg *config.Config, opts config.RuntimeResolveOpts, w io.Writer, modeLabel string) (*config.Config, config.ResolveRuntimeInfo) {
	if w != nil {
		for _, warning := range cfg.MCPCompatibilityWarnings() {
			_, _ = fmt.Fprintf(w, "pipelock: warning: %s\n", warning.Message)
		}
	}
	resolved, info := cfg.ResolveRuntime(opts)
	EmitResolveInfoLogs(w, info, modeLabel)
	EmitMCPTaintDiagnostics(diaglog.New(w), resolved, opts.Mode)
	return resolved, info
}

// EmitMCPTaintDiagnostics reports MCP prerequisites at startup and reload.
// Forward-only and one-shot scan commands have no MCP session to diagnose.
func EmitMCPTaintDiagnostics(w *diaglog.Writer, cfg *config.Config, mode config.RuntimeMode) {
	if w != nil {
		w.TryWrite(RenderMCPTaintDiagnostics(cfg, mode))
	}
}

// RenderMCPTaintDiagnostics prepares immutable operator text without I/O.
func RenderMCPTaintDiagnostics(cfg *config.Config, mode config.RuntimeMode) string {
	if cfg == nil || !mode.WrapsMCP() {
		return ""
	}
	var b strings.Builder
	for _, diagnostic := range cfg.MCPTaintDiagnostics() {
		_, _ = fmt.Fprintf(&b, "pipelock: diagnostic: %s: %s\n", diagnostic.Field, diagnostic.Message)
	}
	return b.String()
}

// EmitResolveInfoLogs writes the operator-facing notices that correspond to the
// auto-enable and fallback branches a config.ResolveRuntime call reported as
// having fired.
func EmitResolveInfoLogs(w io.Writer, info config.ResolveRuntimeInfo, modeLabel string) {
	if w == nil {
		return
	}
	if info.ResponseScanningFallback {
		_, _ = fmt.Fprintln(w, ResponseScanningMCPDisabledWarning)
	}
	if info.MCPInputScanningAutoEnabled {
		_, _ = fmt.Fprintf(w, "pipelock: auto-enabling MCP input scanning for %s mode\n", modeLabel)
	}
	if info.MCPToolScanningAutoEnabled {
		_, _ = fmt.Fprintf(w, "pipelock: auto-enabling MCP tool scanning for %s mode\n", modeLabel)
	}
	if info.MCPToolPolicyAutoEnabled {
		_, _ = fmt.Fprintf(w, "pipelock: auto-enabling MCP tool call policy for %s mode\n", modeLabel)
	}
}
