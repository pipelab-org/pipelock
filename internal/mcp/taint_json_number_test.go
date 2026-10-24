// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestEvaluateMCPTaintJSONNumberApproval(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, number string }{
		{"ordinary", "1.5"},
		{"positive_exponent", "1e999"},
		{"negative_exponent", "-1e999"},
		{"small_exponent", "1e-999"},
		{"large_integer", strings.Repeat("9", 400)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Taint.Policy = config.ModeBalanced
			cfg.Taint.ProtectedPaths = []string{"*/auth/*", "*/security/*", "*/.env*"}
			cfg.Taint.ElevatedPaths = []string{"*/config/*", "*/middleware*"}
			rec := &taintRecorder{}
			rec.ObserveRisk(session.RiskObservation{Source: session.TaintSourceRef{
				URL: "https://api.vendor.example/document", Level: session.TaintExternalUntrusted,
			}})
			args := fmt.Sprintf(`{"path":"/repo/auth/middleware.go","content":"x","extra":[{"n":%s}]}`, tt.number)
			got := evaluateMCPTaint(MCPProxyOpts{TaintCfg: &cfg.Taint, Rec: rec}, "write_file", args)
			if got.ActionClass != session.ActionClassWrite || got.Sensitivity != session.SensitivityProtected || got.ActionRef != "mcp:write_file:/repo/auth/middleware.go" {
				t.Fatalf("classification = %s/%s ref=%q", got.ActionClass, got.Sensitivity, got.ActionRef)
			}
			if got.Result.Decision != session.PolicyAsk || got.Result.Reason != "protected_write_after_untrusted_external_exposure" {
				t.Fatalf("decision = %+v, want protected write approval", got.Result)
			}
		})
	}
}

// Absent, null and empty-object arguments name no write target. Through the
// real frame parser and taint gate they must reach one decision under the
// default fail-safe setting; only an explicit target may raise sensitivity.
func TestEvaluateMCPTaintArgumentlessWriteParity(t *testing.T) {
	t.Parallel()

	frames := map[string]string{
		"absent":       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"save_memory"}}`,
		"null":         `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"save_memory","arguments":null}}`,
		"empty_object": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"save_memory","arguments":{}}}`,
	}
	for name, raw := range frames {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			rec := &taintRecorder{}
			rec.ObserveRisk(session.RiskObservation{Source: session.TaintSourceRef{
				URL: "https://api.vendor.example/document", Level: session.TaintExternalUntrusted,
			}})
			frame := ParseMCPFrame([]byte(raw))
			if frame.ParseErr != nil || !frame.IsToolsCall() {
				t.Fatalf("frame parse = %v, tools/call = %v; want a valid tools/call", frame.ParseErr, frame.IsToolsCall())
			}
			args := mcpFrameCallableArgs(frame)
			if wantArgs := map[string]string{"absent": "", "null": "", "empty_object": "{}"}[name]; args != wantArgs {
				t.Fatalf("callable args = %q, want %q", args, wantArgs)
			}
			got := evaluateMCPTaint(MCPProxyOpts{TaintCfg: &cfg.Taint, Rec: rec}, "save_memory", args)
			if got.ActionClass != session.ActionClassWrite || got.Sensitivity != session.SensitivityNormal {
				t.Fatalf("classification = %s/%s, want write/normal", got.ActionClass, got.Sensitivity)
			}
			if got.Result.Decision != session.PolicyAllow {
				t.Fatalf("decision = %+v, want allow for a write that names no target", got.Result)
			}
		})
	}
}
