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
