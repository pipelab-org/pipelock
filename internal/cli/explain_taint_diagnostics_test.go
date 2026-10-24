// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestExplainMCPTaintDiagnostics_NoSessionPrediction(t *testing.T) {
	cfg := config.Defaults()
	report, err := buildMCPExplainReport(cfg, "docs-cache", []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(report.Notes, "\n")
	for _, want := range []string{"taint.mcp_recorder:", "taint.mcp_listener:", "taint.mcp_origin:", "taint.mcp_recovery:", "no live recorder or caller history", config.MCPTaintRecoveryGuidance} {
		if !strings.Contains(notes, want) {
			t.Errorf("explain omitted %q: %s", want, notes)
		}
	}
}
