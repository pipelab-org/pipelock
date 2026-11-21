// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import "testing"

type v3MCPMatrixRow struct {
	path     string
	required bool
	scenario string
}

func runV3MCPMatrix(t *testing.T, run func(*testing.T, v3MCPMatrixRow)) {
	t.Helper()
	paths := []string{"stdio subprocess", "stdio-to-HTTP upstream", "HTTP listener", "SSE bridge GET", "WebSocket upstream"}
	modes := []struct {
		name     string
		required bool
	}{{"required", true}, {"optional", false}}
	scenarios := []string{
		"ok", "intent write fail", "intent sync fail", "client cancel before effect",
		"cancel after intent", "upstream error", "upstream closes mid-response",
		"tool-scan block", "media/redaction rewrite", "deferred approve", "deferred deny",
		"deferred timeout", "kill-switch during hold", "restart recovery of a pending hold",
	}
	for i, path := range paths {
		for _, mode := range modes {
			for _, scenario := range scenarios {
				t.Run(path+"/"+mode.name+"/"+scenario, func(t *testing.T) {
					if i >= 2 {
						t.Skip("pending-in-a-later-step")
					}
					run(t, v3MCPMatrixRow{path: path, required: mode.required, scenario: scenario})
				})
			}
		}
	}
}
