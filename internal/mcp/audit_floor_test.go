// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A policy verdict raised because the arguments could not be inspected is
// not a rule decision, so audit mode keeps it.
func TestAuditPolicyUninspectableStaysBlocked(t *testing.T) {
	pc := policy.New(config.MCPToolPolicy{
		Enabled: true, Action: config.ActionBlock,
		Rules: []config.ToolPolicyRule{{
			Name: "wipe", ToolPattern: "^shell$", ArgPattern: `rm\s+-rf`, Action: config.ActionBlock,
		}},
	})
	matched := pc.CheckRequest([]byte(auditTool("shell", map[string]string{"command": "rm -rf /"})))
	if !matched.Matched || matched.CouldNotInspect() {
		t.Fatalf("rule match verdict = %+v", matched)
	}
	if got := policyAuditAction(true, matched); got != config.ActionWarn {
		t.Fatalf("matched rule action = %q, want warn", got)
	}
	deep := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell","arguments":` + deepJSONObject("x", 300) + `}}`
	uninspectable := pc.CheckRequest([]byte(deep))
	if !uninspectable.Matched || !uninspectable.CouldNotInspect() {
		t.Fatalf("deep arguments verdict = %+v", uninspectable)
	}
	if got := policyAuditAction(true, uninspectable); got != config.ActionBlock {
		t.Fatalf("uninspectable action = %q, want block", got)
	}
}

// Only the named scanners are observable; a label added later stays refused.
func TestAuditURLFindingUnknownScannerStaysBlocked(t *testing.T) {
	for _, label := range []string{scanner.ScannerSSRF, scanner.ScannerCoreSSRF, scanner.ScannerSSRFMetadata, scanner.ScannerRateLimit, "future_scanner"} {
		if urlFindingPolicyOnly(scanner.Result{Scanner: label}) {
			t.Errorf("scanner %q is observable", label)
		}
	}
	if !urlFindingPolicyOnly(scanner.Result{Scanner: scanner.ScannerBlocklist}) {
		t.Error("blocklist finding is not observable")
	}
}
