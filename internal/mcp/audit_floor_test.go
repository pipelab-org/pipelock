// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
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
	if !matched.Matched || !matched.RuleDecision {
		t.Fatalf("rule match verdict = %+v", matched)
	}
	if got := policyAuditAction(true, matched); got != config.ActionWarn {
		t.Fatalf("matched rule action = %q, want warn", got)
	}
	deep := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell","arguments":` + deepJSONObject("x", 300) + `}}`
	uninspectable := pc.CheckRequest([]byte(deep))
	if !uninspectable.Matched || uninspectable.RuleDecision {
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

// A URL finding lifts only when the submitted URL can be read back for the
// core credential check.
func TestAuditURLFindingUnreadableURLStaysBlocked(t *testing.T) {
	sc := auditTestScanner(t, nil)
	verdict := InputVerdict{URLFindings: []scanner.Result{{Scanner: scanner.ScannerBlocklist}}}
	for name, msg := range map[string]string{
		"missing uri":  makeRequest(1, methodResourcesRead, map[string]string{}),
		"null params":  `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":null}`,
		"other method": auditTool("send", map[string]string{"url": "https://api.vendor.example/"}),
	} {
		t.Run(name, func(t *testing.T) {
			if got := auditContentAction(true, sc, verdict, config.ActionWarn, []byte(msg)); got != config.ActionBlock {
				t.Fatalf("action = %q, want block", got)
			}
		})
	}
	readable := auditResource("https://api.vendor.example/v1")
	if got := auditContentAction(true, sc, verdict, config.ActionWarn, []byte(readable)); got != config.ActionWarn {
		t.Fatalf("readable URL action = %q, want warn", got)
	}
}

// A rule that happens to share a reserved name is still a rule decision; a
// verdict built without the mark is never observed.
func TestAuditPolicyOnlyMarkedRuleDecisionsLift(t *testing.T) {
	pc := policy.New(config.MCPToolPolicy{
		Enabled: true, Action: config.ActionBlock,
		Rules: []config.ToolPolicyRule{{
			Name: "duplicate_json_object_key", ToolPattern: "^shell$", ArgPattern: `rm\s+-rf`, Action: config.ActionBlock,
		}},
	})
	verdict := pc.CheckRequest([]byte(auditTool("shell", map[string]string{"command": "rm -rf /"})))
	if got := policyAuditAction(true, verdict); got != config.ActionWarn {
		t.Fatalf("rule decision action = %q, want warn", got)
	}
	unmarked := policy.Verdict{Matched: true, Action: config.ActionBlock, Rules: []string{"wipe"}}
	if got := policyAuditAction(true, unmarked); got != config.ActionBlock {
		t.Fatalf("unmarked verdict action = %q, want block", got)
	}
	if got := chainAuditAction(true, chains.Verdict{Matched: true, Action: config.ActionBlock}); got != config.ActionBlock {
		t.Fatalf("unmarked chain verdict action = %q, want block", got)
	}
	unmarkedBaseline := observeBaselineAudit(MCPProxyOpts{AuditMode: true}, session.BaselineDecision{Blocked: true, Action: config.ActionBlock})
	if !unmarkedBaseline.Blocked || unmarkedBaseline.Action != config.ActionBlock {
		t.Fatalf("unmarked baseline decision = %+v, want block", unmarkedBaseline)
	}
}

func TestAuditA2AAskAndFragmentCoreStayRefused(t *testing.T) {
	result := A2AScanResult{InjectFindings: []scanner.ResponseMatch{{PatternName: "probe"}}}
	if got := a2aAuditAction(true, result, config.ActionAsk); got != config.ActionAsk {
		t.Fatalf("A2A ask action = %q, want ask", got)
	}
	if got := a2aAuditAction(true, result, config.ActionBlock); got != config.ActionWarn {
		t.Fatalf("A2A content block action = %q, want warn", got)
	}
	mixed := []scanner.DLPMatch{{PatternName: "Vendor Token"}, {PatternName: "AWS Access ID"}}
	if !scanner.HasCoreFragmentMatch(mixed) {
		t.Fatal("a core match after a non-core match was not found")
	}
	if scanner.HasCoreFragmentMatch(mixed[:1]) {
		t.Fatal("a non-core match counted as core")
	}
}
