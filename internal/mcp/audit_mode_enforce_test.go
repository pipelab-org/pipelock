// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"io"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestAuditModeMCPEnforceIgnored records that enforce does not change MCP
// decisions. A tool-policy block and a core credential stay refused for both
// values. A core credential in a response is forwarded when the scanner
// action is warn, for both values. The MCP proxy does not read enforce.
func TestAuditModeMCPEnforceIgnored(t *testing.T) {
	tool := makeRequest(1, methodToolsCall, map[string]any{
		"name": "shell", "arguments": map[string]string{"command": "rm -rf /"},
	})
	credential := makeRequest(2, methodToolsCall, map[string]any{
		"name": "send", "arguments": map[string]string{"text": fakeAWSKey()},
	})
	response := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"` + fakeAWSKey() + `"}]}}`
	var enforceTrue, enforceFalse mcpAuditObservation
	for _, enforce := range []bool{true, false} {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		cfg.Enforce = &enforce
		cfg.ResponseScanning.Action = config.ActionWarn
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		policyCfg := policy.New(config.MCPToolPolicy{
			Enabled: true, Action: config.ActionBlock,
			Rules: []config.ToolPolicyRule{{
				Name: "wipe", ToolPattern: "^shell$", ArgPattern: `rm\s+-rf`, Action: config.ActionBlock,
			}},
		})
		toolDecision := scanHTTPInputDecision([]byte(tool), io.Discard, "session", "session", MCPProxyOpts{Scanner: sc, PolicyCfg: policyCfg})
		credentialDecision := scanHTTPInputDecision([]byte(credential), io.Discard, "session", "session", MCPProxyOpts{
			Scanner: sc, InputCfg: &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock},
		})
		var out bytes.Buffer
		_, err := ForwardScanned(
			transport.NewStdioReader(bytes.NewReader([]byte(response+"\n"))),
			transport.NewStdioWriter(&out),
			io.Discard,
			nil,
			MCPProxyOpts{Scanner: sc},
		)
		if err != nil {
			t.Fatal(err)
		}
		got := mcpAuditObservation{
			toolBlocked:       toolDecision.Blocked != nil,
			toolCode:          blockedCode(toolDecision.Blocked),
			credentialBlocked: credentialDecision.Blocked != nil,
			credentialCode:    blockedCode(credentialDecision.Blocked),
			response:          out.String(),
		}
		if enforce {
			enforceTrue = got
		} else {
			enforceFalse = got
		}
	}
	if enforceTrue != enforceFalse {
		t.Fatalf("enforce changed MCP outcome\n true=%+v\nfalse=%+v", enforceTrue, enforceFalse)
	}
	if !enforceFalse.toolBlocked || !enforceFalse.credentialBlocked {
		t.Fatalf("refusal released: %+v", enforceFalse)
	}
	if enforceFalse.response != response+"\n" {
		t.Fatalf("warn-action response changed: %q", enforceFalse.response)
	}
}

type mcpAuditObservation struct {
	toolBlocked, credentialBlocked bool
	toolCode, credentialCode       int
	response                       string
}

func blockedCode(blocked *BlockedRequest) int {
	if blocked == nil {
		return 0
	}
	return blocked.ErrorCode
}
