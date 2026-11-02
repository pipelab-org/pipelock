// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// deepEntityChain is benign text behind more nested HTML entity layers than
// the decoder's pass limit.
func deepEntityChain() string {
	return "note: &" + strings.Repeat("amp;", 24) + "#104;ello"
}

func TestDecodeInspectionLimitAgentCardsDeliver(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionWarn
	cfg.ScanAgentCards = true
	ctx := t.Context()
	for _, malformed := range []bool{false, true} {
		name := any("report helper")
		if malformed {
			// Valid JSON with a wrong typed field exercises the card fallback.
			name = 7
		}
		body, err := json.Marshal(map[string]any{"name": name, "description": deepEntityChain(), "skills": []any{}})
		if err != nil {
			t.Fatal(err)
		}
		for surface, result := range map[string]AgentCardScanResult{
			"direct": ScanAgentCard(ctx, body, sc, nil, cardCacheKey{}, cfg),
			"HTTP":   ScanAgentCardWithOptions(ctx, body, sc, A2AResponseOpts{Cfg: cfg}),
		} {
			if result.Action == config.ActionBlock || scanner.HasInspectionLimit(result.Findings.DLPFindings) {
				t.Errorf("%s malformed=%v: inbound card refused: %+v", surface, malformed, result)
			}
		}
		line := []byte(`{"jsonrpc":"2.0","id":1,"result":` + string(body) + `}`)
		verdict := ScanResponseA2A(line, sc, &A2AResponseOpts{Cfg: cfg, Method: methodGetExtendedAgentCard})
		if verdict.Action == config.ActionBlock || scanner.HasInspectionLimit(verdict.DLPMatches) {
			t.Errorf("MCP malformed=%v: inbound card refused: action=%s error=%s", malformed, verdict.Action, verdict.Error)
		}
	}
	// Inbound direction exempts the decode-depth refusal, not known secrets.
	secret := "AK" + "IA" + "Q9W8E7R6T5Y4U3I2"
	card := []byte(`{"name":"report helper","description":"` + secret + `"}`)
	if result := ScanAgentCard(ctx, card, sc, nil, cardCacheKey{}, cfg); result.Action != config.ActionBlock {
		t.Fatalf("card containing a core credential was not refused: %+v", result)
	}
	// Marking a derived response context must not modify the caller's context.
	body := []byte(`{"message":{"parts":[{"text":"` + deepEntityChain() + `"}]}}`)
	if result := ScanA2ARequestBody(ctx, body, sc, cfg); result.Action != config.ActionBlock || !scanner.HasInspectionLimit(result.DLPFindings) {
		t.Fatalf("outbound scan after card response lost refusal: %+v", result)
	}
}

func TestDecodeInspectionLimitMCPDirection(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	args, _ := json.Marshal(map[string]string{"text": deepEntityChain()})
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"report","arguments":` + string(args) + `}}`)
	if v := ScanRequest(t.Context(), line, sc, config.ActionWarn, config.ActionForward); v.Clean || v.Action != config.ActionBlock {
		t.Fatalf("tool-call input past the entity pass limit: clean=%v action=%s", v.Clean, v.Action)
	}
	control, _ := json.Marshal(map[string]string{"text": "Tom &amp;amp; Jerry"})
	controlLine := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"report","arguments":` + string(control) + `}}`)
	if v := ScanRequest(t.Context(), controlLine, sc, config.ActionWarn, config.ActionForward); v.Action == config.ActionBlock {
		t.Fatal("tool-call control refused")
	}

	cfg := enabledA2ACfg()
	cfg.Action = config.ActionWarn
	body := []byte(`{"message":{"parts":[{"text":` + strings.TrimPrefix(strings.TrimSuffix(string(args), "}"), `{"text":`) + `}]}}`)
	if v := ScanA2ARequestBody(t.Context(), body, sc, cfg); v.Clean || v.Action != config.ActionBlock {
		t.Fatalf("A2A request past the entity pass limit: clean=%v action=%s", v.Clean, v.Action)
	}

	// Tool results flow to the agent; a decode bound does not refuse them.
	result, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []map[string]string{{"type": "text", "text": deepEntityChain()}}}})
	if v := ScanResponse(result, sc); v.Action == config.ActionBlock {
		t.Fatalf("tool result refused at a decode bound: %+v", v)
	}
}

// Generic SSE events and A2A responses run the outbound text-DLP entry
// points for their pattern and secret checks. They are still responses, so a
// decode bound must not refuse them, while an A2A request must.
func TestDecodeInspectionLimitResponseStreamsDeliver(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionWarn)
	var output bytes.Buffer
	input := "data: " + deepEntityChain() + "\n\n"
	sseCfg := &config.GenericSSEScanning{Enabled: true, Action: config.ActionWarn}
	if err := ScanGenericSSEStream(t.Context(), strings.NewReader(input), &output, nil, sc, sseCfg); err != nil || output.Len() == 0 {
		t.Fatalf("SSE event refused at a decode bound: delivered=%d err=%v", output.Len(), err)
	}

	cfg := enabledA2ACfg()
	cfg.Action = config.ActionWarn
	body := []byte(`{"message":{"parts":[{"text":"` + deepEntityChain() + `"}]}}`)
	if res := ScanA2AResponseBody(t.Context(), body, sc, cfg); res.Action == config.ActionBlock {
		t.Fatalf("A2A response refused at a decode bound: %s", res.Reason)
	}
	if res := ScanA2ARequestBody(t.Context(), body, sc, cfg); res.Clean || res.Action != config.ActionBlock {
		t.Fatalf("A2A request past the entity pass limit: clean=%v action=%s", res.Clean, res.Action)
	}
}
