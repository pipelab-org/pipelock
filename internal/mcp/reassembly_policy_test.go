// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func policyPartialBody() string {
	return strings.Repeat("30", 1<<22) + strings.Repeat("!0", 80)
}

// Each inbound surface is its own top-level test so the CI shard planner can
// place the 8 MiB allowance witnesses on different shards.
func TestReassemblyPolicyInboundMCPResponse(t *testing.T) {
	runReassemblyPolicyInbound(t, "mcp-response")
}

func TestReassemblyPolicyInboundA2AResponse(t *testing.T) {
	runReassemblyPolicyInbound(t, "a2a-response")
}

func TestReassemblyPolicyInboundGenericSSE(t *testing.T) {
	runReassemblyPolicyInbound(t, "generic-sse")
}

func TestReassemblyPolicyInboundA2ASSE(t *testing.T) {
	runReassemblyPolicyInbound(t, "a2a-sse")
}

func runReassemblyPolicyInbound(t *testing.T, surface string) {
	t.Helper()
	if testing.Short() {
		t.Skip("large allowance witness")
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = nil
	for _, pattern := range config.DefaultDLPPatterns() {
		if pattern.Name == "AWS Access ID" {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, pattern)
		}
	}
	if len(cfg.DLP.Patterns) != 1 {
		t.Fatal("AWS control absent")
	}
	cfg.ResponseScanning.Action = config.ActionBlock
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	body := policyPartialBody()
	t.Run(surface, func(t *testing.T) {
		warnings := 0
		sc.SetDLPWarnHook(func(_ context.Context, name, _ string) {
			if name == scanner.PartialEncodedContentPattern {
				warnings++
			}
		})
		defer sc.SetDLPWarnHook(nil)
		switch surface {
		case "mcp-response":
			line, e := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []map[string]string{{"type": "text", "text": body}}}})
			if e != nil {
				t.Fatal(e)
			}
			emitter, rec, dir, pub := newReceiptTestHarness(t)
			var out, log bytes.Buffer
			found, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(string(line)+"\n")), transport.NewStdioWriter(&out), &log, nil, MCPProxyOpts{Scanner: sc, ReceiptEmitter: emitter, Transport: transportMCPStdio, ResponseActionOverride: config.ActionBlock})
			if err != nil || !found || out.String() != string(line)+"\n" {
				t.Fatalf("partial response refused: found=%v err=%v log=%s", found, err, log.String())
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			receipts := readActionReceipts(t, dir)
			if len(receipts) == 0 {
				t.Fatal("partial response lost receipt")
			}
			for _, r := range receipts {
				if r.ActionRecord.Verdict != config.ActionWarn || !strings.Contains(r.ActionRecord.Pattern, scanner.PartialEncodedContentPattern) {
					t.Fatal("wrong partial receipt", r.ActionRecord)
				}
				if err := receipt.VerifyWithKey(r, pub); err != nil {
					t.Fatal(err)
				}
			}
			if !strings.Contains(log.String(), "action=warn") {
				t.Fatal("operator warning absent")
			}
		case "a2a-response":
			data, e := json.Marshal(map[string]any{"result": map[string]any{"kind": "message", "parts": []map[string]string{{"kind": "text", "text": body}}}})
			if e != nil {
				t.Fatal(e)
			}
			cfg := enabledA2ACfg()
			cfg.Action = config.ActionBlock
			r := ScanA2AResponseBody(t.Context(), data, sc, cfg)
			if r.ScanError != "" || r.Action != config.ActionWarn || !scanner.OnlyInformational(r.DLPFindings) {
				t.Fatalf("A2A partial response enforces or loses evidence: %s %s %v", r.ScanError, r.Action, r.DLPFindings)
			}
		default:
			payload := body
			if surface == "a2a-sse" {
				data, e := json.Marshal(map[string]any{"result": map[string]any{"kind": "message", "parts": []map[string]string{{"kind": "text", "text": body}}}})
				if e != nil {
					t.Fatal(e)
				}
				payload = string(data)
			}
			stream := "data: " + payload + "\n\n"
			var out bytes.Buffer
			opts := GenericSSEScanOptions{}
			var err error
			if surface == "generic-sse" {
				err = ScanGenericSSEStreamWithOptions(t.Context(), strings.NewReader(stream), &out, nil, sc, &config.GenericSSEScanning{Enabled: true, Action: config.ActionBlock, MaxEventBytes: transport.MaxLineSize}, opts)
			} else {
				cfg := enabledA2ACfg()
				cfg.Action = config.ActionBlock
				err = ScanA2AStreamWithOptions(t.Context(), strings.NewReader(stream), &out, nil, sc, A2AStreamOptions{Config: cfg, Warning: opts})
			}
			if err != nil || out.String() != stream {
				t.Fatalf("partial stream refused: %v", err)
			}
		}
		if warnings == 0 {
			t.Fatal("partial evidence did not reach warn hook")
		}
	})
}
