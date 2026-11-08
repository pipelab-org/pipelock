// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func watchCoverageExtraLogger(t *testing.T, opts *MCPProxyOpts) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	opts.AuditLogger = logger
	return &logs
}

func TestWatchCoverageExtraInputObservations(t *testing.T) {
	for _, kind := range []string{"policy", "chain", "critical", "redaction unavailable", "redaction rewrite", "hostile propagation"} {
		t.Run(kind, func(t *testing.T) {
			opts := testOpts(testInputScanner(t))
			opts.WatchOnly = true
			rec := &hostedWatchRecorder{}
			opts.Rec, opts.AdaptiveCfg = rec, adaptiveCfgEnabled()
			opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock}
			msg := []byte(toolsCallReadMsg)
			want := ""
			var tainted *taintRecorder
			switch kind {
			case "policy":
				opts.PolicyCfg = buildPolicyConfig(config.ActionBlock, []config.ToolPolicyRule{{Name: "read observation", ToolPattern: "^list_files$", Action: config.ActionBlock}})
				want = "tool_policy"
			case "chain":
				opts.ChainMatcher = buildBlockChainMatcher()
				first := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/safe.txt"}}}`)
				if got := watchInputDecision(first, io.Discard, "coverage-session", opts); got.Blocked != nil {
					t.Fatal(got.Blocked)
				}
				msg = []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bash_exec","arguments":{"command":"ls"}}}`)
				want = "test-block-chain"
			case "critical":
				rec.level = 3
				yes := true
				opts.AdaptiveCfg.Levels.Critical.BlockAll = &yes
				want = "session action upgrade"
			case "redaction unavailable":
				opts.RedactionCfgFn = func() MCPRedactionConfig { return MCPRedactionConfig{Required: true} }
				want = "redaction runtime unavailable"
			case "redaction rewrite":
				matcher := redact.NewDefaultMatcher()
				if err := matcher.AddDictionary(redact.Dictionary{Class: "customer", Entries: []string{"ProjectOrchid"}}); err != nil {
					t.Fatal(err)
				}
				opts.RedactMatcher, opts.RedactLimits = matcher, redact.DefaultLimits().ToLimits()
				msg = []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"ProjectOrchid"}}}`)
				changed, _, err := applyMCPToolCallRedaction(msg, opts)
				if err != nil || bytes.Equal(changed, msg) {
					t.Fatalf("redaction fixture did not rewrite: %v", err)
				}
				want = "request redaction"
			case "hostile propagation":
				tainted = &taintRecorder{}
				contaminateRecorder(tainted, true)
				cfg := config.Defaults()
				opts.Rec, opts.TaintCfg = tainted, &cfg.Taint
				want = "cross-agent escalation"
			}
			logs := watchCoverageExtraLogger(t, &opts)
			got := watchInputDecision(msg, io.Discard, "coverage-session", opts)
			if got.Blocked != nil || !bytes.Equal(got.ForwardMessage, msg) {
				t.Fatalf("observation altered request: blocked=%v body=%s", got.Blocked, got.ForwardMessage)
			}
			if !strings.Contains(logs.String(), want) {
				t.Fatalf("missing %q observation: %s", want, logs.String())
			}
			if kind == "policy" || kind == "chain" {
				if len(rec.observed) != 1 || rec.observed[0] != session.SignalBlock {
					t.Fatalf("missing shadow block signal: %v", rec.observed)
				}
			}
			if tainted != nil && len(crossAgentSources(tainted)) != 1 {
				t.Fatal("cross-agent evidence missing")
			}
		})
	}
}

func TestWatchCoverageExtraResponseObservations(t *testing.T) {
	for _, kind := range []string{"wrong version", "uninspectable inventory", "media rewrite"} {
		t.Run(kind, func(t *testing.T) {
			opts := testOpts(testInputScanner(t))
			opts.WatchOnly = true
			rec := &hostedWatchRecorder{}
			opts.Rec, opts.AdaptiveCfg = rec, adaptiveCfgEnabled()
			line, want := "", ""
			switch kind {
			case "wrong version":
				line = `{"jsonrpc":"1.0","id":1,"result":{}}`
				want = "not a JSON-RPC 2.0 response"
			case "uninspectable inventory":
				line = `{"jsonrpc":"2.0","id":1,"result":{"tools":"invalid"}}`
				opts.ToolCfg = &tools.ToolScanConfig{Action: config.ActionBlock}
				want = "tool_definition_uninspectable"
			case "media rewrite":
				cfg := config.Defaults()
				cfg.MediaPolicy.AllowedImageTypes = []string{"image/png", "image/jpeg", "image/webp"}
				opts.MediaPolicy = &cfg.MediaPolicy
				webp := append([]byte("RIFF\x24\x00\x00\x00WEBPVP8 \x18\x00\x00\x00"), make([]byte, 24)...)
				line = `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"image","data":"` + base64.StdEncoding.EncodeToString(webp) + `","mimeType":"image/png"}]}}`
				enforced := applyMCPResponseMediaPolicy([]byte(line), opts.MediaPolicy, transportMCPStdio)
				if !enforced.Changed || enforced.Blocked {
					t.Fatalf("media fixture did not rewrite: %+v", enforced)
				}
				want = "response media rewrite"
			}
			logs := watchCoverageExtraLogger(t, &opts)
			var out watchMessageBuffer
			found, err := forwardWatchResponse([]byte(line), &out, io.Discard, nil, opts)
			if err != nil || !found || out.String() != line {
				t.Fatalf("found=%v err=%v output=%q", found, err, out.String())
			}
			if !strings.Contains(logs.String(), want) {
				t.Fatalf("missing %q observation: %s", want, logs.String())
			}
			if len(rec.observed) != 1 || rec.observedCleans != 0 {
				t.Fatalf("shadow state: signals=%v clean=%d", rec.observed, rec.observedCleans)
			}
		})
	}
}

func TestWatchCoverageExtraA2AURLFloor(t *testing.T) {
	opts := testOpts(testA2AScanner(t))
	opts.WatchOnly = true
	opts.A2ACfg = enabledA2ACfg()
	opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock}
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"messageId":"test","role":"user","parts":[{"kind":"file","file":{"uri":"https://api.vendor.example/?key=` + fakeAWSKey() + `","mimeType":"text/plain"}}]}}}`)
	before := ScanA2ARequestBody(t.Context(), msg, opts.Scanner, opts.A2ACfg)
	if len(before.URLFindings) == 0 {
		t.Fatal("fixture did not produce URL finding")
	}
	logs := watchCoverageExtraLogger(t, &opts)
	got := watchInputDecision(msg, io.Discard, "coverage-session", opts)
	if got.Blocked == nil || !strings.Contains(logs.String(), "audit-mode security floor") {
		t.Fatalf("metadata URL floor missing: block=%v logs=%s findings=%+v", got.Blocked, logs.String(), before)
	}
}
